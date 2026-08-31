"""Transactional creation of single tickets and Project Incident bundles."""

from dataclasses import dataclass, field

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.wazuh_ingest.models import WazuhAlert

from .forms import ProjectIncidentForm, ProjectIncidentTargetForm, TicketForm
from .models import (
    ProjectIncident,
    Ticket,
    TicketAlertLink,
    TicketLog,
    TriageRecord,
    bundle_suffix_for_index,
)
from .notifications import notify_manager_triage_pending, notify_system_owner_created
from .policies import can_create_ticket_from_triage, can_create_ticket_from_wazuh
from .staging import adopt_staged

MAX_ALERT_BUNDLE_SIZE = 25
BUNDLE_SHARED_FIELDS = tuple(ProjectIncidentForm.Meta.fields)


@dataclass(frozen=True)
class CaseCreationResult:
    """The non-HTTP result of creating a case and any follow-up warnings."""

    ticket: Ticket | None = None
    project: ProjectIncident | None = None
    tickets: tuple[Ticket, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)


def load_alert_bundle(alert_ids, user, *, lock=False):
    """Load and validate an opt-in Alert Bundle for this analyst.

    Selection is a convenience supplied by the browser, never authority. The
    claimed, actionable and unconsumed checks are repeated here and, for the
    save path, under row locks in the same transaction as ticket creation.
    """
    if len(alert_ids) < 2:
        raise ValidationError('กรุณาเลือก Alert ที่เกี่ยวข้องอย่างน้อย 2 รายการ')
    if len(alert_ids) > MAX_ALERT_BUNDLE_SIZE:
        raise ValidationError(
            f'เลือก Alert ได้ไม่เกิน {MAX_ALERT_BUNDLE_SIZE} รายการต่อ Ticket'
        )

    query = WazuhAlert.objects.filter(pk__in=alert_ids).order_by('pk')
    if lock:
        query = query.select_for_update()
    alerts = list(query)
    if len(alerts) != len(alert_ids):
        raise ValidationError('มี Alert ที่เลือกไว้ไม่พบในระบบ')

    unavailable = [
        str(alert.pk)
        for alert in alerts
        if not can_create_ticket_from_wazuh(alert, user)
    ]
    if unavailable:
        raise ValidationError(
            'Alert ต่อไปนี้ไม่อยู่ในความรับผิดชอบของคุณหรือถูกดำเนินการแล้ว: '
            + ', '.join(unavailable)
        )
    return alerts


def create_ticket_from_form(*, form, actor, triage=None, alert_bundle_ids=(), evidence_token=''):
    """Persist a validated TicketForm with all source records and evidence."""
    with transaction.atomic():
        locked_triage = _lock_triage(triage, actor) if triage else None
        ticket = form.save(commit=False)
        ticket.created_by = actor
        ticket.assigned_to = actor

        locked_alert, locked_alerts = _lock_ticket_alert_sources(
            ticket=ticket,
            actor=actor,
            alert_bundle_ids=alert_bundle_ids,
        )
        ticket.save()

        source_alerts = locked_alerts or ([locked_alert] if locked_alert else [])
        _link_alerts(ticket, source_alerts, actor)
        _apply_initial_ticket_route(ticket, actor, form.cleaned_data.get('t1_route'))

        if locked_triage:
            consume_source_triage(
                locked_triage,
                classification=ticket.classification,
                user=actor,
                ticket=ticket,
            )
        for source_alert in source_alerts:
            consume_source_alert(
                source_alert,
                actor,
                classification=ticket.classification,
                link_ticket=ticket,
                stamp_conversion=source_alert.pk == ticket.wazuh_alert_id,
            )

        _log_alert_bundle(ticket, source_alerts, actor)
        adopt_staged(evidence_token, actor, ticket=ticket)

    return CaseCreationResult(ticket=ticket, warnings=_ticket_creation_warnings(ticket))


def create_project_incident_from_forms(
    *,
    shared_form,
    target_formset,
    actor,
    source_alert=None,
    source_triage=None,
    evidence_token='',
):
    """Persist a validated Project Incident form and its member tickets."""
    shared = shared_form.cleaned_data
    with transaction.atomic():
        project = ProjectIncident.objects.create(
            title=shared['title'],
            summary=shared.get('issue_description', ''),
            created_by=actor,
            actions_taken_summary=shared.get('actions_taken_summary', ''),
            next_steps_summary=shared.get('next_steps_summary', ''),
        )
        tickets = _create_project_members(project, shared, target_formset, actor)
        if len(tickets) < 2:
            raise ValidationError('ต้องระบุระบบเป้าหมายอย่างน้อย 2 ระบบสำหรับ Project Incident')

        source_classification = (
            Ticket.CLASSIFICATION_INCIDENT
            if any(ticket.is_incident for ticket in tickets)
            else Ticket.CLASSIFICATION_EVENT
        )

        if source_alert is not None:
            locked_alert = WazuhAlert.objects.select_for_update().get(pk=source_alert.pk)
            if not can_create_ticket_from_wazuh(locked_alert, actor):
                raise ValidationError(
                    'Wazuh Alert นี้ไม่พร้อมสำหรับการสร้าง Project Incident '
                    '(อาจถูกดำเนินการไปแล้ว)'
                )
            consume_source_alert(
                locked_alert,
                actor,
                classification=source_classification,
                link_ticket=tickets[0],
                project_incident=project,
            )

        if source_triage is not None:
            locked_triage = _lock_triage(source_triage, actor, project=True)
            consume_source_triage(
                locked_triage,
                classification=source_classification,
                user=actor,
                project_incident=project,
            )

        adopt_staged(evidence_token, actor, project=project)

    # Incident owners/admins are notified only after the SOC Manager releases
    # the corresponding member from Project Review.
    warnings = []
    first_incident = next(
        (ticket for ticket in tickets
         if ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE),
        None,
    )
    if first_incident is not None:
        notify_manager_triage_pending(first_incident)
    return CaseCreationResult(
        project=project,
        tickets=tuple(tickets),
        warnings=tuple(warnings),
    )


def consume_source_alert(
    alert,
    user,
    *,
    classification,
    link_ticket,
    project_incident=None,
    stamp_conversion=True,
):
    """Mark a claimed Wazuh alert handled once it has become a ticket (or a
    case bundle) and stamp the analyst response time on ``link_ticket``.

    Shared by the single-ticket (create_ticket) and fan-out
    (create_project_incident) flows. A mixed Project Incident records its
    source as Incident when any member is an Incident, and as Event only when
    every member is an Event. ``alert`` must already be locked
    (select_for_update) and re-validated by the caller.
    """
    now = timezone.now()
    alert.triage_status = (
        WazuhAlert.TRIAGE_FALSE_POSITIVE
        if classification == Ticket.CLASSIFICATION_EVENT
        else WazuhAlert.TRIAGE_TRUE_POSITIVE
    )
    alert.triaged_by = user
    alert.triaged_at = now
    alert.escalated_to_tier = None
    alert.claimed_by = None
    alert.claimed_at = None
    update_fields = [
        'triage_status',
        'triaged_by',
        'triaged_at',
        'escalated_to_tier',
        'claimed_by',
        'claimed_at',
    ]
    if project_incident is not None:
        alert.project_incident = project_incident
        update_fields.insert(0, 'project_incident')
    alert.save(update_fields=update_fields)

    # Stamp analyst response time once (alert actionable → ticket raised).
    # now() is within sub-second of the ticket's auto_now_add created_at; guard
    # against clock skew that would otherwise yield a negative duration.
    delta = now - alert.ingested_at
    if stamp_conversion and delta.total_seconds() >= 0:
        link_ticket.alert_conversion_duration = delta
        link_ticket.save(update_fields=['alert_conversion_duration'])


def consume_source_triage(triage, *, classification, user, ticket=None, project_incident=None):
    """Mark a claimed manual-triage record handled once it has become a ticket
    (or a case bundle): record the Event/Incident decision, link it to whatever
    it spawned, stamp who handled it, and release the claim so it leaves the
    manual queue.

    Shared by both create flows. ``triage`` must already be locked
    (select_for_update) and re-validated by the caller.
    """
    triage.decision = (
        TriageRecord.DECISION_FP
        if classification == Ticket.CLASSIFICATION_EVENT
        else TriageRecord.DECISION_TP
    )
    # Stamped before the claim is cleared — this is the only durable record of
    # who disposed of the report.
    triage.resolved_by = user
    triage.resolved_at = timezone.now()
    triage.claimed_by = None
    triage.claimed_at = None
    update_fields = ['decision', 'resolved_by', 'resolved_at', 'claimed_by', 'claimed_at']
    if ticket is not None:
        triage.ticket = ticket
        update_fields.insert(0, 'ticket')
    if project_incident is not None:
        triage.project_incident = project_incident
        update_fields.insert(0, 'project_incident')
    triage.save(update_fields=update_fields)


def _lock_triage(triage, actor, *, project=False):
    locked_triage = TriageRecord.objects.select_for_update().get(pk=triage.pk)
    if not can_create_ticket_from_triage(locked_triage, actor):
        if project:
            raise ValidationError(
                'รายการ Manual Triage นี้ไม่พร้อมสำหรับการสร้าง Project Incident '
                '(อาจถูกดำเนินการไปแล้ว)'
            )
        raise ValidationError('This triage record is no longer available for ticket creation.')
    return locked_triage


def _lock_ticket_alert_sources(*, ticket, actor, alert_bundle_ids):
    if alert_bundle_ids:
        locked_alerts = load_alert_bundle(alert_bundle_ids, actor, lock=True)
        if ticket.wazuh_alert_id not in {alert.pk for alert in locked_alerts}:
            raise ValidationError('กรุณาเลือก Primary Alert จาก Alert ที่รวมไว้เท่านั้น')
        return None, locked_alerts
    if ticket.wazuh_alert_id:
        locked_alert = WazuhAlert.objects.select_for_update().get(pk=ticket.wazuh_alert_id)
        if not can_create_ticket_from_wazuh(locked_alert, actor):
            raise ValidationError('This Wazuh alert is not assigned to you or already has a ticket.')
        return locked_alert, []
    return None, []


def _link_alerts(ticket, source_alerts, actor):
    for source_alert in source_alerts:
        link = TicketAlertLink(
            ticket=ticket,
            alert=source_alert,
            role=(
                TicketAlertLink.ROLE_PRIMARY
                if source_alert.pk == ticket.wazuh_alert_id
                else TicketAlertLink.ROLE_SUPPORTING
            ),
            linked_by=actor,
        )
        link.full_clean()
        link.save()


def _apply_initial_ticket_route(ticket, actor, route):
    if ticket.classification == Ticket.CLASSIFICATION_EVENT:
        ticket.transition_to(
            Ticket.STATUS_ESCALATED_T2,
            actor,
            'จัดประเภทเป็น Event — ส่งให้ Tier 2 ยืนยันก่อนปิด',
        )
    elif route == TicketForm.ROUTE_ESCALATE_T2:
        ticket.transition_to(
            Ticket.STATUS_ESCALATED_T2,
            actor,
            'จัดประเภทเป็น Incident — ส่งต่อให้ Tier 2',
        )
    elif route == TicketForm.ROUTE_ASSIGN_ADMIN:
        ticket.t1_route = Ticket.T1_ROUTE_ADMIN
        ticket.transition_to(
            Ticket.STATUS_PENDING_MGR_TRIAGE,
            actor,
            'จัดประเภทเป็น Incident — เลือกมอบหมายผู้ดูแลระบบ (รอผู้จัดการ SOC ตรวจ)',
        )
    elif route == TicketForm.ROUTE_DIRECT_OWNER:
        ticket.t1_route = Ticket.T1_ROUTE_OWNER
        ticket.transition_to(
            Ticket.STATUS_PENDING_MGR_TRIAGE,
            actor,
            'จัดประเภทเป็น Incident — เลือกให้เจ้าของระบบแก้ไขเอง (รอผู้จัดการ SOC ตรวจ)',
        )


def _log_alert_bundle(ticket, source_alerts, actor):
    if len(source_alerts) <= 1:
        return
    supporting_ids = [
        str(alert.pk)
        for alert in source_alerts
        if alert.pk != ticket.wazuh_alert_id
    ]
    TicketLog.objects.create(
        ticket=ticket,
        note=(
            f'สร้าง Alert Bundle: Primary Alert #{ticket.wazuh_alert_id}; '
            f'Supporting Alerts #{", #".join(supporting_ids)}'
        ),
        status_at_time=ticket.status,
        author=actor,
    )


def _create_project_members(project, shared, target_formset, actor):
    tickets = []
    for target_form in target_formset:
        cleaned_data = getattr(target_form, 'cleaned_data', None)
        if not cleaned_data or cleaned_data.get('DELETE'):
            continue
        ticket = target_form.save(commit=False)
        for field_name in BUNDLE_SHARED_FIELDS:
            setattr(ticket, field_name, shared[field_name])
        ticket.incident_name = shared['title']
        route = cleaned_data['t1_route']
        is_event = route == ProjectIncidentTargetForm.ROUTE_EVENT
        ticket.classification = (
            Ticket.CLASSIFICATION_EVENT if is_event
            else Ticket.CLASSIFICATION_INCIDENT
        )
        ticket.t1_route = '' if is_event else route
        ticket.created_by = actor
        ticket.assigned_to = actor
        ticket.project_incident = project
        ticket.bundle_suffix = bundle_suffix_for_index(len(tickets))
        ticket.save()
        if is_event:
            ticket.transition_to(
                Ticket.STATUS_ESCALATED_T2,
                actor,
                f'Project Incident {project.project_code} — '
                f'จัดประเภท {ticket.device_name} เป็น Event '
                '— ส่ง Tier 2 ยืนยันก่อนปิด',
            )
        else:
            route_label = (
                'เจ้าของระบบ'
                if route == Ticket.T1_ROUTE_OWNER else 'ผู้ดูแลระบบ'
            )
            ticket.transition_to(
                Ticket.STATUS_PENDING_MGR_TRIAGE,
                actor,
                f'Project Incident {project.project_code} — '
                f'จัดประเภท {ticket.device_name} เป็น Incident '
                f'และเลือกส่งให้{route_label} '
                '— รอผู้จัดการ SOC ตรวจ',
            )
        tickets.append(ticket)
    return tickets


def _ticket_creation_warnings(ticket):
    warnings = []
    if ticket.system_owner and ticket.system_owner.email:
        if not notify_system_owner_created(ticket):
            warnings.append('Ticket สร้างแล้ว แต่ส่งอีเมลแจ้ง System Owner ไม่สำเร็จ')
    if ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE:
        notify_manager_triage_pending(ticket)
    return tuple(warnings)
