"""Write-side Project Incident workflow operations.

Views retain HTTP validation, authorization, and user-facing messages.  This
module coordinates the database changes that affect a Project Incident and its
member tickets so those mutations have one transactional home.
"""

from dataclasses import dataclass, field

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from .case_creation import BUNDLE_SHARED_FIELDS
from .forms import ProjectIncidentTargetForm
from .models import (
    ProjectIncident, ProjectIncidentAttachment, ProjectIncidentLog, Ticket,
    TicketIOC, TicketLog, bundle_suffix_for_index,
)
from .notifications import (
    notify_containment_alert, notify_manager_triage_pending,
    notify_system_owner_created,
)


MAX_PROJECT_MEMBERS = 25


@dataclass(frozen=True)
class ProjectWorkflowResult:
    """The non-HTTP outcome of a Project Incident write operation."""

    project: ProjectIncident
    tickets: tuple[Ticket, ...] = ()
    attachments: tuple[ProjectIncidentAttachment, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)


def add_project_member(*, project, target_form, actor):
    """Add one newly reported system and place it in the correct workflow lane."""
    cleaned = target_form.cleaned_data
    with transaction.atomic():
        locked_project = ProjectIncident.objects.select_for_update().get(pk=project.pk)
        members = locked_project.member_tickets.select_for_update()
        if not members.exclude(status__in=Ticket.TERMINAL_STATUSES).exists():
            raise ValidationError(
                'ไม่สามารถเพิ่มระบบได้ เนื่องจาก Project Incident นี้ปิดครบทุก Ticket แล้ว'
            )
        if members.count() >= MAX_PROJECT_MEMBERS:
            raise ValidationError(
                f'Project Incident หนึ่งรายการมี Member Ticket ได้ไม่เกิน {MAX_PROJECT_MEMBERS} ระบบ'
            )

        lead = members.order_by('bundle_suffix', 'created_at').first()
        if lead is None:
            raise ValidationError('Project Incident นี้ไม่มี Member Ticket ต้นแบบ')

        ticket = target_form.save(commit=False)
        for field_name in BUNDLE_SHARED_FIELDS:
            setattr(ticket, field_name, getattr(lead, field_name))
        ticket.incident_name = lead.incident_name or locked_project.title

        route = cleaned['t1_route']
        is_event = route == ProjectIncidentTargetForm.ROUTE_EVENT
        ticket.classification = (
            Ticket.CLASSIFICATION_EVENT if is_event
            else Ticket.CLASSIFICATION_INCIDENT
        )
        ticket.t1_route = '' if is_event else route
        ticket.created_by = locked_project.created_by or actor
        ticket.assigned_to = ticket.created_by
        ticket.project_incident = locked_project

        used_suffixes = set(members.values_list('bundle_suffix', flat=True))
        suffix_index = len(used_suffixes)
        suffix = bundle_suffix_for_index(suffix_index)
        while suffix in used_suffixes:
            suffix_index += 1
            suffix = bundle_suffix_for_index(suffix_index)
        ticket.bundle_suffix = suffix

        now = timezone.now()
        if is_event:
            ticket.status = Ticket.STATUS_ESCALATED_T2
            ticket.classification_at_escalation = Ticket.CLASSIFICATION_EVENT
            ticket.escalated_to_t2_at = now
            route_label = 'Event — ส่ง Tier 2 ยืนยันและปิด'
        elif locked_project.emergency_decided_at is None:
            ticket.status = Ticket.STATUS_PENDING_MGR_TRIAGE
            route_label = (
                'Incident — รอ Project Review เพื่อส่งให้เจ้าของระบบ'
                if route == Ticket.T1_ROUTE_OWNER
                else 'Incident — รอ Project Review เพื่อส่งให้ผู้ดูแลระบบ'
            )
        else:
            ticket.is_emergency = locked_project.is_emergency
            ticket.emergency_decided_by = locked_project.emergency_decided_by
            ticket.emergency_decided_at = locked_project.emergency_decided_at
            if route == Ticket.T1_ROUTE_OWNER:
                ticket.status = Ticket.STATUS_AWAITING_OWNER
                ticket.direct_owner_remediation = True
                ticket.owner_contacted_at = now
                route_label = 'Incident — ส่งให้เจ้าของระบบตาม Project Review เดิม'
            else:
                ticket.status = Ticket.STATUS_AWAITING_CONTAINMENT
                ticket.report_issued_at = now
                route_label = 'Incident — ส่งให้ผู้ดูแลระบบตาม Project Review เดิม'

        ticket.status_changed_at = now
        ticket.save()
        TicketIOC.objects.bulk_create([
            TicketIOC(
                ticket=ticket,
                category=ioc.category,
                value=ioc.value,
                order=ioc.order,
            )
            for ioc in lead.iocs.all()
        ])

        note = (
            f'เพิ่มระบบ {ticket.device_name} ใน Project Incident '
            f'{locked_project.project_code} โดย '
            f'{actor.get_full_name() or actor.username} — {route_label}'
        )
        TicketLog.objects.create(
            ticket=ticket,
            author=actor,
            status_at_time=ticket.status,
            note=note,
        )
        ProjectIncidentLog.objects.create(
            project=locked_project,
            author=actor,
            note=f'เพิ่ม Member Ticket {ticket.bundle_ref}: {ticket.device_name} — {route_label}',
        )
        locked_project.save(update_fields=('updated_at',))

    if ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE:
        notify_manager_triage_pending(ticket)
        warnings = ()
    elif ticket.status == Ticket.STATUS_AWAITING_CONTAINMENT:
        warnings = _containment_warnings(ticket)
    elif ticket.status == Ticket.STATUS_AWAITING_OWNER:
        warnings = _owner_route_warnings(ticket)
    else:
        warnings = ()
    return ProjectWorkflowResult(
        project=locked_project,
        tickets=(ticket,),
        warnings=warnings,
    )


def forward_project_review(*, project, actor, want_emergency, note):
    """Record one group verdict and forward every Incident awaiting review."""
    verdict = 'Emergency' if want_emergency else 'Normal'
    with transaction.atomic():
        locked_project = ProjectIncident.objects.select_for_update().get(pk=project.pk)
        pending = tuple(
            locked_project.member_tickets.select_for_update().filter(
                status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            )
        )
        if not pending:
            raise ValidationError('ไม่มี Member Ticket ที่รอ Project Review')

        now = timezone.now()
        locked_project.is_emergency = want_emergency
        locked_project.emergency_decided_by = actor
        locked_project.emergency_decided_at = now
        locked_project.save(update_fields=(
            'is_emergency', 'emergency_decided_by', 'emergency_decided_at',
            'updated_at',
        ))
        ProjectIncidentLog.objects.create(
            project=locked_project,
            author=actor,
            note=f'Project Review: {verdict} — {note}',
        )
        for ticket in pending:
            ticket.assess_emergency_initial(want_emergency, actor)
            target = (
                Ticket.STATUS_AWAITING_OWNER
                if ticket.t1_route == Ticket.T1_ROUTE_OWNER
                else Ticket.STATUS_AWAITING_CONTAINMENT
            )
            ticket.transition_to(target, actor, f'[Project Review: {verdict}] {note}')

    warnings = tuple(
        warning
        for ticket in pending
        for warning in (
            _owner_route_warnings(ticket)
            if ticket.status == Ticket.STATUS_AWAITING_OWNER
            else _containment_warnings(ticket)
        )
    )
    return ProjectWorkflowResult(
        project=locked_project,
        tickets=pending,
        warnings=warnings,
    )


def reassess_project_emergency(*, project, actor, value, reason):
    """Apply a post-review emergency reassessment to active member tickets."""
    with transaction.atomic():
        locked_project = ProjectIncident.objects.select_for_update().get(pk=project.pk)
        active_members = tuple(
            locked_project.member_tickets.select_for_update()
            .exclude(status__in=Ticket.TERMINAL_STATUSES)
            .exclude(status=Ticket.STATUS_PENDING_MGR_TRIAGE)
            .filter(classification=Ticket.CLASSIFICATION_INCIDENT)
        )
        for ticket in active_members:
            if ticket.is_emergency != value:
                old = ticket.is_emergency
                ticket.is_emergency = value
                ticket.save(update_fields=('is_emergency', 'updated_at'))
                action_label = 'ตั้งเป็น' if value else 'ยกเลิก'
                TicketLog.objects.create(
                    ticket=ticket,
                    author=actor,
                    status_at_time=ticket.status,
                    note=(
                        f'[Project Reassess Emergency] {action_label} Emergency '
                        f'({old} → {value}) — เหตุผล: {reason}'
                    ),
                )
        locked_project.is_emergency = value
        locked_project.save(update_fields=('is_emergency', 'updated_at'))
        state = 'Emergency' if value else 'Normal'
        ProjectIncidentLog.objects.create(
            project=locked_project,
            author=actor,
            note=f'Reassess Emergency: {state} — {reason}',
        )
    return ProjectWorkflowResult(project=locked_project, tickets=active_members)


def add_shared_attachments(*, project, actor, uploads, description):
    """Add a validated batch of shared evidence and its single audit record."""
    uploads = tuple(uploads)
    with transaction.atomic():
        attachments = tuple(
            ProjectIncidentAttachment.objects.create(
                project=project,
                file=upload,
                original_name=upload.name,
                description=description,
                uploaded_by=actor,
            )
            for upload in uploads
        )
        ProjectIncidentLog.objects.create(
            project=project,
            author=actor,
            note='แนบหลักฐานส่วนกลาง: ' + ', '.join(upload.name for upload in uploads),
        )
    return ProjectWorkflowResult(project=project, attachments=attachments)


def delete_shared_attachment(*, attachment, actor, reason):
    """Soft-delete shared evidence and record its recovery reason."""
    with transaction.atomic():
        locked_attachment = ProjectIncidentAttachment.objects.select_for_update().get(
            pk=attachment.pk,
        )
        locked_attachment.deleted_by = actor
        locked_attachment.deleted_at = timezone.now()
        locked_attachment.deleted_reason = reason[:255]
        locked_attachment.save(update_fields=('deleted_by', 'deleted_at', 'deleted_reason'))
        ProjectIncidentLog.objects.create(
            project=locked_attachment.project,
            author=actor,
            note=(
                f'ลบหลักฐานส่วนกลาง: {locked_attachment.original_name} '
                f'— เหตุผล: {reason}'
            ),
        )
    return ProjectWorkflowResult(project=locked_attachment.project, attachments=(locked_attachment,))


def restore_shared_attachment(*, attachment, actor):
    """Restore soft-deleted shared evidence and retain who removed it."""
    with transaction.atomic():
        locked_attachment = ProjectIncidentAttachment.all_objects.select_for_update().get(
            pk=attachment.pk,
        )
        removed_by = (
            locked_attachment.deleted_by.get_full_name()
            or locked_attachment.deleted_by.username
        ) if locked_attachment.deleted_by else 'ไม่ทราบผู้ลบ'
        locked_attachment.deleted_by = None
        locked_attachment.deleted_at = None
        locked_attachment.deleted_reason = ''
        locked_attachment.save(update_fields=('deleted_by', 'deleted_at', 'deleted_reason'))
        ProjectIncidentLog.objects.create(
            project=locked_attachment.project,
            author=actor,
            note=(
                f'กู้คืนหลักฐานส่วนกลาง: {locked_attachment.original_name} '
                f'(ลบโดย {removed_by})'
            ),
        )
    return ProjectWorkflowResult(project=locked_attachment.project, attachments=(locked_attachment,))


def _containment_warnings(ticket):
    """Notify the assigned admin, returning the existing view warning text."""
    if not ticket.assigned_admin_id:
        return ('Ticket routed — ไม่สามารถส่งอีเมลแจ้งเตือนได้: ยังไม่ได้กำหนดผู้ดูแลระบบ',)
    admin = ticket.assigned_admin
    if not admin.email:
        return (f'Ticket routed — {admin.get_full_name() or admin.username} ไม่มีอีเมล',)
    if not notify_containment_alert(ticket, reason=None):
        return ('Ticket routed แต่ส่งอีเมลแจ้งเตือนไม่สำเร็จ — โปรดแจ้งผู้ดูแลระบบด้วยตนเอง',)
    return ()


def _owner_route_warnings(ticket):
    """Notify an owner only after the manager releases the Incident lane."""
    if not ticket.system_owner_id:
        return ('Ticket routed — ไม่สามารถแจ้งเจ้าของระบบได้: ยังไม่ได้กำหนดเจ้าของระบบ',)
    owner = ticket.system_owner
    if not owner.email:
        return (f'Ticket routed — {owner.get_full_name() or owner.username} ไม่มีอีเมล',)
    if not notify_system_owner_created(ticket):
        return ('Ticket routed แต่ส่งอีเมลแจ้งเจ้าของระบบไม่สำเร็จ — โปรดแจ้งด้วยตนเอง',)
    return ()
