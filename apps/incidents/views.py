import calendar
import ipaddress
import logging

import requests
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.http import FileResponse, Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.accounts.models import UserProfile
from apps.incidents import ola as ola_buckets
from apps.wazuh_ingest.models import WazuhAlert
from .forms import (
    AdminAssignmentForm, AttachmentForm, ProjectIncidentForm,
    ProjectIncidentTargetFormSet, ResponseRequestForm, SubtaskForm,
    SubtaskUpdateForm, TicketForm, TicketReviewForm, TriageForm,
)
from .models import (
    ProjectIncident, ThreatGuidance, Ticket, TicketAttachment, TicketLog,
    TicketSubtask, TriageRecord, bundle_suffix_for_index, validate_attachment,
)
from .report_content import GUIDANCE_COORDINATION_NOTE
from .notifications import (
    notify_containment_alert,
    notify_containment_submitted,
    notify_manager_triage_pending,
    notify_response_request_created,
    notify_response_request_completed,
    notify_system_owner_created,
    notify_system_owner_closed,
)
from .reports import (
    build_ticket_report_render_context,
    generate_ticket_report,
    generate_ticket_report_pdf,
)

logger = logging.getLogger(__name__)


# ── Private helpers ──────────────────────────────────────────────────── #

def _user_can_drive(ticket, user, perm):
    """Whether ``user`` satisfies a SOC-side transition permission token.

    Only the SOC-driven tokens are considered here (the ASSIGNED_ADMIN step is
    handled by the dedicated containment form, not the status dropdown).
    """
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    if profile is None:
        return False
    if perm == 'TIER1_CREATOR':
        return profile.is_tier1 and user.pk == ticket.created_by_id
    if perm == 'TIER2':
        return profile.is_tier2
    if perm == 'MANAGER':
        return profile.is_soc_manager
    return False


def _valid_soc_status_choices(ticket, user):
    """Status options to offer this user in the detail-page dropdown, honoring
    the state machine, the Event/Incident + manager-routing gates, and the
    per-user transition permission.
    """
    profile = getattr(user, 'profile', None)
    if not user.is_superuser and (profile is None or not profile.is_soc):
        return []

    status_map = dict(Ticket.STATUS_CHOICES)
    result = []
    if (
        not user.is_superuser
        and ticket.status in Ticket.CREATOR_REVIEW_STATUSES
        and user.pk != ticket.created_by_id
    ):
        pass  # not this ticket's creator — can't even add a note in this stage
    else:
        result.append((ticket.status, status_map.get(ticket.status, ticket.status)))

    for next_status in Ticket.ALLOWED_TRANSITIONS.get(ticket.status, []):
        if not ticket.can_transition_to(next_status):
            continue  # blocked by classification or manager-routing gate
        perm = Ticket.TRANSITION_PERMISSIONS.get((ticket.status, next_status))
        if perm == 'ASSIGNED_ADMIN':
            continue  # admin uses the containment form, not this dropdown
        if _user_can_drive(ticket, user, perm):
            result.append((next_status, status_map.get(next_status, next_status)))

    return result


def _transition_actions(ticket, user):
    """Return only legal, permitted forward actions for the current user."""
    labels = {
        Ticket.STATUS_CLOSED_EVENT: 'Mark as Event -> Close',
        Ticket.STATUS_T1_REVIEW: 'Mark as Incident -> Return to Tier 1',
        Ticket.STATUS_PENDING_MGR_TRIAGE: 'Route to SOC Manager review',
        Ticket.STATUS_OWNER_REMEDIATED: 'Owner fixed it -> Confirm',
        Ticket.STATUS_PENDING_T2_REVIEW: 'Send to Tier 2 review',
        Ticket.STATUS_PENDING_MANAGER: 'Send to SOC Manager',
        Ticket.STATUS_APPROVED: (
            'Verify -> Close'
            if ticket.status in (
                Ticket.STATUS_PENDING_MANAGER, Ticket.STATUS_PENDING_T2_REVIEW,
                Ticket.STATUS_CONTAINMENT_REPORTED,
            ) else 'Close case'
        ),
    }
    actions = []
    for next_status in Ticket.ALLOWED_TRANSITIONS.get(ticket.status, []):
        can_transition = ticket.can_transition_to(next_status)
        # Tier 2's two decision buttons also set the classification. Ask the
        # model whether each edge is valid with that proposed classification.
        if ticket.status == Ticket.STATUS_ESCALATED_T2:
            proposed = {
                Ticket.STATUS_CLOSED_EVENT: Ticket.CLASSIFICATION_EVENT,
                Ticket.STATUS_T1_REVIEW: Ticket.CLASSIFICATION_INCIDENT,
            }.get(next_status)
            if proposed:
                original = ticket.classification
                ticket.classification = proposed
                can_transition = ticket.can_transition_to(next_status)
                ticket.classification = original
        if not can_transition:
            continue
        permission = Ticket.TRANSITION_PERMISSIONS.get((ticket.status, next_status))
        if permission == 'ASSIGNED_ADMIN' or not _user_can_drive(ticket, user, permission):
            continue
        label = labels.get(next_status, dict(Ticket.STATUS_CHOICES).get(next_status, next_status))
        if next_status == Ticket.STATUS_AWAITING_CONTAINMENT:
            label = (
                'Return to System Admin (not contained)'
                if ticket.status == Ticket.STATUS_CONTAINMENT_REPORTED
                else 'Send to System Admin'
            )
        if next_status == Ticket.STATUS_AWAITING_OWNER:
            if ticket.status == Ticket.STATUS_OWNER_REMEDIATED:
                label = 'Return to owner (not fixed)'
            elif ticket.status == Ticket.STATUS_PENDING_T2_REVIEW:
                label = 'Reject -> back to owner'
            else:
                label = 'Send to owner (direct)'
        actions.append({'status': next_status, 'label': label})
    return actions


def _notify_containment(ticket, reason, request):
    if not ticket.assigned_admin_id:
        messages.warning(request, 'Ticket routed — ไม่สามารถส่งอีเมลแจ้งเตือนได้: ยังไม่ได้กำหนดผู้ดูแลระบบ')
        return
    admin = ticket.assigned_admin
    if not admin.email:
        messages.warning(request, f'Ticket routed — {admin.get_full_name() or admin.username} ไม่มีอีเมล')
        return
    if not notify_containment_alert(ticket, reason=reason):
        messages.warning(request, 'Ticket routed แต่ส่งอีเมลแจ้งเตือนไม่สำเร็จ — โปรดแจ้งผู้ดูแลระบบด้วยตนเอง')


def _notify_owner_closed(ticket, request):
    if ticket.system_owner and ticket.system_owner.email:
        attachments = list(ticket.attachments.all())
        if not notify_system_owner_closed(ticket, attachments=attachments):
            messages.warning(request, 'Ticket ปิดแล้ว แต่ส่งอีเมลแจ้ง System Owner ไม่สำเร็จ')


# ── Ticket views ─────────────────────────────────────────────────────── #

def _can_create_ticket_from_triage(triage, user):
    if triage.ticket_id or triage.project_incident_id:
        return False
    if not triage.decision:
        return (
            user.is_superuser
            or (triage.claimed_by_id == user.id and getattr(getattr(user, 'profile', None), 'is_tier1', False))
        )
    if user.is_superuser:
        return triage.final_decision == TriageRecord.DECISION_TP
    if triage.decision == TriageRecord.DECISION_TP:
        return triage.analyst_id == user.id
    return (
        triage.decision == TriageRecord.DECISION_ESCALATED
        and triage.t2_decision == TriageRecord.DECISION_TP
        and triage.escalated_to_id == user.id
    )


def _can_create_ticket_from_wazuh(alert, user):
    profile = getattr(user, 'profile', None)
    if alert.claimed_by_id != user.id or hasattr(alert, 'ticket'):
        return False
    if user.is_superuser:
        return alert.triage_status in (
            WazuhAlert.TRIAGE_TRIAGING,
            WazuhAlert.TRIAGE_ESCALATED,
        )
    if alert.triage_status == WazuhAlert.TRIAGE_TRIAGING:
        return True
    if alert.triage_status != WazuhAlert.TRIAGE_ESCALATED or profile is None:
        return False
    user_tier = WazuhAlert.TIER_MANAGER if profile.is_soc_manager else profile.tier
    return alert.escalated_to_tier == user_tier


def _consume_source_alert(alert, user, *, classification, link_ticket,
                          project_incident=None):
    """Mark a claimed Wazuh alert handled once it has become a ticket (or a
    case bundle) and stamp the analyst response time on ``link_ticket``.

    Shared by the single-ticket (create_ticket) and fan-out
    (create_project_incident) flows — the only differences are the disposition
    (a bundle is always an Incident) and whether the alert links to a
    ProjectIncident. ``alert`` must already be locked (select_for_update) and
    re-validated by the caller.
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
        'triage_status', 'triaged_by', 'triaged_at',
        'escalated_to_tier', 'claimed_by', 'claimed_at',
    ]
    if project_incident is not None:
        alert.project_incident = project_incident
        update_fields.insert(0, 'project_incident')
    alert.save(update_fields=update_fields)

    # Stamp analyst response time once (alert actionable → ticket raised).
    # now() is within sub-second of the ticket's auto_now_add created_at; guard
    # against clock skew that would otherwise yield a negative duration.
    delta = now - alert.ingested_at
    if delta.total_seconds() >= 0:
        link_ticket.alert_conversion_duration = delta
        link_ticket.save(update_fields=['alert_conversion_duration'])


def _consume_source_triage(triage, *, classification, ticket=None,
                           project_incident=None):
    """Mark a claimed manual-triage record handled once it has become a ticket
    (or a case bundle): record the Event/Incident decision, link it to whatever
    it spawned, and release the claim so it leaves the manual queue.

    Shared by both create flows. ``triage`` must already be locked
    (select_for_update) and re-validated by the caller.
    """
    triage.decision = (
        TriageRecord.DECISION_FP
        if classification == Ticket.CLASSIFICATION_EVENT
        else TriageRecord.DECISION_TP
    )
    triage.claimed_by = None
    triage.claimed_at = None
    update_fields = ['decision', 'claimed_by', 'claimed_at']
    if ticket is not None:
        triage.ticket = ticket
        update_fields.insert(0, 'ticket')
    if project_incident is not None:
        triage.project_incident = project_incident
        update_fields.insert(0, 'project_incident')
    triage.save(update_fields=update_fields)


@login_required
def ticket_list(request):
    visible = Ticket.objects.visible_to(request.user)
    return _render_ticket_list(
        request,
        visible,
        page_title='Active Incidents',
        heading='Active incidents',
        description='Monitor every open case you are permitted to view.',
    )


@login_required
def manager_queue(request):
    """Action-required queue for SOC Manager review and approval steps only."""
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_soc_manager):
        raise PermissionDenied('SOC Manager access is required for this queue.')

    visible = Ticket.objects.visible_to(request.user).filter(
        status__in=Ticket.MANAGER_QUEUE_STATUSES,
    )
    return _render_ticket_list(
        request,
        visible,
        page_title='Manager Reviews',
        heading='Manager reviews',
        description='Cases waiting for your routing decision or emergency approval.',
        is_manager_queue=True,
    )


def _render_ticket_list(request, visible, *, page_title, heading, description,
                        is_manager_queue=False):
    """Render a filtered, non-terminal ticket list with shared list controls."""
    tickets_qs = visible.exclude(
        status__in=list(Ticket.TERMINAL_STATUSES)
    ).select_related('assigned_admin', 'created_by')

    search = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '').strip()
    severity_filter = request.GET.get('severity', '').strip()
    emergency_filter = request.GET.get('emergency', '').strip()
    sort = request.GET.get('sort', 'ola').strip()

    if search:
        tickets_qs = tickets_qs.filter(
            Q(ticket_id__icontains=search)
            | Q(device_name__icontains=search)
            | Q(ip_address__icontains=search)
            | Q(issue_description__icontains=search)
            | Q(destination_ip__icontains=search)
        )

    active_status_choices = [
        (code, label) for code, label in Ticket.STATUS_CHOICES
        if code not in Ticket.TERMINAL_STATUSES
    ]
    if is_manager_queue:
        active_status_choices = [
            (code, label) for code, label in active_status_choices
            if code in Ticket.MANAGER_QUEUE_STATUSES
        ]
    if status_filter in dict(active_status_choices):
        tickets_qs = tickets_qs.filter(status=status_filter)
    else:
        status_filter = ''

    if severity_filter in dict(Ticket.SEVERITY_CHOICES):
        tickets_qs = tickets_qs.filter(severity=severity_filter)
    else:
        severity_filter = ''

    if emergency_filter in ('1', '0'):
        tickets_qs = tickets_qs.filter(is_emergency=emergency_filter == '1')
    else:
        emergency_filter = ''

    # OLA-pressure bucket filter — shares thresholds with the dashboard chart
    # (apps.incidents.ola) so the dashboard's "Overdue/Due ≤1h/…" bars can
    # deep-link straight to the matching slice of this list.
    ola_filter = request.GET.get('ola', '').strip()
    if ola_filter in ola_buckets.BUCKET_KEYS:
        tickets_qs = tickets_qs.filter(
            ola_buckets.bucket_filter(ola_filter, timezone.now()))
    else:
        ola_filter = ''

    sort_map = {
        'ola':       ('ola_contain_deadline',),
        'emergency': ('-is_emergency', 'ola_contain_deadline'),
        'newest':    ('-created_at',),
        'oldest':    ('created_at',),
    }
    if sort not in sort_map:
        sort = 'ola'
    tickets_qs = tickets_qs.order_by(*sort_map[sort])

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    # Live OLA breach: active ticket already past its contain/resolve deadline
    # (vs now()). Medium/Low have no contain deadline, so they never count here.
    ola_breach_count = visible.filter(
        ola_contain_deadline__lt=timezone.now()
    ).exclude(status__in=list(Ticket.TERMINAL_STATUSES)).count()

    return render(request, 'incidents/ticket_list.html', {
        'page_title': page_title,
        'heading': heading,
        'description': description,
        'is_manager_queue': is_manager_queue,
        'tickets': page_obj,
        'page_obj': page_obj,
        'result_count': paginator.count,
        'ola_breach_count': ola_breach_count,
        'search': search,
        'status_filter': status_filter,
        'severity_filter': severity_filter,
        'emergency_filter': emergency_filter,
        'ola_filter': ola_filter,
        'sort': sort,
        'active_status_choices': active_status_choices,
        'severity_choices': Ticket.SEVERITY_CHOICES,
        'ola_bucket_choices': ola_buckets.OLA_BUCKETS,
    })


@login_required
def create_ticket(request):
    profile = getattr(request.user, 'profile', None)
    # Tickets are always created by Tier 1 — no other role may open a case.
    if not request.user.is_superuser and (profile is None or not profile.is_tier1):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถเปิดเคสใหม่ได้')
        return redirect('ticket_list')

    # Pre-fill from triage if coming from a TP triage decision
    triage = None
    triage_id = request.GET.get('triage_id') or request.POST.get('triage_id')
    if triage_id:
        triage = get_object_or_404(TriageRecord, pk=triage_id)
        if triage.ticket_id:
            messages.info(request, 'This triage record already has a ticket.')
            return redirect('ticket_detail', pk=triage.ticket_id)
        if not _can_create_ticket_from_triage(triage, request.user):
            messages.error(request, 'You are not authorized to create a ticket from this triage record.')
            return redirect('triage_list')

    if request.method == 'POST':
        form = TicketForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            try:
                with transaction.atomic():
                    locked_triage = None
                    if triage:
                        locked_triage = TriageRecord.objects.select_for_update().get(pk=triage.pk)
                        if not _can_create_ticket_from_triage(locked_triage, request.user):
                            raise ValidationError(
                                'This triage record is no longer available for ticket creation.'
                            )

                    ticket = form.save(commit=False)
                    ticket.created_by = request.user
                    ticket.assigned_to = request.user

                    locked_alert = None
                    if ticket.wazuh_alert_id:
                        locked_alert = WazuhAlert.objects.select_for_update().get(
                            pk=ticket.wazuh_alert_id
                        )
                        if not _can_create_ticket_from_wazuh(locked_alert, request.user):
                            raise ValidationError(
                                'This Wazuh alert is not assigned to you or already has a ticket.'
                            )

                    ticket.save()

                    # T1 disposition is part of the create flow: the
                    # Event/Incident classification (set on the ticket by the
                    # form) plus the chosen route decide where the ticket goes.
                    route = form.cleaned_data.get('t1_route')
                    if ticket.classification == Ticket.CLASSIFICATION_EVENT:
                        # Event → must be confirmed by Tier 2 before closing.
                        # Tier 1 can no longer close an Event directly.
                        ticket.transition_to(
                            Ticket.STATUS_ESCALATED_T2, request.user,
                            'จัดประเภทเป็น Event — ส่งให้ Tier 2 ยืนยันก่อนปิด',
                        )
                    elif route == TicketForm.ROUTE_ESCALATE_T2:
                        ticket.transition_to(
                            Ticket.STATUS_ESCALATED_T2, request.user,
                            'จัดประเภทเป็น Incident — ส่งต่อให้ Tier 2',
                        )
                    elif route == TicketForm.ROUTE_ASSIGN_ADMIN:
                        # Incident → admin lane, but first the SOC Manager
                        # pre-containment review. Remember the chosen lane.
                        ticket.t1_route = Ticket.T1_ROUTE_ADMIN
                        ticket.transition_to(
                            Ticket.STATUS_PENDING_MGR_TRIAGE, request.user,
                            'จัดประเภทเป็น Incident — เลือกมอบหมายผู้ดูแลระบบ (รอผู้จัดการ SOC ตรวจ)',
                        )
                    elif route == TicketForm.ROUTE_DIRECT_OWNER:
                        # Incident → owner lane (no System Admin ticket / email),
                        # also via the SOC Manager pre-containment review.
                        ticket.t1_route = Ticket.T1_ROUTE_OWNER
                        ticket.transition_to(
                            Ticket.STATUS_PENDING_MGR_TRIAGE, request.user,
                            'จัดประเภทเป็น Incident — เลือกให้เจ้าของระบบแก้ไขเอง (รอผู้จัดการ SOC ตรวจ)',
                        )

                    if locked_triage:
                        _consume_source_triage(
                            locked_triage,
                            classification=ticket.classification,
                            ticket=ticket,
                        )

                    if locked_alert:
                        _consume_source_alert(
                            locked_alert, request.user,
                            classification=ticket.classification,
                            link_ticket=ticket,
                        )

                    for evidence_file in request.FILES.getlist('evidence_files'):
                        validate_attachment(evidence_file)
                        TicketAttachment.objects.create(
                            ticket=ticket,
                            file=evidence_file,
                            original_name=evidence_file.name,
                            uploaded_by=request.user,
                        )
            except ValidationError as exc:
                form.add_error(None, exc.message)
                ticket = None

            # Stage 5 — notify System Owner
            if ticket and ticket.system_owner and ticket.system_owner.email:
                if not notify_system_owner_created(ticket):
                    messages.warning(request, 'Ticket สร้างแล้ว แต่ส่งอีเมลแจ้ง System Owner ไม่สำเร็จ')

            # An Incident now waits in the SOC Manager pre-containment review
            # (PENDING_MGR_TRIAGE) rather than going straight to the lane, so
            # alert the SOC Managers that a ticket needs their triage. The
            # admin/owner is notified later, when the manager forwards.
            if ticket and ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE:
                notify_manager_triage_pending(ticket)

            if ticket:
                return redirect('ticket_detail', pk=ticket.pk)
    else:
        initial = {}
        if triage:
            initial['device_name'] = triage.source_ip
            initial['issue_description'] = triage.alert_description
            # Source channel carries straight over — issue_type and triage
            # source now share the SOURCE_CHOICES vocabulary, so it maps 1:1.
            initial['issue_type'] = triage.source
        if request.GET.get('wazuh_alert'):
            initial['wazuh_alert'] = request.GET['wazuh_alert']
        if request.GET.get('issue_description'):
            initial['issue_description'] = request.GET['issue_description']
        if request.GET.get('severity'):
            initial['severity'] = request.GET['severity']
        if request.GET.get('detailed_issue2') in dict(Ticket.DETAILED_ISSUE_CHOICES2):
            di2 = request.GET['detailed_issue2']
            initial['detailed_issue2'] = di2
            # Keep the parent category in step so the cascade stays consistent.
            parent = Ticket.parent_of_detailed_issue2(di2)
            if parent:
                initial['detailed_issue'] = parent
        form = TicketForm(initial=initial, user=request.user)

    # Standard containment guidance per threat category (admin-editable) for
    # the "แทรกแนวทางมาตรฐาน" button — inserted client-side, never auto-applied.
    threat_guidance = {
        g.detailed_issue: {
            'action_required': g.action_required,
            'action_precautions': g.action_precautions,
        }
        for g in ThreatGuidance.objects.filter(is_active=True)
    }

    return render(request, 'incidents/ticket_form.html', {
        'form': form,
        'triage_id': triage_id or '',
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        'threat_guidance': threat_guidance,
        'guidance_note': GUIDANCE_COORDINATION_NOTE,
    })


# ── Project Incident (Case Bundling) ─────────────────────────────────── #
# Incident-level fields copied from the shared form onto every member ticket.
# Derived from the form itself so a field added to ProjectIncidentForm can't be
# silently dropped from members by a stale hand-maintained copy. (title is a
# form-only field, not in Meta.fields, so it is correctly excluded.)
_BUNDLE_SHARED_FIELDS = list(ProjectIncidentForm.Meta.fields)


@login_required
def create_project_incident(request):
    """Fan out one multi-system incident into linked member tickets.

    Tier 1 fills the shared incident facts once and lists the affected systems;
    each system becomes a Ticket routed to its own admin (AWAITING_CONTAINMENT),
    all pointing at one ProjectIncident so they stay grouped and trackable.
    """
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_tier1):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถเปิด Project Incident ได้')
        return redirect('ticket_list')

    # Optional originating Wazuh alert — the analyst arrived here from the
    # triage queue ("Create Project Incident" on a claimed alert). It pre-fills
    # the shared fields and, on success, is linked to the whole bundle.
    source_alert = None
    alert_pk = request.POST.get('wazuh_alert') or request.GET.get('wazuh_alert')
    if alert_pk:
        source_alert = WazuhAlert.objects.filter(pk=alert_pk).first()
        if (source_alert and request.method == 'GET'
                and not _can_create_ticket_from_wazuh(source_alert, request.user)):
            messages.error(request, 'Wazuh Alert นี้ไม่ได้อยู่ในความรับผิดชอบของคุณ หรือถูกดำเนินการไปแล้ว')
            return redirect('triage_queue')

    # Or an originating manual-triage record (analyst came from Manual Triage,
    # "Create Project Incident" on a claimed record). Same idea, different queue.
    source_triage = None
    triage_pk = request.POST.get('triage_id') or request.GET.get('triage_id')
    if triage_pk:
        source_triage = TriageRecord.objects.filter(pk=triage_pk).first()
        if (source_triage and request.method == 'GET'
                and not _can_create_ticket_from_triage(source_triage, request.user)):
            messages.error(request, 'รายการ Manual Triage นี้ไม่พร้อมสำหรับการสร้าง Project Incident')
            return redirect('triage_list')

    if request.method == 'POST':
        shared_form = ProjectIncidentForm(request.POST, request.FILES, user=request.user)
        target_formset = ProjectIncidentTargetFormSet(request.POST, prefix='target')
        project = None
        if shared_form.is_valid() and target_formset.is_valid():
            shared = shared_form.cleaned_data
            created = []
            try:
                with transaction.atomic():
                    project = ProjectIncident.objects.create(
                        title=shared['title'],
                        summary=shared.get('issue_description', ''),
                        created_by=request.user,
                    )
                    for tform in target_formset:
                        cd = getattr(tform, 'cleaned_data', None)
                        if not cd or cd.get('DELETE'):
                            continue
                        ticket = tform.save(commit=False)
                        for field in _BUNDLE_SHARED_FIELDS:
                            setattr(ticket, field, shared[field])
                        # The bundle title doubles as each member's incident name.
                        ticket.incident_name = shared['title']
                        ticket.classification = Ticket.CLASSIFICATION_INCIDENT
                        # Each member is an admin-assigned Incident, so it takes
                        # the same SOC Manager pre-containment review as a single
                        # ticket before reaching the admin.
                        ticket.t1_route = Ticket.T1_ROUTE_ADMIN
                        ticket.created_by = request.user
                        ticket.assigned_to = request.user
                        ticket.project_incident = project
                        ticket.bundle_suffix = bundle_suffix_for_index(len(created))
                        ticket.save()
                        ticket.transition_to(
                            Ticket.STATUS_PENDING_MGR_TRIAGE, request.user,
                            f'Project Incident {project.project_code} — '
                            f'จัดประเภทเป็น Incident มอบหมายผู้ดูแลระบบ ({ticket.device_name}) '
                            f'— รอผู้จัดการ SOC ตรวจ',
                        )
                        created.append(ticket)

                    if len(created) < 2:
                        raise ValidationError(
                            'ต้องระบุระบบเป้าหมายอย่างน้อย 2 ระบบสำหรับ Project Incident'
                        )

                    # Evidence attaches to the first member — it is the shared
                    # incident evidence; per-target files can be added later.
                    for evidence_file in request.FILES.getlist('evidence_files'):
                        validate_attachment(evidence_file)
                        TicketAttachment.objects.create(
                            ticket=created[0], file=evidence_file,
                            original_name=evidence_file.name, uploaded_by=request.user,
                        )

                    # Consume the originating alert: link it to the bundle and
                    # mark it handled so it leaves the triage queue (mirrors the
                    # single-ticket flow, but pointing at the ProjectIncident).
                    if source_alert is not None:
                        locked_alert = WazuhAlert.objects.select_for_update().get(
                            pk=source_alert.pk
                        )
                        if not _can_create_ticket_from_wazuh(locked_alert, request.user):
                            raise ValidationError(
                                'Wazuh Alert นี้ไม่พร้อมสำหรับการสร้าง Project Incident '
                                '(อาจถูกดำเนินการไปแล้ว)'
                            )
                        # A bundle is always an Incident; the response time is
                        # stamped once on the first member.
                        _consume_source_alert(
                            locked_alert, request.user,
                            classification=Ticket.CLASSIFICATION_INCIDENT,
                            link_ticket=created[0],
                            project_incident=project,
                        )

                    # Consume the originating manual-triage record: link it to
                    # the bundle and mark it TP so it leaves the manual queue.
                    if source_triage is not None:
                        locked_triage = TriageRecord.objects.select_for_update().get(
                            pk=source_triage.pk
                        )
                        if not _can_create_ticket_from_triage(locked_triage, request.user):
                            raise ValidationError(
                                'รายการ Manual Triage นี้ไม่พร้อมสำหรับการสร้าง Project Incident '
                                '(อาจถูกดำเนินการไปแล้ว)'
                            )
                        _consume_source_triage(
                            locked_triage,
                            classification=Ticket.CLASSIFICATION_INCIDENT,
                            project_incident=project,
                        )
            except ValidationError as exc:
                shared_form.add_error(None, exc.message)
                project = None
                created = []

            if project:
                for ticket in created:
                    if ticket.system_owner and ticket.system_owner.email:
                        if not notify_system_owner_created(ticket):
                            messages.warning(
                                request,
                                f'{ticket.bundle_ref}: ส่งอีเมลแจ้ง System Owner ไม่สำเร็จ',
                            )
                # Every member waits in the SOC Manager pre-containment review;
                # one alert covers the bundle (the admin is notified per member
                # when the manager forwards each one).
                notify_manager_triage_pending(created[0])
                messages.success(
                    request,
                    f'สร้าง Project Incident {project.project_code} เรียบร้อย — '
                    f'{len(created)} Ticket ตามระบบที่ได้รับผลกระทบ',
                )
                return redirect('project_incident_detail', pk=project.pk)
    else:
        initial = {}
        if source_alert is not None:
            initial['title'] = (source_alert.rule_description or '')[:255]
            initial['issue_description'] = (
                request.GET.get('issue_description') or source_alert.rule_description
            )
            if source_alert.timestamp:
                initial['incident_datetime'] = timezone.localtime(
                    source_alert.timestamp
                ).strftime('%Y-%m-%dT%H:%M')
            if source_alert.alert_id:
                initial['reference_id'] = source_alert.alert_id
        elif source_triage is not None:
            initial['title'] = (source_triage.alert_description or '')[:255]
            initial['issue_description'] = source_triage.alert_description
            if source_triage.source:
                initial['issue_type'] = source_triage.source
            if source_triage.source_reference:
                initial['reference_id'] = source_triage.source_reference
        if request.GET.get('severity'):
            initial['severity'] = request.GET['severity']
        di2 = request.GET.get('detailed_issue2')
        if di2 in dict(Ticket.DETAILED_ISSUE_CHOICES2):
            initial['detailed_issue2'] = di2
            parent = Ticket.parent_of_detailed_issue2(di2)
            if parent:
                initial['detailed_issue'] = parent
        shared_form = ProjectIncidentForm(initial=initial, user=request.user)
        target_formset = ProjectIncidentTargetFormSet(prefix='target')

    return render(request, 'incidents/project_incident_form.html', {
        'form': shared_form,
        'target_formset': target_formset,
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        'source_alert': source_alert,
        'source_triage': source_triage,
    })


@login_required
def project_incident_detail(request, pk):
    """Overview of a case bundle: the shared incident and its member tickets."""
    project = get_object_or_404(ProjectIncident, pk=pk)
    members = (
        project.member_tickets.visible_to(request.user)
        .select_related('assigned_admin', 'system_owner', 'project_incident')
        .order_by('bundle_suffix', 'created_at')
    )
    # A user who can see none of the members has no business on the bundle page.
    if not members and not request.user.is_superuser:
        raise Http404('ไม่พบ Project Incident')
    return render(request, 'incidents/project_incident_detail.html', {
        'project': project,
        'members': members,
    })


@login_required
def ticket_detail(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    profile = getattr(request.user, 'profile', None)
    is_terminal = ticket.status in Ticket.TERMINAL_STATUSES

    can_submit_containment = (
        not is_terminal
        and ticket.status == Ticket.STATUS_AWAITING_CONTAINMENT
        and (
            request.user.is_superuser
            or (
                profile is not None
                and profile.is_system_admin
                and ticket.assigned_admin_id == request.user.pk
            )
        )
    )
    checklist_items, checklist_trailing = ticket.containment_checklist_display()
    transition_actions = _transition_actions(ticket, request.user)
    transition_codes = {item['status'] for item in transition_actions}
    can_t2_review = (
        ticket.status == Ticket.STATUS_ESCALATED_T2
        and {
            Ticket.STATUS_CLOSED_EVENT, Ticket.STATUS_T1_REVIEW,
        }.issubset(transition_codes)
    )
    can_assign_admin = (
        ticket.status == Ticket.STATUS_T1_REVIEW
        and Ticket.STATUS_PENDING_MGR_TRIAGE in transition_codes
    )
    # SOC Manager pre-containment review: flag Emergency + forward to the lane
    # Tier 1 already chose (t1_route). The manager cannot change the lane.
    can_mgr_forward = (
        not is_terminal
        and ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE
        and (request.user.is_superuser or (profile is not None and profile.is_soc_manager))
    )
    mgr_forward_target = (
        Ticket.STATUS_AWAITING_OWNER
        if ticket.t1_route == Ticket.T1_ROUTE_OWNER
        else Ticket.STATUS_AWAITING_CONTAINMENT
    )
    # Tier 2 may reclassify an in-flight case as an Event and close it directly
    # (no manager), at either verification stage.
    can_t2_reclassify = (
        not is_terminal
        and ticket.status in (
            Ticket.STATUS_CONTAINMENT_REPORTED, Ticket.STATUS_PENDING_T2_REVIEW,
        )
        and (request.user.is_superuser or (profile is not None and profile.is_tier2))
    )
    # SOC Manager may spawn a response-team request (Forensic / Red Team) at any
    # active stage. Runs in parallel to containment; an open request blocks final
    # approval (Ticket.has_open_response_requests).
    can_request_response = (
        not is_terminal
        and (request.user.is_superuser or (profile is not None and profile.is_soc_manager))
    )

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'toggle_emergency':
            value = request.POST.get('emergency_value', '') in ('1', 'true', 'True', 'on')
            note = request.POST.get('emergency_note', '').strip()
            try:
                ticket.set_emergency(value, request.user, note)
                state = 'เปิด' if value else 'ปิด'
                messages.success(request, f'{state}สถานะฉุกเฉิน (Emergency) เรียบร้อยแล้ว')
            except ValidationError as e:
                messages.error(request, e.message)

        elif action == 't2_review':
            next_status = request.POST.get('status', '')
            review_form = TicketReviewForm(request.POST, instance=ticket)
            expected_classification = {
                Ticket.STATUS_CLOSED_EVENT: Ticket.CLASSIFICATION_EVENT,
                Ticket.STATUS_T1_REVIEW: Ticket.CLASSIFICATION_INCIDENT,
            }.get(next_status)
            if not can_t2_review or next_status not in transition_codes:
                messages.error(request, 'This Tier 2 action is not permitted for the ticket.')
            elif review_form.is_valid() and review_form.cleaned_data['classification'] != expected_classification:
                messages.error(request, 'Classification must match the selected Tier 2 decision.')
            elif review_form.is_valid():
                try:
                    with transaction.atomic():
                        ticket = review_form.save()
                        ticket.transition_to(
                            next_status, request.user,
                            request.POST.get('decision_note', '').strip()
                            or dict((item['status'], item['label']) for item in transition_actions)[next_status],
                        )
                    if next_status == Ticket.STATUS_CLOSED_EVENT:
                        _notify_owner_closed(ticket, request)
                except ValidationError as e:
                    messages.error(request, e.message)
            else:
                messages.error(request, 'Please correct the Tier 2 review information.')

        elif action == 'assign_admin':
            # T1 reviews a returned Incident and picks a handling lane (Admin or
            # Owner); either way it goes to the SOC Manager pre-containment
            # review. Only the Admin lane needs an assigned admin.
            route = request.POST.get('t1_route', Ticket.T1_ROUTE_ADMIN)
            note = request.POST.get('decision_note', '').strip()
            assignment_form = AdminAssignmentForm(request.POST, instance=ticket)
            if not can_assign_admin:
                messages.error(request, 'This ticket cannot be assigned by the current user.')
            elif not note:
                messages.error(request, 'A review note is required.')
            elif route == Ticket.T1_ROUTE_OWNER:
                try:
                    with transaction.atomic():
                        ticket.t1_route = Ticket.T1_ROUTE_OWNER
                        ticket.transition_to(
                            Ticket.STATUS_PENDING_MGR_TRIAGE, request.user, note,
                        )
                    notify_manager_triage_pending(ticket)
                except ValidationError as e:
                    messages.error(request, e.message)
            elif assignment_form.is_valid():
                try:
                    with transaction.atomic():
                        ticket = assignment_form.save(commit=False)
                        ticket.t1_route = Ticket.T1_ROUTE_ADMIN
                        ticket.transition_to(
                            Ticket.STATUS_PENDING_MGR_TRIAGE, request.user, note,
                        )
                    notify_manager_triage_pending(ticket)
                except ValidationError as e:
                    messages.error(request, e.message)
            else:
                messages.error(request, 'กรุณาเลือกผู้ดูแลระบบที่รับผิดชอบ')

        elif action == 'mgr_forward':
            # SOC Manager reviews, optionally flags Emergency, and forwards the
            # ticket to the lane Tier 1 fixed. The manager cannot divert the lane.
            note = request.POST.get('decision_note', '').strip()
            want_emergency = request.POST.get('is_emergency', '') in ('1', 'true', 'on')
            if not can_mgr_forward:
                messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
            elif not note:
                messages.error(request, 'กรุณากรอกบันทึกการตรวจ')
            else:
                try:
                    with transaction.atomic():
                        if want_emergency != ticket.is_emergency:
                            ticket.set_emergency(want_emergency, request.user, note)
                        ticket.transition_to(mgr_forward_target, request.user, note)
                    if ticket.status == Ticket.STATUS_AWAITING_CONTAINMENT:
                        _notify_containment(ticket, None, request)
                except ValidationError as e:
                    messages.error(request, e.message)

        elif action == 't2_reclassify_event':
            # Tier 2 decides an in-flight case is actually a benign Event: flip
            # the classification and close directly (never via the manager).
            note = request.POST.get('decision_note', '').strip()
            if not can_t2_reclassify:
                messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
            elif not note:
                messages.error(request, 'กรุณากรอกบันทึกการตัดสินใจ')
            else:
                try:
                    with transaction.atomic():
                        ticket.classification = Ticket.CLASSIFICATION_EVENT
                        ticket.transition_to(
                            Ticket.STATUS_CLOSED_EVENT, request.user, note,
                        )
                    _notify_owner_closed(ticket, request)
                except ValidationError as e:
                    messages.error(request, e.message)

        elif action == 'containment':
            if not can_submit_containment:
                messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
            else:
                # The System Admin writes the countermeasure (containment_report)
                # and investigation-findings (remediation_summary) fields, then
                # submits the ticket for Tier 2 verification. Classification is
                # NOT set here — it is Tier 1's (or Tier 2's) decision.
                report = request.POST.get('containment_report', '').strip()
                remediation = request.POST.get('remediation_summary', '').strip()
                note = request.POST.get('note', '').strip()

                if not report:
                    messages.error(request, 'กรุณากรอกรายงานการควบคุม')
                else:
                    ticket.containment_report = report
                    if remediation:
                        ticket.remediation_summary = remediation

                    # Save the (non-mandatory) containment checklist. Items are
                    # parsed from the current action_required so indices line up
                    # with the checkboxes rendered on the form.
                    item_lines, _ = Ticket.parse_checklist_items(ticket.action_required)
                    checked = set(request.POST.getlist('checklist_done'))
                    ticket.containment_checklist = [
                        {'text': line, 'done': str(idx) in checked}
                        for idx, line in enumerate(item_lines)
                    ]
                    done_count = sum(1 for c in ticket.containment_checklist if c['done'])
                    total_count = len(ticket.containment_checklist)

                    transition_note = note or 'ส่งรายงานการควบคุมแล้ว'
                    if total_count:
                        transition_note = (
                            f'{transition_note}\n'
                            f'(เช็กลิสต์สิ่งที่ต้องดำเนินการ: '
                            f'ดำเนินการแล้ว {done_count}/{total_count} รายการ)'
                        )
                    try:
                        ticket.transition_to(
                            Ticket.STATUS_CONTAINMENT_REPORTED,
                            request.user,
                            transition_note,
                        )
                        if not notify_containment_submitted(ticket):
                            messages.warning(
                                request,
                                'ส่งรายงานการควบคุมแล้ว แต่ส่งอีเมลแจ้งเจ้าหน้าที่ SOC ไม่สำเร็จ',
                            )
                    except ValidationError as e:
                        messages.error(request, e.message)

        elif action in ('workflow_action', 'soc_update'):
            new_note = request.POST.get('update_notes', '').strip()
            new_status = request.POST.get('status')
            prev_status = ticket.status

            if not new_note:
                messages.error(request, 'กรุณากรอกบันทึกการดำเนินการ')
            elif new_status not in transition_codes:
                messages.error(request, 'การดำเนินการนี้ไม่ได้รับอนุญาตในขั้นตอนปัจจุบัน')
            else:
                try:
                    ticket.transition_to(new_status, request.user, new_note)

                    # Notify Security Admin when routed to AWAITING_CONTAINMENT.
                    # The rejection-loop note (CONTAINMENT_REPORTED → AC) tells
                    # the admin what to fix; the first assignment has no reason.
                    if new_status == Ticket.STATUS_AWAITING_CONTAINMENT:
                        reason = (
                            new_note
                            if prev_status == Ticket.STATUS_CONTAINMENT_REPORTED
                            else None
                        )
                        _notify_containment(ticket, reason, request)

                    # Notify System Owner on closure (incident approved or
                    # benign Event closed).
                    if new_status in (Ticket.STATUS_APPROVED, Ticket.STATUS_CLOSED_EVENT):
                        _notify_owner_closed(ticket, request)

                except ValidationError as e:
                    messages.error(request, e.message)

        return redirect('ticket_detail', pk=pk)

    logs = ticket.logs.all()
    attachments = ticket.attachments.all()
    valid_status_choices = _valid_soc_status_choices(ticket, request.user)
    attachment_form = AttachmentForm()

    subtasks = ticket.subtasks.select_related('assigned_to').prefetch_related('attachments')
    subtask_form = SubtaskForm()
    subtask_update_form = SubtaskUpdateForm()
    response_request_form = ResponseRequestForm()
    can_create_subtask = request.user.is_superuser or (profile and profile.is_soc)

    # Data for the spawn card's client-side assignee filter (view still validates
    # the choice authoritatively). Only computed when the card is shown.
    response_routing = {}
    response_member_roles = {}
    if can_request_response:
        response_routing = TicketSubtask.response_routing()
        response_member_roles = {
            str(pk): role
            for pk, role in User.objects.filter(
                is_active=True,
                profile__role__in=(
                    UserProfile.ROLE_FORENSIC, UserProfile.ROLE_REDTEAM_MANAGER,
                ),
            ).values_list('pk', 'profile__role')
        }

    return render(request, 'incidents/ticket_detail.html', {
        'ticket': ticket,
        'logs': logs,
        'attachments': attachments,
        'attachment_form': attachment_form,
        'profile': profile,
        'is_terminal': is_terminal,
        'can_submit_containment': can_submit_containment,
        'checklist_items': checklist_items,
        'checklist_trailing': checklist_trailing,
        'has_saved_checklist': bool(ticket.containment_checklist),
        'valid_status_choices': valid_status_choices,
        'transition_actions': transition_actions,
        'can_t2_review': can_t2_review,
        't2_review_form': TicketReviewForm(instance=ticket),
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        'can_assign_admin': can_assign_admin,
        'assignment_form': AdminAssignmentForm(instance=ticket),
        'can_mgr_forward': can_mgr_forward,
        'mgr_forward_target': mgr_forward_target,
        'can_t2_reclassify': can_t2_reclassify,
        'can_request_response': can_request_response,
        'response_request_form': response_request_form,
        'response_routing': response_routing,
        'response_member_roles': response_member_roles,
        'RESPONSE_TYPES': list(TicketSubtask.RESPONSE_TYPES),
        'T1_ROUTE_ADMIN': Ticket.T1_ROUTE_ADMIN,
        'T1_ROUTE_OWNER': Ticket.T1_ROUTE_OWNER,
        'can_set_emergency': ticket.can_set_emergency(request.user),
        'CLASSIFICATION_CHOICES': Ticket.CLASSIFICATION_CHOICES,
        'subtasks': subtasks,
        'subtask_form': subtask_form,
        'subtask_update_form': subtask_update_form,
        'can_create_subtask': can_create_subtask,
    })


@login_required
@require_POST
def ticket_report_docx(request, pk):
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    try:
        report = generate_ticket_report(pk, generated_by=request.user)
    except Exception:
        logger.exception('DOCX report generation failed for ticket %s', pk)
        messages.error(request, 'ไม่สามารถสร้างรายงาน DOCX ได้ — โปรดแจ้งผู้ดูแลระบบ')
        return redirect('ticket_detail', pk=pk)
    return FileResponse(
        report.as_file(),
        as_attachment=True,
        filename=report.filename,
        content_type=report.content_type,
    )


@login_required
@require_POST
def ticket_report_pdf(request, pk):
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    try:
        report = generate_ticket_report_pdf(
            pk,
            generated_by=request.user,
            base_url=request.build_absolute_uri('/'),
        )
    except Exception:
        logger.exception('PDF report generation failed for ticket %s', pk)
        messages.error(request, 'ไม่สามารถสร้างรายงาน PDF ได้ — โปรดแจ้งผู้ดูแลระบบ')
        return redirect('ticket_detail', pk=pk)
    return FileResponse(
        report.as_file(),
        as_attachment=True,
        filename=report.filename,
        content_type=report.content_type,
    )


@login_required
def ticket_report_preview(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    return render(
        request,
        'incidents/report_preview.html',
        build_ticket_report_render_context(ticket),
    )


@login_required
def edit_log(request, log_id):
    log = get_object_or_404(TicketLog, id=log_id)
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=log.ticket_id)
    ticket_id = log.ticket.id

    # Only the original author, a SOC manager, or a superuser may rewrite
    # a timeline entry — it is part of the audit trail.
    profile = getattr(request.user, 'profile', None)
    can_edit = (
        request.user.is_superuser
        or log.author_id == request.user.pk
        or (profile is not None and profile.is_soc_manager)
    )
    if not can_edit:
        messages.error(request, 'แก้ไขได้เฉพาะผู้บันทึกเดิมหรือผู้จัดการ SOC เท่านั้น')
        return redirect('ticket_detail', pk=ticket_id)

    if request.method == 'POST':
        note = (request.POST.get('note') or '').strip()
        if not note:
            messages.error(request, 'บันทึกต้องไม่เว้นว่าง')
        else:
            log.note = note
            log.save(update_fields=['note', 'updated_at'])
            messages.success(request, 'แก้ไขบันทึกเรียบร้อยแล้ว')
            return redirect('ticket_detail', pk=ticket_id)

    return render(request, 'incidents/edit_log.html', {'log': log})


@login_required
def ticket_history(request):
    query_set = Ticket.objects.visible_to(request.user).filter(
        status__in=list(Ticket.TERMINAL_STATUSES)
    )

    search_ticket = request.GET.get('search_ticket', '').strip()
    status_filter = request.GET.get('status', '').strip()
    severity_filter = request.GET.get('severity', '').strip()
    emergency_filter = request.GET.get('emergency', '').strip()
    sort = request.GET.get('sort', 'newest').strip()
    approved_by_filter = request.GET.get('approved_by', '').strip()
    start_date = request.GET.get('start_date', '').strip()
    end_date = request.GET.get('end_date', '').strip()
    all_time = request.GET.get('all_time', '').strip()

    if not start_date and not end_date and not all_time:
        today = timezone.now()
        start_date_obj = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_day = calendar.monthrange(today.year, today.month)[1]
        end_date_obj = today.replace(day=last_day, hour=23, minute=59, second=59, microsecond=999999)
        query_set = query_set.filter(created_at__range=[start_date_obj, end_date_obj])
        start_date = start_date_obj.strftime('%Y-%m-%d')
        end_date = end_date_obj.strftime('%Y-%m-%d')
    elif start_date and end_date:
        query_set = query_set.filter(created_at__date__range=[start_date, end_date])

    if search_ticket:
        query_set = query_set.filter(ticket_id__icontains=search_ticket)

    if status_filter in (Ticket.STATUS_APPROVED, Ticket.STATUS_CLOSED_EVENT):
        query_set = query_set.filter(status=status_filter)

    if severity_filter:
        query_set = query_set.filter(severity=severity_filter)

    if emergency_filter in ('1', '0'):
        query_set = query_set.filter(is_emergency=emergency_filter == '1')
    else:
        emergency_filter = ''

    if approved_by_filter:
        try:
            query_set = query_set.filter(approved_by_id=int(approved_by_filter))
        except ValueError:
            approved_by_filter = ''

    sort_map = {
        'newest': ('-updated_at',),
        'emergency': ('-is_emergency', '-updated_at'),
    }
    if sort not in sort_map:
        sort = 'newest'
    tickets_qs = query_set.prefetch_related('logs').order_by(*sort_map[sort])

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    approver_choices = (
        User.objects.filter(approved_tickets__isnull=False)
        .distinct()
        .order_by('first_name', 'username')
    )

    return render(request, 'incidents/ticket_history.html', {
        'page_obj': page_obj,
        'tickets': page_obj,
        'search_ticket': search_ticket,
        'status_filter': status_filter,
        'severity_filter': severity_filter,
        'emergency_filter': emergency_filter,
        'sort': sort,
        'approved_by_filter': approved_by_filter,
        'approver_choices': approver_choices,
        'start_date': start_date,
        'end_date': end_date,
        'all_time': all_time,
        'severity_choices': Ticket.SEVERITY_CHOICES,
        'approved_count': Ticket.objects.visible_to(request.user).filter(status=Ticket.STATUS_APPROVED).count(),
        'event_count': Ticket.objects.visible_to(request.user).filter(status=Ticket.STATUS_CLOSED_EVENT).count(),
    })


# ── Triage views ─────────────────────────────────────────────────────── #

@login_required
def triage_list(request):
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_tier1):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่เข้าถึงหน้านี้ได้')
        return redirect('home')

    queue = TriageRecord.objects.filter(decision='', ticket__isnull=True).select_related(
        'analyst', 'claimed_by',
    ).order_by('-created_at')
    history = TriageRecord.objects.exclude(decision='').select_related(
        'analyst', 'ticket',
    ).order_by('-created_at')[:50]

    return render(request, 'incidents/triage_list.html', {
        'manual_queue': queue,
        'manual_history': history,
    })


@login_required
def create_triage(request):
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (
        profile is None
        or not profile.is_soc_staff
        or profile.tier != profile.TIER_T1
    ):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถ Triage ได้')
        return redirect('home')

    if request.method == 'POST':
        form = TriageForm(request.POST)
        if form.is_valid():
            triage = form.save(commit=False)
            triage.analyst = request.user
            triage.save()

            messages.success(request, 'เพิ่มรายการ Manual Triage เข้าคิวแล้ว')
            return redirect('triage_list')
    else:
        form = TriageForm()

    return render(request, 'incidents/triage_form.html', {'form': form})


@login_required
def claim_manual_triage(request, triage_id):
    profile = getattr(request.user, 'profile', None)
    if request.method != 'POST' or (
        not request.user.is_superuser and (profile is None or not profile.is_tier1)
    ):
        return redirect('triage_list')
    updated = TriageRecord.objects.filter(
        pk=triage_id, decision='', ticket__isnull=True, claimed_by__isnull=True,
    ).update(claimed_by=request.user, claimed_at=timezone.now())
    if not updated:
        messages.error(request, 'รายการนี้ถูกผู้อื่นรับไปแล้วหรือดำเนินการเสร็จแล้ว')
    return redirect('triage_list')


@login_required
def release_manual_triage(request, triage_id):
    profile = getattr(request.user, 'profile', None)
    if request.method != 'POST' or (
        not request.user.is_superuser and (profile is None or not profile.is_tier1)
    ):
        return redirect('triage_list')
    reason = request.POST.get('release_reason', '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการคืนรายการกลับเข้าคิว')
        return redirect('triage_list')
    releasable = TriageRecord.objects.filter(
        pk=triage_id, decision='', ticket__isnull=True, claimed_by=request.user,
    )
    if request.user.is_superuser:
        releasable = TriageRecord.objects.filter(
            pk=triage_id, decision='', ticket__isnull=True,
        )
    updated = releasable.update(
        claimed_by=None, claimed_at=None, release_reason=reason,
    )
    if not updated:
        messages.error(request, 'รายการนี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
    return redirect('triage_list')


# ── Full-text search across tickets and triage records ─────────────────── #

@login_required
def global_search(request):
    query = (request.GET.get('q') or '').strip()
    ticket_results = []
    triage_results = []

    if query:
        ticket_vector = SearchVector(
            'ticket_id', 'device_name', 'ip_address', 'destination_ip',
            'issue_description', 'ioc_details', 'mitre_phase', 'reference_id',
        )
        search_query = SearchQuery(query)
        ticket_results = (
            Ticket.objects.visible_to(request.user)
            .annotate(rank=SearchRank(ticket_vector, search_query))
            .filter(rank__gt=0)
            .order_by('-rank', '-created_at')[:50]
        )

        profile = getattr(request.user, 'profile', None)
        if request.user.is_superuser or (profile and profile.is_soc):
            triage_vector = SearchVector(
                'source_reference', 'alert_description', 'source_ip', 'notes', 't2_notes',
            )
            triage_results = (
                TriageRecord.objects
                .annotate(rank=SearchRank(triage_vector, search_query))
                .filter(rank__gt=0)
                .order_by('-rank', '-created_at')[:50]
            )

    return render(request, 'incidents/search_results.html', {
        'query': query,
        'ticket_results': ticket_results,
        'triage_results': triage_results,
    })


# ── IOC / IP lookup tool ─────────────────────────────────────────────── #

@login_required
def ip_lookup(request):
    """RDAP (WHOIS) lookup for an IP address — returns a small JSON summary
    for use by the lookup button on the ticket form/detail pages.
    """
    ip = (request.GET.get('ip') or '').strip()

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return JsonResponse({'error': 'รูปแบบ IP ไม่ถูกต้อง'}, status=400)

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return JsonResponse({'error': 'เป็น IP ภายใน (private/loopback) — ไม่มีข้อมูล WHOIS'}, status=200)

    try:
        resp = requests.get(f'https://rdap.org/ip/{ip}', timeout=5)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.warning('RDAP lookup failed for %s: %s', ip, exc)
        return JsonResponse({'error': 'ไม่สามารถติดต่อบริการ WHOIS/RDAP ได้'}, status=502)
    except ValueError:
        return JsonResponse({'error': 'ไม่พบข้อมูลสำหรับ IP นี้'}, status=404)

    entities = data.get('entities') or []
    org_name = ''
    for entity in entities:
        vcard = entity.get('vcardArray')
        if vcard and len(vcard) > 1:
            for field in vcard[1]:
                if field[0] == 'fn':
                    org_name = field[3]
                    break
        if org_name:
            break

    country = ''
    for remark_key in ('country',):
        if data.get(remark_key):
            country = data[remark_key]

    result = {
        'ip': ip,
        'network_name': data.get('name', ''),
        'cidr': f"{data.get('startAddress', '')} - {data.get('endAddress', '')}",
        'org': org_name,
        'country': country,
        'type': data.get('type', ''),
    }
    return JsonResponse(result)


# ── Subtask views (Investigation / Countermeasure) ─────────────────────── #

@login_required
def create_subtask(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_soc):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถสร้างงานย่อยได้')
        return redirect('ticket_detail', pk=pk)

    if request.method == 'POST':
        form = SubtaskForm(request.POST)
        if form.is_valid():
            subtask = form.save(commit=False)
            subtask.ticket = ticket
            subtask.created_by = request.user
            subtask.save()
            messages.success(request, f'สร้างงานย่อย "{subtask.title}" เรียบร้อยแล้ว')
        else:
            messages.error(request, 'ไม่สามารถสร้างงานย่อยได้ — กรุณาตรวจสอบข้อมูล')
    return redirect('ticket_detail', pk=pk)


@login_required
@require_POST
def create_response_request(request, pk):
    """SOC Manager spawns a response-team request (VA/PT, InfraSec, Forensics).

    The type fixes the receiving role; the assignee is resolved here:
    auto-assigned when a single active role-holder exists, taken from the
    picker when several do, and blocked when none exist.
    """
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    profile = getattr(request.user, 'profile', None)
    is_manager = request.user.is_superuser or (profile is not None and profile.is_soc_manager)
    if not is_manager:
        messages.error(request, 'เฉพาะผู้จัดการ SOC เท่านั้นที่สามารถส่งคำขอทีมตอบสนองได้')
        return redirect('ticket_detail', pk=pk)
    if ticket.status in Ticket.TERMINAL_STATUSES:
        messages.error(request, 'Ticket นี้ปิดแล้ว — ส่งคำขอทีมตอบสนองไม่ได้')
        return redirect('ticket_detail', pk=pk)

    form = ResponseRequestForm(request.POST)
    if not form.is_valid():
        messages.error(request, 'ไม่สามารถส่งคำขอได้ — กรุณาตรวจสอบข้อมูล')
        return redirect('ticket_detail', pk=pk)

    subtask_type = form.cleaned_data['subtask_type']
    chosen = form.cleaned_data.get('assigned_to')
    eligible = TicketSubtask.eligible_assignees(subtask_type)
    role_label = dict(UserProfile.ROLE_CHOICES).get(
        TicketSubtask.role_for_type(subtask_type), '')

    if not eligible.exists():
        messages.error(
            request,
            f'ยังไม่มีบัญชีผู้ใช้ในบทบาท "{role_label}" — ไม่สามารถมอบหมายคำขอนี้ได้',
        )
        return redirect('ticket_detail', pk=pk)
    if chosen is not None:
        if not eligible.filter(pk=chosen.pk).exists():
            messages.error(
                request,
                f'ผู้รับผิดชอบที่เลือกไม่ได้อยู่ในบทบาท "{role_label}"',
            )
            return redirect('ticket_detail', pk=pk)
        assignee = chosen
    elif eligible.count() == 1:
        assignee = eligible.first()
    else:
        messages.error(
            request,
            f'มีผู้รับผิดชอบในบทบาท "{role_label}" มากกว่าหนึ่งคน — กรุณาเลือกผู้รับผิดชอบ',
        )
        return redirect('ticket_detail', pk=pk)

    subtask = form.save(commit=False)
    subtask.ticket = ticket
    subtask.created_by = request.user
    subtask.assigned_to = assignee
    subtask.save()
    if not notify_response_request_created(subtask):
        messages.warning(
            request,
            'สร้างคำขอแล้ว แต่ส่งอีเมลแจ้งผู้รับผิดชอบไม่สำเร็จ',
        )
    messages.success(
        request,
        f'ส่งคำขอ "{subtask.get_subtask_type_display()}" ให้ '
        f'{assignee.get_full_name() or assignee.username} เรียบร้อยแล้ว',
    )
    return redirect('ticket_detail', pk=pk)


@login_required
def update_subtask(request, subtask_id):
    subtask = get_object_or_404(TicketSubtask, pk=subtask_id)
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=subtask.ticket_id)
    profile = getattr(request.user, 'profile', None)

    can_update = (
        request.user.is_superuser
        or (profile and profile.is_soc)
        or subtask.assigned_to_id == request.user.pk
    )
    if not can_update:
        messages.error(request, 'คุณไม่มีสิทธิ์อัปเดตงานย่อยนี้')
        return redirect('ticket_detail', pk=ticket.pk)

    if request.method == 'POST':
        was_done = subtask.is_done
        form = SubtaskUpdateForm(request.POST, instance=subtask)
        if form.is_valid():
            subtask = form.save()

            # Optional deliverable file (e.g. forensic report / scan output),
            # linked to both the subtask and its ticket so it serves through the
            # hardened download_attachment path.
            upload = request.FILES.get('result_file')
            if upload is not None:
                try:
                    validate_attachment(upload)
                    TicketAttachment.objects.create(
                        ticket=ticket, subtask=subtask, file=upload,
                        original_name=upload.name, uploaded_by=request.user,
                        description=request.POST.get('result_file_desc', '').strip(),
                    )
                except ValidationError as e:
                    messages.error(request, e.message)

            # A response request reaching DONE for the first time pings the SOC
            # managers so they can review the result and proceed to approval.
            if (
                subtask.is_response_request
                and subtask.is_done
                and not was_done
            ):
                notify_response_request_completed(subtask)

            messages.success(request, f'อัปเดตงานย่อย "{subtask.title}" เรียบร้อยแล้ว')
        else:
            messages.error(request, 'ไม่สามารถอัปเดตงานย่อยได้ — กรุณาตรวจสอบข้อมูล')
    return redirect('ticket_detail', pk=ticket.pk)


@login_required
def response_request_queue(request):
    """'My Requests' — the response-team member's work queue of requests routed
    to them. Forensic Analysts see Forensics/RCA; Red Team Managers see VA/PT and
    InfraSec. SOC/superusers get an all-team overview."""
    profile = getattr(request.user, 'profile', None)
    is_response = profile is not None and profile.is_response_team
    is_overview = request.user.is_superuser or (profile is not None and profile.is_soc)
    if not (is_response or is_overview):
        messages.error(request, 'หน้านี้สำหรับทีมตอบสนองเท่านั้น')
        return redirect('ticket_list')

    requests_qs = (
        TicketSubtask.objects
        .filter(subtask_type__in=TicketSubtask.RESPONSE_TYPES)
        .select_related('ticket', 'assigned_to', 'created_by')
        .order_by('status', '-created_at')
    )
    if is_response and not is_overview:
        requests_qs = requests_qs.filter(assigned_to=request.user)

    status_filter = request.GET.get('status', '').strip()
    if status_filter in dict(TicketSubtask.STATUS_CHOICES):
        requests_qs = requests_qs.filter(status=status_filter)
    else:
        status_filter = ''

    open_count = sum(1 for s in requests_qs if not s.is_done)

    return render(request, 'incidents/response_request_queue.html', {
        'requests': requests_qs,
        'status_filter': status_filter,
        'status_choices': TicketSubtask.STATUS_CHOICES,
        'open_count': open_count,
        'is_overview': is_overview and not is_response,
    })


# ── Attachment views ─────────────────────────────────────────────────── #

@login_required
def upload_attachment(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    if request.method == 'POST':
        form = AttachmentForm(request.POST, request.FILES)
        if form.is_valid():
            att = form.save(commit=False)
            att.ticket = ticket
            att.original_name = request.FILES['file'].name
            att.uploaded_by = request.user
            att.save()
            messages.success(request, f'อัพโหลด "{att.original_name}" เรียบร้อยแล้ว')
        else:
            messages.error(request, 'ไม่สามารถอัพโหลดไฟล์ได้ — กรุณาตรวจสอบไฟล์อีกครั้ง')
    return redirect('ticket_detail', pk=pk)


@login_required
def delete_attachment(request, attachment_id):
    att = get_object_or_404(TicketAttachment, pk=attachment_id)
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=att.ticket_id)
    profile = getattr(request.user, 'profile', None)
    # Only SOC or the original uploader may delete
    can_delete = (
        request.user.is_superuser
        or (profile and profile.is_soc)
        or att.uploaded_by == request.user
    )
    if request.method == 'POST' and can_delete:
        att.file.delete(save=False)
        att.delete()
        messages.success(request, 'ลบไฟล์เรียบร้อยแล้ว')
    return redirect('ticket_detail', pk=ticket.pk)


@login_required
def download_attachment(request, attachment_id):
    """Serve a ticket attachment to authorized users only.

    Attachments are incident evidence and must never be a security hole:

      • Authorization — the requester must be able to see the parent ticket
        (same rule as ``ticket_detail`` via ``visible_to``). This closes both
        unauthenticated access and cross-role IDOR on the raw file path.
      • Forced download — ``Content-Disposition: attachment`` plus
        ``X-Content-Type-Options: nosniff`` means an uploaded ``.html`` or
        ``.svg`` is downloaded, never rendered as same-origin script. Without
        this a user could upload ``<svg onload=…>`` and land stored XSS on
        whoever opens the file.
    """
    att = get_object_or_404(TicketAttachment, pk=attachment_id)
    # 404 (not 403) if the user can't see the parent ticket — no enumeration.
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=att.ticket_id)

    response = FileResponse(
        att.file.open('rb'),
        as_attachment=True,
        filename=att.original_name,
    )
    response['X-Content-Type-Options'] = 'nosniff'
    return response


# ── System Owner dashboard ────────────────────────────────────────────── #

@login_required
def system_owner_dashboard(request):
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (
        profile is None or not profile.is_system_owner
    ):
        return redirect('home')

    my_tickets = (
        Ticket.objects.all()
        if request.user.is_superuser
        else Ticket.objects.filter(system_owner=request.user)
    )
    terminal   = list(Ticket.TERMINAL_STATUSES)
    active_qs  = my_tickets.exclude(status__in=terminal)
    closed_qs  = my_tickets.filter(status__in=terminal)

    # Live OLA breach: active ticket already past its contain/resolve deadline
    # (vs now()). Medium/Low are notification-only (no contain deadline).
    now = timezone.now()
    stats = {
        'total':          my_tickets.count(),
        'active':         active_qs.count(),
        'closed':         closed_qs.count(),
        'ola_breaches':   active_qs.filter(ola_contain_deadline__lt=now).count(),
    }

    emergency_filter = request.GET.get('emergency', '').strip()
    sort = request.GET.get('sort', 'newest').strip()
    if emergency_filter in ('1', '0'):
        emergency_value = emergency_filter == '1'
        active_qs = active_qs.filter(is_emergency=emergency_value)
        closed_qs = closed_qs.filter(is_emergency=emergency_value)
    else:
        emergency_filter = ''
    if sort not in ('newest', 'emergency'):
        sort = 'newest'
    active_order = ('-is_emergency', '-created_at') if sort == 'emergency' else ('-created_at',)
    closed_order = ('-is_emergency', '-updated_at') if sort == 'emergency' else ('-updated_at',)

    recent_tickets = active_qs.order_by(*active_order)[:10]
    closed_tickets = closed_qs.order_by(*closed_order)[:10]

    return render(request, 'incidents/system_owner_dashboard.html', {
        'stats':          stats,
        'recent_tickets': recent_tickets,
        'closed_tickets': closed_tickets,
        'profile':        profile,
        'is_superuser_view': request.user.is_superuser,
        'emergency_filter': emergency_filter,
        'sort': sort,
    })


@login_required
def respond_escalation(request, triage_id):
    messages.info(request, 'Manual Triage no longer escalates before ticket creation.')
    return redirect('escalation_queue')
