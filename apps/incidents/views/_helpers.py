import logging
from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Exists, OuterRef, Q
from django.shortcuts import render
from django.utils import timezone

from apps.incidents import ola as ola_buckets
from ..models import (
    MAX_ATTACHMENT_BATCH_SIZE, MAX_ATTACHMENT_SIZE, ThreatGuidance, Ticket,
    TicketLog, allowed_attachment_extensions,
)
from ..staging import (
    MAX_ATTACHMENT_COUNT,
)
from ..notifications import (
    notify_containment_alert,
)
from ..policies import (
    user_can_drive as _user_can_drive,
)
from ..models import TicketCancellationRequest

logger = logging.getLogger('apps.incidents.views')


# ── Private helpers ──────────────────────────────────────────────────── #

def _active_threat_guidance():
    """Return the client-side containment guidance keyed by threat category."""
    return {
        guidance.detailed_issue: {
            'action_required': guidance.action_required,
            'action_precautions': guidance.action_precautions,
        }
        for guidance in ThreatGuidance.objects.filter(is_active=True)
    }


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
        edge = (ticket.status, next_status)
        if (edge in Ticket.STEP_BACK_EDGES or edge in Ticket.MONITORING_EDGES
                or edge in Ticket.MANAGER_RETURN_EDGES):
            continue  # step-back / monitoring / manager return have their own controls
        if not ticket.can_transition_to(next_status):
            continue  # blocked by classification or manager-routing gate
        perm = Ticket.TRANSITION_PERMISSIONS.get((ticket.status, next_status))
        if perm == 'ASSIGNED_ADMIN':
            continue  # admin uses the containment form, not this dropdown
        if _user_can_drive(ticket, user, perm):
            result.append((next_status, status_map.get(next_status, next_status)))

    return result


def _case_switch_qs(triage_id=None, alert_id=None, evidence_token=None):
    """Query string carrying the case's origin across the single ↔ multi switch.

    The two creation forms are one menu entry with a mode toggle, so switching
    must not lose the manual-triage record or Wazuh alert the analyst started
    from — otherwise the new case would come back unlinked. The evidence token
    rides along for the same reason: the toggle is a full page load, so without
    it any staged evidence would be stranded.
    """
    params = {k: v for k, v in (
        ('triage_id', triage_id), ('wazuh_alert', alert_id),
        ('evidence_token', evidence_token),
    ) if v}
    return urlencode(params)


def _attachment_limits():
    """Upload rules handed to the evidence picker's client-side pre-check.

    Derived from the model constants rather than restated in the template, so
    the `accept` list and the in-browser checks cannot drift from what
    validate_attachment actually enforces. The template hands this dict to the
    picker with the |json_script filter (an inert application/json data block).
    """
    extensions = allowed_attachment_extensions()
    return {
        'allowed_extensions': extensions,
        'accept': ','.join('.' + ext for ext in extensions),
        'max_file_size': MAX_ATTACHMENT_SIZE,
        'max_batch_size': MAX_ATTACHMENT_BATCH_SIZE,
        'max_count': MAX_ATTACHMENT_COUNT,
    }


def _transition_actions(ticket, user):
    """Return only legal, permitted forward actions for the current user."""
    if (
        ticket.project_incident_id
        and ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE
        and ticket.project_incident.emergency_decided_at is None
    ):
        return []
    labels = {
        Ticket.STATUS_CLOSED_EVENT: (
            'Confirm Event -> Close'
            if ticket.status == Ticket.STATUS_PENDING_MGR_EVENT_REVIEW
            else 'Mark as Event -> Close'
        ),
        Ticket.STATUS_PENDING_MGR_EVENT_REVIEW: 'Mark as Event -> SOC Manager verification',
        Ticket.STATUS_PENDING_MGR_TRIAGE: (
            'Mark as Incident -> SOC Manager review'
            if ticket.status == Ticket.STATUS_ESCALATED_T2
            else 'Route to SOC Manager review'
        ),
        # Records what the owner reported; it does not assert the fix is good.
        # "Confirm" was what invited Tier 1 to adjudicate a call that belongs
        # to Tier 2.
        Ticket.STATUS_OWNER_REMEDIATED: 'บันทึกผลจากเจ้าของระบบ (Record owner report)',
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
        edge = (ticket.status, next_status)
        if (edge in Ticket.STEP_BACK_EDGES or edge in Ticket.MONITORING_EDGES
                or edge in Ticket.MANAGER_RETURN_EDGES):
            continue  # step-back / monitoring / manager return have their own controls
        can_transition = ticket.can_transition_to(next_status)
        # Tier 2's decision buttons also set the classification (and, for the
        # Incident decision, the lane — chosen on the same form, so assume one).
        # Ask the model whether each edge is valid with that proposal.
        if ticket.status == Ticket.STATUS_ESCALATED_T2:
            proposed = {
                Ticket.STATUS_CLOSED_EVENT: Ticket.CLASSIFICATION_EVENT,
                # Same Event decision, but for a ticket Tier 2 is downgrading
                # from Incident the model routes it via the manager instead.
                Ticket.STATUS_PENDING_MGR_EVENT_REVIEW: Ticket.CLASSIFICATION_EVENT,
                Ticket.STATUS_PENDING_MGR_TRIAGE: Ticket.CLASSIFICATION_INCIDENT,
            }.get(next_status)
            if proposed:
                original = ticket.classification, ticket.t1_route
                ticket.classification = proposed
                if next_status == Ticket.STATUS_PENDING_MGR_TRIAGE:
                    ticket.t1_route = Ticket.T1_ROUTE_OWNER  # lane comes from the form
                can_transition = ticket.can_transition_to(next_status)
                ticket.classification, ticket.t1_route = original
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
        # From AWAITING_OWNER this single action IS the relay, so name what
        # Tier 1 is asserting. The legacy OWNER_REMEDIATED hop keeps the plain
        # wording — by then the report was already recorded.
        if (next_status == Ticket.STATUS_PENDING_T2_REVIEW
                and ticket.status == Ticket.STATUS_AWAITING_OWNER):
            label = 'เจ้าของแจ้งแก้ไขแล้ว → ส่ง Tier 2 ตรวจสอบ'
        if next_status == Ticket.STATUS_AWAITING_OWNER:
            # No OWNER_REMEDIATED branch: that edge is gone. Sending a case
            # back to the owner is Tier 2's call, made at PENDING_T2_REVIEW.
            if ticket.status == Ticket.STATUS_PENDING_T2_REVIEW:
                label = 'ตีกลับ → ส่งคืนเจ้าของระบบ'
            else:
                label = 'ส่งให้เจ้าของระบบ (โดยตรง)'
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


# ── Ticket views ─────────────────────────────────────────────────────── #

def _alert_bundle_ids(request):
    """Return distinct selected Wazuh alert ids, preserving form order."""
    values = request.POST.getlist('alert_bundle') or request.GET.getlist('alert_bundle')
    ids = []
    for value in values:
        try:
            alert_id = int(value)
        except (TypeError, ValueError):
            continue
        if alert_id > 0 and alert_id not in ids:
            ids.append(alert_id)
    return ids


def _render_ticket_list(request, visible, *, page_title, heading, description,
                        is_manager_queue=False):
    """Render a filtered, non-terminal ticket list with shared list controls."""
    tickets_qs = visible.exclude(
        status__in=list(Ticket.TERMINAL_STATUSES)
    ).select_related('assigned_admin', 'created_by', 'project_incident')

    # A return from Tier 2 lands back in the same AWAITING_CONTAINMENT state as
    # a first assignment. Preserve that intentionally simple workflow state,
    # but annotate the System Admin's queue from its audit trail so rework is
    # impossible to mistake for brand-new work. The annotation avoids one log
    # query per queue row and also works for tickets returned before this UI
    # signal existed.
    profile = getattr(request.user, 'profile', None)
    is_system_admin_viewer = (
        not request.user.is_superuser
        and profile is not None
        and profile.is_system_admin
    )
    if is_system_admin_viewer:
        tickets_qs = tickets_qs.annotate(
            is_returned_to_admin=Exists(
                TicketLog.objects.filter(
                    ticket_id=OuterRef('pk'),
                    status_at_time=Ticket.STATUS_CONTAINMENT_REPORTED,
                )
            )
        )

    search = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '').strip()
    severity_filter = request.GET.get('severity', '').strip()
    classification_filter = request.GET.get('classification', '').strip()
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

    if classification_filter in dict(Ticket.CLASSIFICATION_CHOICES):
        tickets_qs = tickets_qs.filter(classification=classification_filter)
    else:
        classification_filter = ''

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
    if is_system_admin_viewer:
        # The OLA deadline remains the primary work-ordering rule. Within the
        # same urgency band, returned work comes first because it already had a
        # failed verification pass and needs a concrete correction.
        sort_map['ola'] = (
            'ola_contain_deadline', '-is_returned_to_admin', '-status_changed_at',
        )
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
        'pending_cancellations': (
            TicketCancellationRequest.objects.filter(status='PENDING', ticket__in=Ticket.objects.visible_to(request.user))
            .select_related('ticket', 'requested_by').order_by('requested_at')
            if is_manager_queue else []
        ),
        'show_returned_to_admin_indicator': is_system_admin_viewer,
        'tickets': page_obj,
        'page_obj': page_obj,
        'result_count': paginator.count,
        'ola_breach_count': ola_breach_count,
        'search': search,
        'status_filter': status_filter,
        'severity_filter': severity_filter,
        'classification_filter': classification_filter,
        'emergency_filter': emergency_filter,
        'ola_filter': ola_filter,
        'sort': sort,
        'active_status_choices': active_status_choices,
        'severity_choices': Ticket.SEVERITY_CHOICES,
        'classification_choices': Ticket.CLASSIFICATION_CHOICES,
        'ola_bucket_choices': ola_buckets.OLA_BUCKETS,
    })
