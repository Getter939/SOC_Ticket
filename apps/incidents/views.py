import calendar
import ipaddress
import json
import logging
from urllib.parse import urlencode

import requests
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Exists, F, OuterRef, Q
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.accounts.models import UserProfile
from apps.incidents import history
from apps.incidents import ola as ola_buckets
from apps.wazuh_ingest.models import WazuhAlert
from .forms import (
    AdminAssignmentForm, AttachmentForm, ProjectIncidentForm,
    ProjectIncidentTargetFormSet, ResponseRequestForm, SubtaskForm,
    SubtaskUpdateForm, TicketEditForm, TicketForm, TicketReviewForm, TriageForm,
)
from .models import (
    MAX_ATTACHMENT_BATCH_SIZE, MAX_ATTACHMENT_SIZE, ProjectIncident,
    ProjectIncidentAttachment, ThreatGuidance, Ticket,
    TicketAttachment, TicketLog, TicketLogRevision,
    TicketSubtask, TriageRecord,
    allowed_attachment_extensions, bundle_suffix_for_index,
    validate_attachment,
)
from .staging import (
    MAX_ATTACHMENT_COUNT, discard_staged, restore_staged,
    staged_for, stage_uploads,
)
from .report_content import GUIDANCE_COORDINATION_NOTE
from .notifications import (
    notify_containment_alert,
)
from .reports import (
    build_ticket_report_render_context,
    generate_ticket_report,
    generate_ticket_report_pdf,
)
from .policies import (
    can_access_ticket_report as _can_access_ticket_report,
    can_create_ticket_from_triage as _can_create_ticket_from_triage,
    can_create_ticket_from_wazuh as _can_create_ticket_from_wazuh,
    can_delete_project_attachment as _can_delete_project_attachment,
    can_delete_ticket_attachment as _can_delete_ticket_attachment,
    can_edit_ticket as _can_edit_ticket,
    can_restore_ticket_attachment as _can_restore_ticket_attachment,
    can_upload_project_attachment as _can_upload_project_attachment,
    can_upload_subtask_result as _can_upload_subtask_result,
    can_upload_ticket_attachment as _can_upload_ticket_attachment,
    holds_ticket_court as _holds_ticket_court,
    is_soc as _is_soc,
    is_soc_manager as _is_soc_manager,
    user_can_drive as _user_can_drive,
)
from .selectors import get_ticket_detail_read_model
from .case_creation import (
    create_project_incident_from_forms,
    create_ticket_from_form,
    load_alert_bundle,
)
from .project_workflow import (
    add_shared_attachments,
    delete_shared_attachment,
    forward_project_review,
    reassess_project_emergency,
    restore_shared_attachment,
)
from .ticket_evidence import (
    add_ticket_attachments,
    delete_ticket_attachment,
    restore_ticket_attachment,
)
from .subtask_creation import (
    create_legacy_subtask,
    create_response_request as create_response_request_operation,
)
from .ticket_updates import save_subtask_update, save_ticket_edit
from .ticket_workflow import (
    assign_admin_or_owner_route,
    claim_tier2_ticket,
    complete_t2_review,
    manager_forward,
    reassess_emergency,
    reclassify_as_event,
    step_back,
    submit_containment,
    transition_ticket,
)

logger = logging.getLogger(__name__)


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
        Ticket.STATUS_T1_REVIEW: 'Mark as Incident -> Return to Tier 1',
        Ticket.STATUS_PENDING_MGR_TRIAGE: 'Route to SOC Manager review',
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
        can_transition = ticket.can_transition_to(next_status)
        # Tier 2's two decision buttons also set the classification. Ask the
        # model whether each edge is valid with that proposed classification.
        if ticket.status == Ticket.STATUS_ESCALATED_T2:
            proposed = {
                Ticket.STATUS_CLOSED_EVENT: Ticket.CLASSIFICATION_EVENT,
                # Same Event decision, but for a ticket Tier 2 is downgrading
                # from Incident the model routes it via the manager instead.
                Ticket.STATUS_PENDING_MGR_EVENT_REVIEW: Ticket.CLASSIFICATION_EVENT,
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


@login_required
def ticket_list(request):
    visible = Ticket.objects.visible_to(request.user)
    return _render_ticket_list(
        request,
        visible,
        page_title='Ticket ที่กำลังดำเนินการ',
        heading='Ticket ที่กำลังดำเนินการ',
        description='ติดตามเคสเปิดทั้งหมดที่อยู่ในขอบเขตสิทธิ์ของคุณ',
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
        page_title='รายการรอตรวจโดยผู้จัดการ SOC',
        heading='รายการรอตรวจโดยผู้จัดการ SOC',
        description='เคสที่รอการเลือกเส้นทางหรือการอนุมัติสถานะฉุกเฉิน',
        is_manager_queue=True,
    )


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
        'show_returned_to_admin_indicator': is_system_admin_viewer,
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
    # TEMP: Tier 2 allowed to open cases too (revert to is_tier1-only later).
    if not request.user.is_superuser and (
        profile is None or not (profile.is_tier1 or profile.is_tier2)
    ):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถเปิดเคสใหม่ได้')
        return redirect('ticket_list')

    alert_bundle_ids = _alert_bundle_ids(request)
    alert_bundle = []
    if alert_bundle_ids:
        try:
            alert_bundle = load_alert_bundle(alert_bundle_ids, request.user)
        except ValidationError as exc:
            messages.error(request, exc.message)
            return redirect('triage_queue')

    # Pre-fill from triage if coming from a TP triage decision
    triage = None
    triage_id = request.GET.get('triage_id') or request.POST.get('triage_id')
    # Seeded from the request so the single ↔ multi switch link keeps the alert
    # on EVERY render, including a POST that comes back with validation errors.
    # The GET branch below refines it to the bundle's primary alert; leaving it
    # None here would strand the analyst's alert on the first failed submit.
    alert_pk = request.POST.get('wazuh_alert') or request.GET.get('wazuh_alert')
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
        if alert_bundle_ids:
            # Keep the existing primary-alert selector inside the submitted
            # bundle rather than exposing every alert claimed by the analyst.
            form.fields['wazuh_alert'].queryset = WazuhAlert.objects.filter(
                pk__in=alert_bundle_ids
            ).order_by('timestamp', 'pk')
        # Stage evidence BEFORE validating. A browser cannot repopulate a file
        # input after a page load, so anything not persisted here is lost the
        # moment the form comes back with an error.
        evidence_token, staged_errors = stage_uploads(request)
        for staged_error in staged_errors:
            form.add_error(None, staged_error)
        if form.is_valid() and alert_bundle_ids:
            if form.cleaned_data['classification'] != Ticket.CLASSIFICATION_INCIDENT:
                form.add_error(
                    'classification',
                    'Alert Bundle ต้องเปิดเป็น Incident เดียว ไม่สามารถจัดเป็น Event ได้',
                )
        if form.is_valid():
            try:
                result = create_ticket_from_form(
                    form=form,
                    actor=request.user,
                    triage=triage,
                    alert_bundle_ids=alert_bundle_ids,
                    evidence_token=evidence_token,
                )
            except ValidationError as exc:
                form.add_error(None, exc.message)
            else:
                for warning in result.warnings:
                    messages.warning(request, warning)
                # The browser only gets here on a genuine save, so this is the
                # one place it is safe to drop the localStorage draft. Clearing
                # it on the form's submit event instead would wipe the draft
                # even when the POST is rejected (expired session → login
                # redirect, CSRF 403), losing everything the analyst typed. The
                # key mirrors DRAFT_KEY in ticket_form.html; ticket_detail pops
                # this flag and emits the removeItem.
                draft_key = 'ticket_form_draft'
                if triage_id:
                    draft_key += f'_triage_{triage_id}'
                request.session['clear_ticket_draft_key'] = draft_key
                return redirect('ticket_detail', pk=result.ticket.pk)
    else:
        initial = {}
        if triage:
            initial['device_name'] = triage.source_ip
            initial['issue_description'] = triage.alert_description
            # Source channel carries straight over — issue_type and triage
            # source now share the SOURCE_CHOICES vocabulary, so it maps 1:1.
            initial['issue_type'] = triage.source
        primary_alert = (
            min(alert_bundle, key=lambda alert: (alert.timestamp, alert.pk))
            if alert_bundle else None
        )
        alert_pk = primary_alert.pk if primary_alert else request.GET.get('wazuh_alert')
        if alert_pk:
            initial['wazuh_alert'] = alert_pk
            # The alert's own detection time is authoritative for
            # 'วันและเวลาที่ตรวจพบ' — the analyst should never retype it. Filled
            # server-side so the field is right on first paint rather than only
            # after a change event; the template locks it while an alert is
            # selected, with an explicit unlock for the rare manual override.
            prefill_alert = (
                WazuhAlert.objects.filter(pk=alert_pk).first()
                if str(alert_pk).isdigit() else None
            )
            if prefill_alert:
                initial['incident_datetime'] = timezone.localtime(
                    prefill_alert.timestamp).strftime('%Y-%m-%dT%H:%M')
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
        if alert_bundle_ids:
            form.fields['wazuh_alert'].queryset = WazuhAlert.objects.filter(
                pk__in=alert_bundle_ids
            ).order_by('timestamp', 'pk')
        # Carried by the single ↔ multi toggle so switching mode does not
        # strand evidence the analyst already uploaded.
        evidence_token = request.GET.get('evidence_token', '')

    # Standard containment guidance per threat category (admin-editable) for
    # the "แทรกแนวทางมาตรฐาน" button — inserted client-side, never auto-applied.
    threat_guidance = _active_threat_guidance()

    return render(request, 'incidents/ticket_form.html', {
        'form': form,
        'triage_id': triage_id or '',
        'case_mode': 'single',
        'case_switch_qs': _case_switch_qs(
            triage_id, alert_pk, evidence_token),
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        'threat_guidance': threat_guidance,
        'guidance_note': GUIDANCE_COORDINATION_NOTE,
        'alert_bundle': alert_bundle,
        'evidence_token': evidence_token,
        'staged_files': staged_for(request.user, evidence_token),
        'attachment_limits': _attachment_limits(),
    })


@login_required
def create_project_incident(request):
    """Fan out one multi-system incident into linked member tickets.

    Tier 1 fills the shared incident facts once and lists the affected systems;
    each system becomes a Ticket routed to its own admin (AWAITING_CONTAINMENT),
    all pointing at one ProjectIncident so they stay grouped and trackable.
    """
    profile = getattr(request.user, 'profile', None)
    # TEMP: Tier 2 allowed to open Project Incidents too (revert to is_tier1-only later).
    if not request.user.is_superuser and (
        profile is None or not (profile.is_tier1 or profile.is_tier2)
    ):
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
        # Staged before validation — see create_ticket for why.
        evidence_token, staged_errors = stage_uploads(request)
        for staged_error in staged_errors:
            shared_form.add_error(None, staged_error)
        if shared_form.is_valid() and target_formset.is_valid():
            try:
                result = create_project_incident_from_forms(
                    shared_form=shared_form,
                    target_formset=target_formset,
                    actor=request.user,
                    source_alert=source_alert,
                    source_triage=source_triage,
                    evidence_token=evidence_token,
                )
            except ValidationError as exc:
                shared_form.add_error(None, exc.message)
            else:
                for warning in result.warnings:
                    messages.warning(request, warning)
                messages.success(
                    request,
                    f'สร้าง Project Incident {result.project.project_code} เรียบร้อย — '
                    f'{len(result.tickets)} Ticket ตามระบบที่ได้รับผลกระทบ',
                )
                return redirect('project_incident_detail', pk=result.project.pk)
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
        evidence_token = request.GET.get('evidence_token', '')

    return render(request, 'incidents/project_incident_form.html', {
        'form': shared_form,
        'target_formset': target_formset,
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        'source_alert': source_alert,
        'source_triage': source_triage,
        'case_mode': 'multi',
        'case_switch_qs': _case_switch_qs(
            source_triage.pk if source_triage else None,
            source_alert.pk if source_alert else None,
            evidence_token,
        ),
        'threat_guidance': _active_threat_guidance(),
        'guidance_note': GUIDANCE_COORDINATION_NOTE,
        'evidence_token': evidence_token,
        'staged_files': staged_for(request.user, evidence_token),
        'attachment_limits': _attachment_limits(),
    })


@login_required
def project_incident_detail(request, pk):
    """Overview of a case bundle: the shared incident and its member tickets."""
    project = get_object_or_404(ProjectIncident, pk=pk)
    profile = getattr(request.user, 'profile', None)
    can_manage_project = request.user.is_superuser or (
        profile is not None and profile.is_soc_manager
    )

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'project_mgr_forward':
            assessment = request.POST.get('emergency_assessment', '')
            note = request.POST.get('decision_note', '').strip()
            if not can_manage_project:
                messages.error(request, 'เฉพาะผู้จัดการ SOC เท่านั้นที่ดำเนินการ Project Review ได้')
            elif project.emergency_decided_at is not None:
                messages.error(request, 'Project Incident นี้ผ่าน Project Review แล้ว')
            elif assessment not in ('normal', 'emergency') or not note:
                messages.error(request, 'กรุณาเลือก Normal หรือ Emergency และกรอกบันทึกการตรวจ')
            else:
                want_emergency = assessment == 'emergency'
                try:
                    result = forward_project_review(
                        project=project,
                        actor=request.user,
                        want_emergency=want_emergency,
                        note=note,
                    )
                except ValidationError as exc:
                    messages.error(request, exc.message)
                else:
                    for warning in result.warnings:
                        messages.warning(request, warning)
                    messages.success(
                        request,
                        'Project Review เสร็จสิ้นและส่งต่อ Member Ticket ที่รอทั้งหมดแล้ว',
                    )
        elif action == 'project_reassess_emergency':
            value = request.POST.get('emergency_value', '') in ('1', 'true', 'True', 'on')
            reason = request.POST.get('emergency_reason', '').strip()
            if not can_manage_project:
                messages.error(request, 'เฉพาะผู้จัดการ SOC เท่านั้นที่ประเมิน Emergency ใหม่ได้')
            elif project.emergency_decided_at is None:
                messages.error(request, 'Project Incident ต้องผ่าน Project Review ก่อน')
            elif not reason:
                messages.error(request, 'กรุณาระบุเหตุผลในการประเมิน Emergency ใหม่')
            else:
                reassess_project_emergency(
                    project=project,
                    actor=request.user,
                    value=value,
                    reason=reason,
                )
                messages.success(request, 'อัปเดต Emergency สำหรับ Member Ticket ที่ยังดำเนินการอยู่แล้ว')
        return redirect('project_incident_detail', pk=project.pk)

    members = (
        project.member_tickets.visible_to(request.user)
        .select_related('assigned_admin', 'system_owner', 'project_incident')
        .order_by('bundle_suffix', 'created_at')
    )
    # A user who can see none of the members has no business on the bundle page.
    if not members and not request.user.is_superuser:
        raise Http404('ไม่พบ Project Incident')
    # Shared incident facts (NCSA severity, log source, MITRE) are copied to
    # every member at creation, so the page reads them off one "lead" member.
    # Deliberately taken from the UNSCOPED set: `members` above is filtered by
    # what the viewer may see, so using it made a System Admin who can see only
    # member C read C's values while SOC read A's — the same bundle reporting
    # different severity to different people.
    lead = project.members.first()
    # Soonest contain deadline still running, so the page that exists to
    # coordinate members shows the group's time pressure without opening each
    # ticket. Members deliberately keep independent OLA clocks.
    next_ola_member = (
        project.member_tickets
        .exclude(status__in=Ticket.TERMINAL_STATUSES)
        .filter(classification=Ticket.CLASSIFICATION_INCIDENT)
        .filter(ola_contain_deadline__isnull=False)
        .order_by('ola_contain_deadline')
        .first()
    )
    return render(request, 'incidents/project_incident_detail.html', {
        'project': project,
        'members': members,
        'lead': lead,
        'next_ola_member': next_ola_member,
        'source_triage': project.source_triages.first(),
        'project_logs': project.logs.select_related('author'),
        'can_manage_project': can_manage_project,
        'can_upload_project_attachment': _can_upload_project_attachment(
            project, request.user),
        'can_restore_project_attachment': _can_restore_ticket_attachment(
            request.user),
        'deleted_attachments': (
            project.attachments.model.all_objects
            .filter(project=project, deleted_at__isnull=False)
            .select_related('deleted_by')
        ),
        'pending_member_count': project.member_tickets.filter(
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
        ).count(),
    })


@login_required
def download_project_attachment(request, attachment_id):
    """Serve shared Project Incident evidence to any authorized member viewer.

    Same hardening as download_attachment: forced download plus nosniff so an
    uploaded .html/.svg can never execute same-origin, and 404 rather than 403
    so the id space isn't enumerable. The default manager is active-only, so a
    soft-deleted file 404s here exactly like a removed ticket attachment.
    """
    attachment = get_object_or_404(ProjectIncidentAttachment, pk=attachment_id)
    if not attachment.project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบไฟล์แนบ')
    response = FileResponse(
        attachment.file.open('rb'),
        as_attachment=True,
        filename=attachment.original_name,
    )
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@login_required
def upload_project_attachment(request, pk):
    """Add shared evidence to a bundle after it was opened.

    Mirrors upload_attachment: same AttachmentForm, so the batch multi-file
    handling and per-file validation are literally the same code path.
    """
    project = get_object_or_404(ProjectIncident, pk=pk)
    if not project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบ Project Incident')

    if not _can_upload_project_attachment(project, request.user):
        messages.error(
            request,
            'คุณไม่มีสิทธิ์แนบไฟล์ในกลุ่มนี้ หรือทุกระบบถูกปิดแล้ว',
        )
        return redirect('project_incident_detail', pk=project.pk)

    if request.method == 'POST':
        form = AttachmentForm(request.POST, request.FILES)
        if form.is_valid():
            description = form.cleaned_data.get('description', '')
            uploads = form.cleaned_data['file']
            result = add_shared_attachments(
                project=project,
                actor=request.user,
                uploads=uploads,
                description=description,
            )
            if len(result.attachments) == 1:
                messages.success(
                    request,
                    f'อัพโหลด "{result.attachments[0].original_name}" เรียบร้อยแล้ว',
                )
            else:
                messages.success(request, f'อัพโหลด {len(result.attachments)} ไฟล์เรียบร้อยแล้ว')
        else:
            detail = '; '.join(
                msg for errors in form.errors.values() for msg in errors
            )
            messages.error(
                request,
                f'ไม่สามารถอัพโหลดไฟล์ได้ — {detail}' if detail
                else 'ไม่สามารถอัพโหลดไฟล์ได้ — กรุณาตรวจสอบไฟล์อีกครั้ง',
            )
    return redirect('project_incident_detail', pk=project.pk)


@login_required
@require_POST
def delete_project_attachment(request, attachment_id):
    """Soft-delete shared bundle evidence, with a required reason."""
    att = get_object_or_404(ProjectIncidentAttachment, pk=attachment_id)
    project = att.project
    if not project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบไฟล์แนบ')

    if not _can_delete_project_attachment(project, att, request.user):
        # Logged, not written to the project timeline: anyone who can see the
        # bundle could otherwise flood it by probing. Same call as the ticket
        # attachment path.
        logger.warning(
            'Refused project attachment delete: user=%s attachment=%s project=%s',
            request.user.pk, att.pk, project.project_code,
        )
        messages.error(
            request,
            'คุณไม่มีสิทธิ์ลบไฟล์นี้ หรือทุกระบบในกลุ่มถูกปิดแล้ว — '
            'หลักฐานของเคสที่ปิดแล้วจะถูกล็อกไว้',
        )
        return redirect('project_incident_detail', pk=project.pk)

    reason = (request.POST.get('reason') or '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการลบไฟล์')
        return redirect('project_incident_detail', pk=project.pk)

    delete_shared_attachment(attachment=att, actor=request.user, reason=reason)
    messages.success(request, 'ลบไฟล์เรียบร้อยแล้ว — ผู้จัดการ SOC สามารถกู้คืนได้')
    return redirect('project_incident_detail', pk=project.pk)


@login_required
@require_POST
def restore_project_attachment(request, attachment_id):
    """Bring back group evidence removed by mistake. SOC Manager only.

    Not gated on all_closed, unlike deletion: refusing removal on a finished
    bundle protects the evidence set, but refusing recovery would only make a
    mistake permanent. Same reasoning as restore_attachment.
    """
    att = get_object_or_404(
        ProjectIncidentAttachment.all_objects,
        pk=attachment_id, deleted_at__isnull=False,
    )
    project = att.project
    if not project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบไฟล์แนบ')

    if not _can_restore_ticket_attachment(request.user):
        logger.warning(
            'Refused project attachment restore: user=%s attachment=%s project=%s',
            request.user.pk, att.pk, project.project_code,
        )
        messages.error(request, 'กู้คืนไฟล์ได้เฉพาะผู้จัดการ SOC เท่านั้น')
        return redirect('project_incident_detail', pk=project.pk)

    restore_shared_attachment(attachment=att, actor=request.user)
    messages.success(request, 'กู้คืนไฟล์เรียบร้อยแล้ว')
    return redirect('project_incident_detail', pk=project.pk)


@login_required
def ticket_detail(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    profile = getattr(request.user, 'profile', None)
    is_terminal = ticket.status in Ticket.TERMINAL_STATUSES
    can_upload_attachment = _can_upload_ticket_attachment(ticket, request.user)

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
    # The Event decision leads to one of two targets — a straight close when
    # Tier 1 had already called it an Event, or SOC Manager verification when
    # Tier 2 is downgrading an Incident. Exactly one is ever offered.
    can_t2_review = (
        ticket.status == Ticket.STATUS_ESCALATED_T2
        and Ticket.STATUS_T1_REVIEW in transition_codes
        and bool(transition_codes & {
            Ticket.STATUS_CLOSED_EVENT, Ticket.STATUS_PENDING_MGR_EVENT_REVIEW,
        })
    )
    can_assign_admin = (
        ticket.status == Ticket.STATUS_T1_REVIEW
        and Ticket.STATUS_PENDING_MGR_TRIAGE in transition_codes
    )
    # SOC Manager pre-containment review: flag Emergency + forward to the lane
    # Tier 1 already chose (t1_route). The manager cannot change the lane.
    # A bundle member is forwardable individually only AFTER its Project Review
    # has recorded the group verdict — before that the group forwards them all
    # at once. Mirrors the model gate in transition_to (step 5) exactly, so the
    # button is never offered for a move the model would refuse. Without the
    # post-review half, a member stepped back out of its lane would strand at
    # PENDING_MGR_TRIAGE with no forward path from either page.
    can_mgr_forward = (
        not is_terminal
        and ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE
        and (
            not ticket.project_incident_id
            or ticket.project_incident.emergency_decided_at is not None
        )
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

    # Tier 2 claim banner: visible whenever the ticket sits in the Tier 2 queue
    # and the viewer is Tier 2 (or superuser) — regardless of which action card
    # renders below it. Other roles never see it: they can't claim, and
    # t2_claim_blocks never applies to them either.
    is_t2_viewer = (
        request.user.is_superuser
        or (profile is not None and profile.is_tier2)
    )
    t2_claim_visible = ticket.status in Ticket.TIER2_QUEUE_STATUSES and is_t2_viewer
    if not t2_claim_visible:
        t2_claim_state = None
    elif ticket.t2_claimed_by_id is None:
        t2_claim_state = 'unclaimed'
    elif ticket.t2_claimed_by_id == request.user.pk:
        t2_claim_state = 'mine'
    else:
        t2_claim_state = 'other'

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'reassess_emergency':
            value = request.POST.get('emergency_value', '') in ('1', 'true', 'True', 'on')
            reason = request.POST.get('emergency_reason', '').strip()
            try:
                reassess_emergency(ticket=ticket, actor=request.user, value=value, reason=reason)
                state = 'ตั้งเป็น Emergency' if value else 'ยกเลิก Emergency'
                messages.success(request, f'ประเมินสถานะฉุกเฉินใหม่ ({state}) เรียบร้อยแล้ว')
            except ValidationError as e:
                messages.error(request, e.message)

        elif action == 'step_back':
            try:
                result = step_back(
                    ticket=ticket,
                    actor=request.user,
                    reason=request.POST.get('step_back_reason', ''),
                )
                messages.success(
                    request,
                    'ย้อนขั้นตอนเรียบร้อยแล้ว — '
                    f'สถานะปัจจุบัน: {dict(Ticket.STATUS_CHOICES).get(result.target_status, result.target_status)}',
                )
            except ValidationError as e:
                messages.error(request, e.message)

        elif action == 't2_review':
            next_status = request.POST.get('status', '')
            review_form = TicketReviewForm(request.POST, instance=ticket)
            expected_classification = {
                Ticket.STATUS_CLOSED_EVENT: Ticket.CLASSIFICATION_EVENT,
                Ticket.STATUS_PENDING_MGR_EVENT_REVIEW: Ticket.CLASSIFICATION_EVENT,
                Ticket.STATUS_T1_REVIEW: Ticket.CLASSIFICATION_INCIDENT,
            }.get(next_status)
            if not can_t2_review or next_status not in transition_codes:
                messages.error(request, 'This Tier 2 action is not permitted for the ticket.')
            elif review_form.is_valid() and review_form.cleaned_data['classification'] != expected_classification:
                messages.error(request, 'Classification must match the selected Tier 2 decision.')
            elif review_form.is_valid():
                try:
                    result = complete_t2_review(
                        ticket=ticket,
                        actor=request.user,
                        review_form=review_form,
                        next_status=next_status,
                        decision_note=request.POST.get('decision_note', '').strip(),
                        fallback_label=dict(
                            (item['status'], item['label']) for item in transition_actions
                        )[next_status],
                    )
                    for warning in result.warnings:
                        messages.warning(request, warning)
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
                    assign_admin_or_owner_route(
                        ticket=ticket,
                        actor=request.user,
                        route=route,
                        note=note,
                    )
                except ValidationError as e:
                    messages.error(request, e.message)
            elif assignment_form.is_valid():
                try:
                    assign_admin_or_owner_route(
                        ticket=ticket,
                        actor=request.user,
                        route=route,
                        note=note,
                        assignment_form=assignment_form,
                    )
                except ValidationError as e:
                    messages.error(request, e.message)
            else:
                messages.error(request, 'กรุณาเลือกผู้ดูแลระบบที่รับผิดชอบ')

        elif action == 'mgr_forward':
            # SOC Manager review: make the REQUIRED Normal/Emergency assessment,
            # then forward to the lane Tier 1 fixed (the manager cannot divert
            # the lane). The assessment is an explicit two-option choice, not a
            # checkbox — "Normal" is a positive decision, recorded as such.
            note = request.POST.get('decision_note', '').strip()
            assessment = request.POST.get('emergency_assessment', '')
            if not can_mgr_forward:
                messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
            elif not note:
                messages.error(request, 'กรุณากรอกบันทึกการตรวจ')
            elif assessment not in ('normal', 'emergency'):
                messages.error(request, 'กรุณาประเมินสถานะฉุกเฉิน (Normal หรือ Emergency)')
            else:
                want_emergency = assessment == 'emergency'
                try:
                    result = manager_forward(
                        ticket=ticket,
                        actor=request.user,
                        want_emergency=want_emergency,
                        target_status=mgr_forward_target,
                        note=note,
                    )
                    for warning in result.warnings:
                        messages.warning(request, warning)
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
                    result = reclassify_as_event(ticket=ticket, actor=request.user, note=note)
                    for warning in result.warnings:
                        messages.warning(request, warning)
                except ValidationError as e:
                    messages.error(request, e.message)

        elif action == 'containment':
            if not can_submit_containment:
                messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
            else:
                report = request.POST.get('containment_report', '').strip()
                remediation = request.POST.get('remediation_summary', '').strip()
                note = request.POST.get('note', '').strip()

                if not report:
                    messages.error(request, 'กรุณากรอกรายงานการควบคุม')
                else:
                    try:
                        result = submit_containment(
                            ticket=ticket,
                            actor=request.user,
                            report=report,
                            remediation=remediation,
                            note=note,
                            checked_indexes=set(request.POST.getlist('checklist_done')),
                        )
                        for warning in result.warnings:
                            messages.warning(request, warning)
                    except ValidationError as e:
                        messages.error(request, e.message)

        elif action in ('workflow_action', 'soc_update'):
            new_note = request.POST.get('update_notes', '').strip()
            new_status = request.POST.get('status')

            if not new_note:
                messages.error(request, 'กรุณากรอกบันทึกการดำเนินการ')
            elif new_status not in transition_codes:
                messages.error(request, 'การดำเนินการนี้ไม่ได้รับอนุญาตในขั้นตอนปัจจุบัน')
            else:
                try:
                    result = transition_ticket(
                        ticket=ticket,
                        actor=request.user,
                        next_status=new_status,
                        note=new_note,
                    )
                    for warning in result.warnings:
                        messages.warning(request, warning)
                except ValidationError as e:
                    messages.error(request, e.message)

        elif action == 'claim_t2':
            # Mirrors claim_escalation (apps/wazuh_ingest/views.py): one
            # conditional UPDATE so two analysts pressing Claim at the same
            # moment can't both win. Redirects back to this ticket instead of
            # the queue, since the button lives on the detail page now.
            if not is_t2_viewer:
                messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 2 เท่านั้นที่สามารถรับ Ticket ได้')
            else:
                result = claim_tier2_ticket(ticket=ticket, actor=request.user)
                if not result.claimed:
                    messages.error(
                        request,
                        'Ticket นี้ถูกเจ้าหน้าที่คนอื่นรับไปแล้ว หรือไม่ได้อยู่ในคิว Tier 2',
                    )
                else:
                    messages.success(request, 'คุณรับ Ticket นี้มาดำเนินการแล้ว')

        return redirect('ticket_detail', pk=pk)

    valid_status_choices = _valid_soc_status_choices(ticket, request.user)
    attachment_form = AttachmentForm()
    subtask_form = SubtaskForm()
    subtask_update_form = SubtaskUpdateForm()
    response_request_form = ResponseRequestForm()
    can_create_subtask = request.user.is_superuser or (profile and profile.is_soc)
    read_model = get_ticket_detail_read_model(
        ticket=ticket,
        user=request.user,
        can_submit_containment=can_submit_containment,
        can_request_response=can_request_response,
    )

    return render(request, 'incidents/ticket_detail.html', {
        'ticket': ticket,
        **read_model,
        # One-shot: set by create_ticket on a successful save so this page can
        # clear the matching localStorage draft. Popped so a later plain visit
        # to a ticket never wipes an unrelated in-progress draft.
        'clear_draft_key': request.session.pop('clear_ticket_draft_key', ''),
        'attachment_form': attachment_form,
        'attachment_limits': _attachment_limits(),
        'can_access_report': _can_access_ticket_report(request.user),
        'can_edit_ticket': _can_edit_ticket(ticket, request.user),
        'can_step_back': ticket.can_step_back(request.user),
        'step_back_target_label': dict(Ticket.STATUS_CHOICES).get(
            ticket.step_back_target(), ''),
        'profile': profile,
        'is_terminal': is_terminal,
        'can_upload_attachment': can_upload_attachment,
        'can_submit_containment': can_submit_containment,
        'checklist_items': checklist_items,
        'checklist_trailing': checklist_trailing,
        'has_saved_checklist': bool(ticket.containment_checklist),
        'valid_status_choices': valid_status_choices,
        'transition_actions': transition_actions,
        'can_t2_review': can_t2_review,
        't2_claim_visible': t2_claim_visible,
        't2_claim_state': t2_claim_state,   # None | 'unclaimed' | 'mine' | 'other'
        't2_review_form': TicketReviewForm(instance=ticket),
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        'can_assign_admin': can_assign_admin,
        'assignment_form': AdminAssignmentForm(instance=ticket),
        'can_mgr_forward': can_mgr_forward,
        'mgr_forward_target': mgr_forward_target,
        'can_t2_reclassify': can_t2_reclassify,
        'can_request_response': can_request_response,
        'response_request_form': response_request_form,
        'RESPONSE_TYPES': list(TicketSubtask.RESPONSE_TYPES),
        'T1_ROUTE_ADMIN': Ticket.T1_ROUTE_ADMIN,
        'T1_ROUTE_OWNER': Ticket.T1_ROUTE_OWNER,
        'can_reassess_emergency': ticket.can_reassess_emergency(request.user),
        'CLASSIFICATION_CHOICES': Ticket.CLASSIFICATION_CHOICES,
        'subtask_form': subtask_form,
        'subtask_update_form': subtask_update_form,
        'can_create_subtask': can_create_subtask,
    })


def _hide_empty_report_fields(params):
    return params.get('hide_empty', '1') != '0'


@login_required
@require_POST
def ticket_report_docx(request, pk):
    if not _can_access_ticket_report(request.user):
        raise Http404
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    try:
        report = generate_ticket_report(
            pk,
            generated_by=request.user,
            hide_empty=_hide_empty_report_fields(request.POST),
        )
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
    if not _can_access_ticket_report(request.user):
        raise Http404
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    try:
        report = generate_ticket_report_pdf(
            pk,
            generated_by=request.user,
            base_url=request.build_absolute_uri('/'),
            hide_empty=_hide_empty_report_fields(request.POST),
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
    if not _can_access_ticket_report(request.user):
        raise Http404
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    return render(
        request,
        'incidents/report_preview.html',
        build_ticket_report_render_context(
            ticket,
            hide_empty=_hide_empty_report_fields(request.GET),
        ),
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
        elif note == log.note:
            return redirect('ticket_detail', pk=ticket_id)
        else:
            # Bank the previous text before overwriting. The timeline is the
            # audit trail, and this view lets the author — or any SOC manager —
            # rewrite it, so without a revision the record of an action could be
            # edited by the person who took it, leaving nothing behind.
            TicketLogRevision.objects.create(
                log=log, previous_note=log.note, edited_by=request.user,
            )
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
    tickets_qs = query_set.select_related('project_incident').prefetch_related(
        'logs'
    ).order_by(*sort_map[sort])

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
    """Tier 1's single work queue ("My Queue" / คิวงานของฉัน).

    Three sections on one page, in render order:
      1. The analyst's own-court tickets (TIER1_QUEUE_STATUSES, created by
         them) — above all T1_REVIEW, where Tier 2 returned the case and only
         the creator may act. Before this page there was no surface telling
         the creator a case had come back.
      2. Manual-intake reports awaiting triage (TriageRecord) — the former
         Manual Triage page, with the same claim / convert / release /
         dismiss actions.
      3. The analyst's own recent dispositions. This is the only trail a
         DISMISSED report leaves: dismiss_manual_triage stamps decision=FP
         with no ticket, so the record surfaces in no ticket list and no
         dashboard.

    Keeps the historical `triage_list` URL name: every redirect and deep link
    from the manual-triage flow lands here, where the manual queue still lives.
    """
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_tier1):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่เข้าถึงหน้านี้ได้')
        return redirect('home')

    # Which tab opens. The manual-triage actions redirect back with
    # ?tab=manual so a claim/release/dismiss doesn't bounce the analyst out of
    # the queue they were working in.
    active_tab = request.GET.get('tab', 'tickets')
    if active_tab not in ('tickets', 'manual', 'history'):
        active_tab = 'tickets'

    queue = TriageRecord.objects.filter(decision='', ticket__isnull=True).select_related(
        'analyst', 'claimed_by',
    ).order_by('-created_at')
    # Scoped to this analyst: on a page called "my queue" a global log of every
    # analyst's records is not actionable, and IOC Search already covers the
    # full history with real filtering. What this needs to show is a trail of
    # what YOU just did — above all a dismissal, which leaves no ticket behind.
    history = TriageRecord.objects.filter(
        resolved_by=request.user,
    ).select_related('ticket').order_by('-resolved_at')[:10]

    # Own-court tickets, most urgent contain-OLA first (no deadline = notify-
    # only Medium/Low → below everything actually on a clock).
    my_tickets = (
        Ticket.objects.filter(
            created_by=request.user, status__in=Ticket.TIER1_QUEUE_STATUSES,
        )
        .select_related('assigned_admin')
        .order_by(
            F('ola_contain_deadline').asc(nulls_last=True),
            '-status_changed_at',
        )
    )
    # Counted before paging — these drive the tab badges and the returned-cases
    # alert, which describe the whole queue, not the page being viewed.
    my_tickets_total = my_tickets.count()
    returned_count = my_tickets.filter(status=Ticket.STATUS_T1_REVIEW).count()
    # This page was the only queue in the app without a Paginator; an unbounded
    # ticket table is what pushed the manual-intake queue below the fold.
    page_obj = Paginator(my_tickets, 10).get_page(request.GET.get('page'))

    return render(request, 'incidents/my_queue.html', {
        'manual_queue': queue,
        'manual_history': history,
        'my_tickets': page_obj,
        'page_obj': page_obj,
        'my_tickets_total': my_tickets_total,
        # Actionable count, matching the sidebar badge's rule exactly
        # (wazuh_ingest.context_processors.pending_triage_count): reports this
        # analyst can pick up or already holds. The table below still lists a
        # peer's claimed rows for shift awareness, but a badge is a call to
        # action — counting another analyst's work would make the nav badge
        # and this one disagree about the same queue.
        'manual_queue_count': queue.filter(
            Q(claimed_by__isnull=True) | Q(claimed_by=request.user)
        ).count(),
        'manual_history_count': len(history),
        'returned_count': returned_count,
        'active_tab': active_tab,
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
            return _manual_queue_redirect()
    else:
        form = TriageForm()

    return render(request, 'incidents/triage_form.html', {'form': form})


def _manual_queue_redirect():
    """Back to My Queue with the manual-intake tab open.

    Every action below belongs to that tab, so landing on the default
    (tickets) tab afterwards would lose the analyst's place mid-triage.
    """
    return redirect(f"{reverse('triage_list')}?tab=manual")


@login_required
def claim_manual_triage(request, triage_id):
    profile = getattr(request.user, 'profile', None)
    if request.method != 'POST' or (
        not request.user.is_superuser and (profile is None or not profile.is_tier1)
    ):
        return _manual_queue_redirect()
    updated = TriageRecord.objects.filter(
        pk=triage_id, decision='', ticket__isnull=True, claimed_by__isnull=True,
    ).update(claimed_by=request.user, claimed_at=timezone.now())
    if not updated:
        messages.error(request, 'รายการนี้ถูกผู้อื่นรับไปแล้วหรือดำเนินการเสร็จแล้ว')
    return _manual_queue_redirect()


@login_required
def release_manual_triage(request, triage_id):
    profile = getattr(request.user, 'profile', None)
    if request.method != 'POST' or (
        not request.user.is_superuser and (profile is None or not profile.is_tier1)
    ):
        return _manual_queue_redirect()
    reason = request.POST.get('release_reason', '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการคืนรายการกลับเข้าคิว')
        return _manual_queue_redirect()
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
    return _manual_queue_redirect()


@login_required
def dismiss_manual_triage(request, triage_id):
    """Close a manual-intake report as junk — no ticket.

    The disposal path the queue lacked: previously the claimer's only options
    were convert-to-ticket or release-back, so a prank call either became a
    full Event ticket (with a Tier 2 confirm) or sat in the queue forever.

    Stamps the existing decision=FP with a required reason (appended to the
    record's notes for the audit trail). A dismissed record leaves the queue
    via the history filter, and _can_create_ticket_from_triage already rejects
    FP-without-ticket records, so it cannot be converted afterwards.
    """
    profile = getattr(request.user, 'profile', None)
    if request.method != 'POST' or (
        not request.user.is_superuser and (profile is None or not profile.is_tier1)
    ):
        return _manual_queue_redirect()

    reason = request.POST.get('dismiss_reason', '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการปิดรายการโดยไม่เปิดเคส')
        return _manual_queue_redirect()

    # Claimer-only, like release — dismissal is a triage decision, so it
    # belongs to whoever holds the item. Superuser may clear any pending row.
    dismissable = TriageRecord.objects.filter(
        pk=triage_id, decision='', ticket__isnull=True, claimed_by=request.user,
    )
    if request.user.is_superuser:
        dismissable = TriageRecord.objects.filter(
            pk=triage_id, decision='', ticket__isnull=True,
        )
    triage = dismissable.first()
    if triage is None:
        messages.error(request, 'รายการนี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
        return _manual_queue_redirect()

    triage.decision = TriageRecord.DECISION_FP
    note = f'ปิดโดยไม่เปิดเคส: {reason}'
    triage.notes = f'{triage.notes}\n{note}' if triage.notes else note
    triage.resolved_by = request.user
    triage.resolved_at = timezone.now()
    triage.claimed_by = None
    triage.claimed_at = None
    triage.save(update_fields=[
        'decision', 'notes', 'resolved_by', 'resolved_at',
        'claimed_by', 'claimed_at',
    ])

    messages.success(request, 'ปิดรายการโดยไม่เปิดเคสแล้ว')
    return _manual_queue_redirect()


# ── Full-text search across tickets and triage records ─────────────────── #

# Substring search, deliberately NOT Postgres full-text.
#
# Full-text indexes whole tokens, which loses every query an analyst actually
# types here: a partial ticket id ("0010"), a subnet prefix ("10.0.1"), a
# partial hostname. Worse, Thai has no word spaces, so `to_tsvector` reduces a
# whole Thai description to ONE lexeme — making Thai content unsearchable
# except by exact full-phrase match.
#
# The predicate was also wrong: `ts_rank` returns 1e-20 rather than 0 for a
# non-match, so the old `.filter(rank__gt=0)` was true for every row and a
# ticket-id search returned the entire table, ranked, sliced to 50.
TICKET_SEARCH_FIELDS = (
    'ticket_id', 'device_name', 'ip_address', 'destination_ip',
    'issue_description', 'ioc_details', 'mitre_tactics', 'reference_id',
)
TRIAGE_SEARCH_FIELDS = (
    'source_reference', 'alert_description', 'source_ip', 'notes', 't2_notes',
)
SEARCH_PAGE_SIZE = 25


def _substring_match(fields, term):
    """OR ``term`` across ``fields`` as a case-insensitive substring."""
    match = Q()
    for field in fields:
        match |= Q(**{f'{field}__icontains': term})
    return match


@login_required
def global_search(request):
    query = (request.GET.get('q') or '').strip()
    profile = getattr(request.user, 'profile', None)
    # Triage records are SOC-only. Carried into the template as its own flag:
    # the card used to be gated on `triage_results is not None`, but the list
    # was initialised to [] and never became None, so every role saw an empty
    # Triage Records panel.
    can_search_triage = bool(
        request.user.is_superuser or (profile and profile.is_soc))

    # Always iterable — callers and tests treat these as sequences. The card
    # gate is can_search_triage, not "is this None".
    ticket_results = []
    triage_results = []
    ticket_total = triage_total = 0

    if query:
        ticket_qs = (
            Ticket.objects.visible_to(request.user)
            .filter(_substring_match(TICKET_SEARCH_FIELDS, query))
            .order_by('-created_at')
        )
        ticket_paginator = Paginator(ticket_qs, SEARCH_PAGE_SIZE)
        # Separate page params: the two result sets page independently.
        ticket_results = ticket_paginator.get_page(request.GET.get('tp'))
        ticket_total = ticket_paginator.count

        if can_search_triage:
            triage_qs = (
                TriageRecord.objects
                .filter(_substring_match(TRIAGE_SEARCH_FIELDS, query))
                .select_related('ticket')
                .order_by('-created_at')
            )
            triage_paginator = Paginator(triage_qs, SEARCH_PAGE_SIZE)
            triage_results = triage_paginator.get_page(request.GET.get('rp'))
            triage_total = triage_paginator.count

    return render(request, 'incidents/search_results.html', {
        'query': query,
        'ticket_results': ticket_results,
        'ticket_total': ticket_total,
        'can_search_triage': can_search_triage,
        'triage_results': triage_results,
        'triage_total': triage_total,
    })


# ── IOC / IP lookup tool ─────────────────────────────────────────────── #

# This view makes an outbound request to a third party on demand, so it is
# rate-limited per user: without a cap any authenticated account can drive
# unbounded traffic through the server to rdap.org, each call holding a worker
# for up to the 5s timeout. Results are cached because RDAP registration data
# changes on a timescale of days — a repeat lookup of the same IP during an
# investigation should not leave the building at all.
IP_LOOKUP_RATE_LIMIT = 30            # lookups per user per window
IP_LOOKUP_RATE_WINDOW = 60           # seconds
IP_LOOKUP_CACHE_SECONDS = 60 * 60    # per-IP result cache


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

    cache_key = f'ip_lookup:result:{ip_obj.compressed}'
    cached = cache.get(cache_key)
    if cached is not None:
        return JsonResponse(cached)

    # Fixed-window counter. add() only succeeds on the first call of a window,
    # which is what establishes the TTL; incr() afterwards leaves it intact so
    # the window really expires instead of sliding forward on every request.
    rate_key = f'ip_lookup:rate:{request.user.pk}'
    if cache.add(rate_key, 1, IP_LOOKUP_RATE_WINDOW):
        used = 1
    else:
        try:
            used = cache.incr(rate_key)
        except ValueError:
            # Key expired between add() and incr() — treat as a fresh window.
            cache.set(rate_key, 1, IP_LOOKUP_RATE_WINDOW)
            used = 1
    if used > IP_LOOKUP_RATE_LIMIT:
        logger.warning('IP lookup rate limit reached for user %s', request.user.pk)
        return JsonResponse(
            {'error': 'ค้นหาบ่อยเกินไป — กรุณารอสักครู่แล้วลองใหม่'}, status=429,
        )

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
    cache.set(cache_key, result, IP_LOOKUP_CACHE_SECONDS)
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
            result = create_legacy_subtask(
                ticket=ticket,
                actor=request.user,
                subtask_form=form,
            )
            messages.success(request, f'สร้างงานย่อย "{result.subtask.title}" เรียบร้อยแล้ว')
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

    try:
        result = create_response_request_operation(
            ticket=ticket,
            actor=request.user,
            response_form=form,
        )
    except ValidationError as exc:
        messages.error(request, exc.message)
        return redirect('ticket_detail', pk=pk)

    if not result.notification_sent:
        messages.warning(
            request,
            'สร้างคำขอแล้ว แต่ส่งอีเมลแจ้งผู้รับผิดชอบไม่สำเร็จ',
        )
    messages.success(
        request,
        f'ส่งคำขอ "{result.subtask.get_subtask_type_display()}" ให้ '
        f'{result.subtask.assigned_to.get_full_name() or result.subtask.assigned_to.username} '
        'เรียบร้อยแล้ว',
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
    if ticket.status in Ticket.TERMINAL_STATUSES:
        messages.error(request, 'This ticket is closed; no further files or subtask updates can be added.')
        return redirect('ticket_detail', pk=ticket.pk)
    if not can_update:
        messages.error(request, 'คุณไม่มีสิทธิ์อัปเดตงานย่อยนี้')
        return redirect('ticket_detail', pk=ticket.pk)

    if request.method == 'POST':
        was_done = subtask.is_done
        previous_status = subtask.status
        # Result notes are freely overwritable by any SOC member and previously
        # left no audit at all, so a forensic analyst's findings could be
        # replaced silently. Capture what was there first.
        previous_notes = subtask.result_notes
        form = SubtaskUpdateForm(request.POST, instance=subtask)
        if form.is_valid():
            # Optional deliverable file (e.g. forensic report / scan output),
            # linked to both the subtask and its ticket so it serves through the
            # hardened download_attachment path. Gated more tightly than the
            # notes/status update above: can_update lets any SOC member edit a
            # request, but only the assignee, a SOC manager, or a superuser may
            # put a file on the ticket through this route.
            upload = request.FILES.get('result_file')
            result_upload = None
            if upload is not None:
                if not _can_upload_subtask_result(subtask, request.user):
                    messages.error(
                        request,
                        'คุณไม่มีสิทธิ์แนบไฟล์ผลการดำเนินการของคำขอนี้ '
                        '— บันทึกข้อความถูกจัดเก็บแล้ว แต่ไฟล์ไม่ถูกแนบ',
                    )
                else:
                    try:
                        validate_attachment(upload)
                        result_upload = upload
                    except ValidationError as e:
                        messages.error(request, e.message)

            subtask = save_subtask_update(
                ticket=ticket,
                actor=request.user,
                update_form=form,
                previous_status=previous_status,
                previous_notes=previous_notes,
                was_done=was_done,
                result_upload=result_upload,
                result_description=request.POST.get('result_file_desc', '').strip(),
            ).subtask

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
        # Both conditions matter. assigned_to alone would surface a request of
        # another team's type that was mis-assigned by a seed, a data migration,
        # or the admin — the queue must not be the place that invariant is
        # discovered. Mirrors the same filter in TicketQuerySet.visible_to().
        requests_qs = requests_qs.filter(
            assigned_to=request.user,
            subtask_type__in=TicketSubtask.types_for_role(profile.role),
        )

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
    if not _can_upload_ticket_attachment(ticket, request.user):
        messages.error(request, 'You cannot upload attachments while this ticket is in its current status.')
        return redirect('ticket_detail', pk=pk)
    if request.method == 'POST':
        form = AttachmentForm(request.POST, request.FILES)
        if form.is_valid():
            description = form.cleaned_data.get('description', '')
            uploads = form.cleaned_data['file']
            result = add_ticket_attachments(
                ticket=ticket,
                actor=request.user,
                uploads=uploads,
                description=description,
            )
            if len(result.attachments) == 1:
                messages.success(
                    request,
                    f'อัพโหลด "{result.attachments[0].original_name}" เรียบร้อยแล้ว',
                )
            else:
                messages.success(request, f'อัพโหลด {len(result.attachments)} ไฟล์เรียบร้อยแล้ว')
        else:
            # Name the offending file — "check your file again" is useless when
            # several were selected and only one was rejected.
            detail = '; '.join(
                msg for errors in form.errors.values() for msg in errors
            )
            messages.error(
                request,
                f'ไม่สามารถอัพโหลดไฟล์ได้ — {detail}' if detail
                else 'ไม่สามารถอัพโหลดไฟล์ได้ — กรุณาตรวจสอบไฟล์อีกครั้ง',
            )
    return redirect('ticket_detail', pk=pk)


@login_required
@require_POST
def discard_staged_attachment(request, pk):
    """Remove one file from an in-progress case form.

    Scoped to the uploader inside discard_staged; a 404 here means the row is
    gone or was never theirs. Answers 204 so the picker can grey the chip out
    without a page reload. The file is retained so restore_staged_attachment
    can undo this.
    """
    if not discard_staged(request.user, pk):
        raise Http404
    return HttpResponse(status=204)


@login_required
@require_POST
def restore_staged_attachment(request, pk):
    """Undo a discard while the case form is still open."""
    if not restore_staged(request.user, pk):
        raise Http404
    return HttpResponse(status=204)


@login_required
@require_POST
def delete_attachment(request, attachment_id):
    att = get_object_or_404(TicketAttachment, pk=attachment_id)
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=att.ticket_id)

    if not _can_delete_ticket_attachment(ticket, att, request.user):
        # A refused attempt used to be a silent redirect, so probing left no
        # trace at all. It goes to the application log rather than TicketLog:
        # anyone who can see a ticket could otherwise flood its timeline.
        logger.warning(
            'Refused attachment delete: user=%s attachment=%s ticket=%s status=%s',
            request.user.pk, att.pk, ticket.ticket_id, ticket.status,
        )
        messages.error(
            request,
            'คุณไม่มีสิทธิ์ลบไฟล์นี้ หรือเคสถูกปิดแล้ว — หลักฐานของเคสที่ปิดแล้วจะถูกล็อกไว้',
        )
        return redirect('ticket_detail', pk=ticket.pk)

    reason = (request.POST.get('reason') or '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการลบไฟล์')
        return redirect('ticket_detail', pk=ticket.pk)

    delete_ticket_attachment(attachment=att, actor=request.user, reason=reason)
    messages.success(request, 'ลบไฟล์เรียบร้อยแล้ว — ผู้จัดการ SOC สามารถกู้คืนได้')
    return redirect('ticket_detail', pk=ticket.pk)


@login_required
def edit_ticket(request, pk):
    """Correct a ticket's content, recording every field that moves.

    Deliberately cannot change status, route, or sign-off: this is a correction
    surface, not a workflow one. Use the transition controls for that.
    """
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    if not _can_edit_ticket(ticket, request.user):
        messages.error(
            request,
            'คุณไม่มีสิทธิ์แก้ไขข้อมูลเคสนี้ '
            '— เจ้าของเคสแก้ไขได้ขณะยังไม่มีผู้อื่นดำเนินการ หลังจากนั้นเป็นสิทธิ์ของ SOC '
            'และเคสที่ปิดแล้วจะถูกล็อกไว้',
        )
        return redirect('ticket_detail', pk=pk)

    if request.method == 'POST':
        form = TicketEditForm(request.POST, instance=ticket)
        if form.is_valid():
            reason = (request.POST.get('reason') or '').strip()
            if not reason:
                messages.error(request, 'กรุณาระบุเหตุผลในการแก้ไข')
            else:
                result = save_ticket_edit(
                    ticket=ticket,
                    actor=request.user,
                    edit_form=form,
                    reason=reason,
                )
                if result.changes:
                    messages.success(
                        request,
                        f'บันทึกการแก้ไข {len(result.changes)} รายการเรียบร้อยแล้ว',
                    )
                else:
                    messages.info(request, 'ไม่มีข้อมูลที่เปลี่ยนแปลง')
                return redirect('ticket_detail', pk=pk)
    else:
        form = TicketEditForm(instance=ticket)

    return render(request, 'incidents/ticket_edit.html', {
        'ticket': ticket,
        'form': form,
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        # Correcting a ticket that is waiting on someone else is allowed but
        # worth flagging — the holder may be acting on what you are about to
        # change. A warning, not a block: see _can_edit_ticket.
        'out_of_court': not _holds_ticket_court(ticket, request.user),
        'court_holder': ticket.court_holder_label,
    })


@login_required
@require_POST
def restore_attachment(request, attachment_id):
    """Bring back evidence removed by mistake. SOC Manager / superuser only."""
    att = get_object_or_404(
        TicketAttachment.all_objects, pk=attachment_id, deleted_at__isnull=False)
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=att.ticket_id)

    if not _can_restore_ticket_attachment(request.user):
        logger.warning(
            'Refused attachment restore: user=%s attachment=%s ticket=%s',
            request.user.pk, att.pk, ticket.ticket_id,
        )
        messages.error(request, 'กู้คืนไฟล์ได้เฉพาะผู้จัดการ SOC เท่านั้น')
        return redirect('ticket_detail', pk=ticket.pk)

    restore_ticket_attachment(attachment=att, actor=request.user)
    messages.success(request, f'กู้คืน "{att.original_name}" เรียบร้อยแล้ว')
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
