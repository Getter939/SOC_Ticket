import logging

from django import forms as django_forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from apps.incidents import history
from apps.wazuh_ingest.models import WazuhAlert
from ..forms import (
    AdminAssignmentForm, AttachmentForm, ResponseRequestForm,
    SubtaskUpdateForm, TicketEditForm, TicketForm, TicketPreparationEditForm,
    TicketReviewForm,
)
from ..models import (
    Ticket,
    TicketSubtask, TriageRecord,
)
from ..staging import (
    staged_for, stage_uploads,
)
from ..report_content import GUIDANCE_COORDINATION_NOTE
from ..policies import (
    can_access_ticket_report as _can_access_ticket_report,
    can_create_ticket_from_triage as _can_create_ticket_from_triage,
    can_edit_ticket as _can_edit_ticket,
    can_upload_ticket_attachment as _can_upload_ticket_attachment,
    holds_ticket_court as _holds_ticket_court,
    user_can_drive as _user_can_drive,
)
from ..selectors import get_ticket_detail_read_model
from ..cancellation_views import cancellation_context
from ..case_creation import (
    create_ticket_from_form,
    load_alert_bundle,
    preparation_form_route,
    set_preparation_route,
)
from ..ticket_updates import save_ticket_edit
from ..ticket_workflow import (
    assign_admin_or_owner_route,
    claim_tier2_ticket,
    complete_t2_review,
    conclude_monitoring,
    manager_forward,
    return_for_completion,
    reassess_emergency,
    reclassify_as_event,
    record_remediation_check,
    start_monitoring,
    step_back,
    submit_preparation,
    submit_containment,
    transition_ticket,
    validate_affected_notified_at,
)

logger = logging.getLogger('apps.incidents.views')

from ._helpers import (
    _active_threat_guidance,
    _valid_soc_status_choices,
    _case_switch_qs,
    _attachment_limits,
    _transition_actions,
    _alert_bundle_ids,
    _render_ticket_list,
)
from .reports import _remediation_checklist_state


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
        if form.is_valid():
            try:
                result = create_ticket_from_form(
                    form=form,
                    actor=request.user,
                    triage=triage,
                    alert_bundle_ids=alert_bundle_ids,
                    evidence_token=evidence_token,
                    propose_monitoring=bool(request.POST.get('propose_monitoring')),
                    submit_immediately=(
                        request.POST.get('submission_intent') != 'save_preparation'
                    ),
                )
            except ValidationError as exc:
                form.add_error(None, exc.message)
            else:
                for warning in result.warnings:
                    messages.warning(request, warning)
                if result.ticket.status == Ticket.STATUS_NEW:
                    messages.success(
                        request,
                        f'บันทึก Ticket #{result.ticket.ticket_id} ไว้เป็นรายการจัดเตรียมแล้ว '
                        'คุณสามารถแก้ไขและแนบหลักฐานก่อนส่งเข้าสู่กระบวนการ',
                    )
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
def ticket_detail(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    profile = getattr(request.user, 'profile', None)
    is_terminal = ticket.status in Ticket.TERMINAL_STATUSES
    can_upload_attachment = _can_upload_ticket_attachment(ticket, request.user)
    can_submit_preparation = (
        ticket.status == Ticket.STATUS_NEW
        and ticket.creator_analyst_can_act(request.user)
    )

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
    can_return_for_completion = (
        ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE
        and (
            request.user.is_superuser
            or (profile is not None and profile.is_soc_manager)
        )
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
    # Tier 2 records the section-8 remediation checklist while verifying that the
    # System Admin (CONTAINMENT_REPORTED) or System Owner (PENDING_T2_REVIEW) has
    # contained the incident. The Owner lane also exposes the two free-text
    # result fields, which the Admin lane leaves to the System Admin's own form.
    can_t2_record_remediation = (
        not is_terminal
        and ticket.status in (
            Ticket.STATUS_CONTAINMENT_REPORTED, Ticket.STATUS_PENDING_T2_REVIEW,
        )
        and bool(transition_actions)
        and (request.user.is_superuser or (profile is not None and profile.is_tier2))
    )
    remediation_owner_lane = ticket.status == Ticket.STATUS_PENDING_T2_REVIEW
    remediation_checklist_state = _remediation_checklist_state(ticket)
    # Tier 2 may park an escalated case under Tier 1 for the fixed watch window
    # — once only (has_been_monitored), and never a bundle member. Rendered
    # inside the Tier 2 review card, alongside the Incident/Event decision.
    can_monitor = (
        not is_terminal
        and ticket.status == Ticket.STATUS_ESCALATED_T2
        and not ticket.has_been_monitored
        and not ticket.project_incident_id
        and (request.user.is_superuser or (profile is not None and profile.is_tier2))
    )
    # The owning Tier 1 concludes the watch window: Incident (something happened)
    # or Event (window closed quietly). The exit edges are TIER1_CREATOR.
    can_conclude_monitoring = (
        ticket.status == Ticket.STATUS_MONITORING
        and _user_can_drive(ticket, request.user, 'TIER1_CREATOR')
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

        if action == 'submit_preparation':
            if not can_submit_preparation:
                messages.error(request, 'คุณไม่มีสิทธิ์ส่ง Ticket รายการนี้')
            else:
                try:
                    result = submit_preparation(
                        ticket=ticket,
                        actor=request.user,
                        propose_monitoring=bool(request.POST.get('propose_monitoring')),
                    )
                    messages.success(request, 'ส่ง Ticket เข้าสู่กระบวนการเรียบร้อยแล้ว')
                    for warning in result.warnings:
                        messages.warning(request, warning)
                except ValidationError as e:
                    messages.error(request, e.message)

        elif action == 'return_for_completion':
            if not can_return_for_completion:
                messages.error(request, 'คุณไม่มีสิทธิ์ส่ง Ticket นี้กลับให้ผู้เปิดดำเนินการ')
            else:
                try:
                    return_for_completion(
                        ticket=ticket,
                        actor=request.user,
                        reason=request.POST.get('return_reason', ''),
                    )
                    messages.success(request, 'ส่ง Ticket กลับให้ผู้เปิดดำเนินการให้ครบถ้วนแล้ว')
                except ValidationError as e:
                    messages.error(request, e.message)

        elif action == 'reassess_emergency':
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
            note = request.POST.get('decision_note', '').strip()
            # The "เฝ้าระวัง" button lives in the same decision form and shares its
            # (required) note, but it is a classification-deferring decision, not
            # an Event/Incident call — so it routes to start_monitoring rather
            # than the classification-matched review path below.
            if next_status == Ticket.STATUS_MONITORING:
                if not can_monitor:
                    messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้ หรือเคสนี้เฝ้าระวังไม่ได้')
                elif not note:
                    messages.error(request, 'กรุณากรอกบันทึกการตัดสินใจ')
                else:
                    try:
                        start_monitoring(ticket=ticket, actor=request.user, note=note)
                        messages.success(
                            request,
                            f'เริ่มเฝ้าระวังเคสนี้เป็นเวลา {Ticket.MONITORING_DURATION_DAYS} วัน',
                        )
                    except ValidationError as e:
                        messages.error(request, e.message)
                return redirect('ticket_detail', pk=pk)

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
                        fallback_label={
                            item['status']: item['label'] for item in transition_actions
                        }[next_status],
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

        elif action == 'conclude_monitoring':
            # The owning Tier 1 ends the watch: Incident (something happened) or
            # Event (window closed quietly).
            outcome = request.POST.get('monitoring_outcome', '')
            note = request.POST.get('decision_note', '').strip()
            if not can_conclude_monitoring:
                messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
            elif outcome not in ('incident', 'event'):
                messages.error(request, 'กรุณาเลือกผลการเฝ้าระวัง (Incident หรือ Event)')
            elif not note:
                messages.error(request, 'กรุณากรอกบันทึกการตัดสินใจ')
            else:
                try:
                    result = conclude_monitoring(
                        ticket=ticket, actor=request.user, outcome=outcome, note=note,
                    )
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
                # Report row 1.4 — recorded on the Tier 2 review card. Required to
                # move the case forward (approve / to manager), optional on the
                # send-back and Event edges, which share the same <form>.
                notified_at = None
                notified_error = None
                forward_targets = (
                    Ticket.STATUS_APPROVED, Ticket.STATUS_PENDING_MANAGER,
                )
                if can_t2_record_remediation:
                    raw_notified = request.POST.get('affected_notified_at', '').strip()
                    if raw_notified:
                        try:
                            notified_at = django_forms.DateTimeField(
                                input_formats=['%Y-%m-%dT%H:%M'],
                            ).clean(raw_notified)
                        except ValidationError:
                            notified_error = (
                                'รูปแบบวันที่ เวลา ที่แจ้งเหตุผู้ที่ได้รับผลกระทบไม่ถูกต้อง'
                            )
                    elif new_status in forward_targets:
                        notified_error = (
                            'กรุณาระบุวันที่ เวลา ที่แจ้งเหตุผู้ที่ได้รับผลกระทบ'
                        )
                if notified_error:
                    messages.error(request, notified_error)
                    return redirect('ticket_detail', pk=pk)
                try:
                    with transaction.atomic():
                        # Tier 2's section-8 remediation checklist is saved
                        # alongside every forward move (incl. Return/Reject), so
                        # what was ticked carries into the next round.
                        if can_t2_record_remediation:
                            before = history.snapshot(ticket)
                            findings = countermeasure = None
                            if remediation_owner_lane:
                                findings = request.POST.get('remediation_summary', '').strip()
                                countermeasure = request.POST.get('containment_report', '').strip()
                            record_remediation_check(
                                ticket=ticket,
                                actor=request.user,
                                checked_keys=set(request.POST.getlist('remediation_done')),
                                other=request.POST.get('remediation_other', '').strip(),
                                findings=findings,
                                countermeasure=countermeasure,
                                affected_notified_at=notified_at,
                            )
                            history.record_changes(
                                ticket, before, request.user, source='t2_remediation',
                            )
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
    subtask_update_form = SubtaskUpdateForm()
    response_request_form = ResponseRequestForm()
    read_model = get_ticket_detail_read_model(
        ticket=ticket,
        user=request.user,
        can_submit_containment=can_submit_containment,
        can_request_response=can_request_response,
    )

    return render(request, 'incidents/ticket_detail.html', {
        'ticket': ticket,
        **cancellation_context(ticket, request.user),
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
        'can_submit_preparation': can_submit_preparation,
        'can_return_for_completion': can_return_for_completion,
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
        'can_t2_record_remediation': can_t2_record_remediation,
        'remediation_owner_lane': remediation_owner_lane,
        'remediation_checklist_state': remediation_checklist_state,
        'can_monitor': can_monitor,
        'can_conclude_monitoring': can_conclude_monitoring,
        'monitoring_duration_days': Ticket.MONITORING_DURATION_DAYS,
        'can_request_response': can_request_response,
        'response_request_form': response_request_form,
        'RESPONSE_TYPES': list(TicketSubtask.RESPONSE_TYPES),
        'T1_ROUTE_ADMIN': Ticket.T1_ROUTE_ADMIN,
        'T1_ROUTE_OWNER': Ticket.T1_ROUTE_OWNER,
        'can_reassess_emergency': ticket.can_reassess_emergency(request.user),
        'CLASSIFICATION_CHOICES': Ticket.CLASSIFICATION_CHOICES,
        'subtask_update_form': subtask_update_form,
    })


@login_required
@transaction.atomic
def edit_ticket(request, pk):
    """Correct a ticket's content, recording every field that moves.

    Deliberately cannot change status, route, or sign-off: this is a correction
    surface, not a workflow one. Use the transition controls for that.
    """
    tickets = Ticket.objects.visible_to(request.user)
    if request.method == 'POST':
        tickets = tickets.select_for_update()
    ticket = get_object_or_404(tickets, pk=pk)
    if not _can_edit_ticket(ticket, request.user):
        messages.error(
            request,
            'คุณไม่มีสิทธิ์แก้ไขข้อมูลเคสนี้ '
            '— เจ้าของเคสแก้ไขได้ขณะยังไม่มีผู้อื่นดำเนินการ หลังจากนั้นเป็นสิทธิ์ของ SOC '
            'และเคสที่ปิดแล้วจะถูกล็อกไว้',
        )
        return redirect('ticket_detail', pk=pk)

    can_upload_attachment = _can_upload_ticket_attachment(ticket, request.user)
    evidence_token = ''
    reason = ''
    is_preparation = ticket.status == Ticket.STATUS_NEW
    if request.method == 'POST':
        if is_preparation:
            posted = request.POST.copy()
            if not posted.get('t1_route'):
                posted['t1_route'] = preparation_form_route(ticket)
            form = TicketPreparationEditForm(posted, instance=ticket)
        else:
            form = TicketEditForm(request.POST, instance=ticket)
        reason = (request.POST.get('reason') or '').strip()
        if can_upload_attachment:
            evidence_token, staged_errors = stage_uploads(request)
            for error in staged_errors:
                form.add_error(None, error)
        elif request.FILES.getlist('evidence_files') or staged_for(
            request.user, request.POST.get('evidence_token'),
        ).exists():
            form.add_error(None, 'คุณไม่มีสิทธิ์แนบไฟล์ในสถานะปัจจุบันของเคสนี้')
        if form.is_valid():
            if is_preparation:
                set_preparation_route(ticket, form.cleaned_data.get('t1_route'))
            if not reason:
                messages.error(request, 'กรุณาระบุเหตุผลในการแก้ไข')
            else:
                try:
                    result = save_ticket_edit(
                        ticket=ticket,
                        actor=request.user,
                        edit_form=form,
                        reason=reason,
                        evidence_token=evidence_token,
                    )
                except ValidationError as exc:
                    messages.error(request, ' '.join(exc.messages))
                    return redirect('ticket_detail', pk=pk)
                if result.changes:
                    messages.success(
                        request,
                        f'บันทึกการแก้ไข {len(result.changes)} รายการเรียบร้อยแล้ว',
                    )
                if result.attachments:
                    messages.success(
                        request,
                        f'แนบไฟล์หลักฐาน {len(result.attachments)} ไฟล์เรียบร้อยแล้ว',
                    )
                if not result.changes and not result.attachments:
                    messages.info(request, 'ไม่มีข้อมูลที่เปลี่ยนแปลง')
                return redirect('ticket_detail', pk=pk)
    else:
        if is_preparation:
            form = TicketPreparationEditForm(
                instance=ticket,
                initial={'t1_route': preparation_form_route(ticket)},
            )
        else:
            form = TicketEditForm(instance=ticket)

    return render(request, 'incidents/ticket_edit.html', {
        'ticket': ticket,
        'is_preparation': is_preparation,
        'form': form,
        'reason': reason,
        'can_upload_attachment': can_upload_attachment,
        'attachment_limits': _attachment_limits(),
        'evidence_token': evidence_token,
        'staged_files': staged_for(request.user, evidence_token),
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        # Correcting a ticket that is waiting on someone else is allowed but
        # worth flagging — the holder may be acting on what you are about to
        # change. A warning, not a block: see _can_edit_ticket.
        'out_of_court': not _holds_ticket_court(ticket, request.user),
        'court_holder': ticket.court_holder_label,
    })
