import calendar
import ipaddress
import logging

import requests
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import F, Q
from django.http import FileResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

logger = logging.getLogger(__name__)

from apps.wazuh_ingest.models import WazuhAlert
from .forms import (
    AdminAssignmentForm, AttachmentForm, SubtaskForm, SubtaskUpdateForm,
    TicketForm, TicketReviewForm, TriageForm,
)
from .models import (
    Ticket, TicketAttachment, TicketLog, TicketSubtask, TriageRecord,
    validate_attachment_size,
)
from .notifications import (
    notify_containment_alert,
    notify_containment_submitted,
    notify_system_owner_created,
    notify_system_owner_closed,
)


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
        Ticket.STATUS_PENDING_MANAGER: 'Send to SOC Manager',
        Ticket.STATUS_APPROVED: (
            'Verify -> Close'
            if ticket.status == Ticket.STATUS_PENDING_MANAGER else 'Close case'
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
    if triage.ticket_id:
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


@login_required
def ticket_list(request):
    visible = Ticket.objects.visible_to(request.user)
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and profile and profile.is_soc_manager:
        visible = visible.filter(status=Ticket.STATUS_PENDING_MANAGER)
    tickets_qs = visible.exclude(
        status__in=list(Ticket.TERMINAL_STATUSES)
    ).select_related('assigned_admin', 'created_by')

    search = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '').strip()
    severity_filter = request.GET.get('severity', '').strip()
    emergency_filter = request.GET.get('emergency', '').strip()
    sort = request.GET.get('sort', 'sla').strip()

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

    sort_map = {
        'sla':       ('sla_deadline',),
        'emergency': ('-is_emergency', 'sla_deadline'),
        'newest':    ('-created_at',),
        'oldest':    ('created_at',),
    }
    if sort not in sort_map:
        sort = 'sla'
    tickets_qs = tickets_qs.order_by(*sort_map[sort])

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    sla_breach_count = visible.filter(
        sla_deadline__lt=F('created_at')
    ).exclude(status__in=list(Ticket.TERMINAL_STATUSES)).count()

    return render(request, 'incidents/ticket_list.html', {
        'tickets': page_obj,
        'page_obj': page_obj,
        'result_count': paginator.count,
        'sla_breach_count': sla_breach_count,
        'search': search,
        'status_filter': status_filter,
        'severity_filter': severity_filter,
        'emergency_filter': emergency_filter,
        'sort': sort,
        'active_status_choices': active_status_choices,
        'severity_choices': Ticket.SEVERITY_CHOICES,
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
                        ticket.transition_to(
                            Ticket.STATUS_CLOSED_EVENT, request.user,
                            'จัดประเภทเป็น Event — ปิด Ticket',
                        )
                    elif route == TicketForm.ROUTE_ESCALATE_T2:
                        ticket.transition_to(
                            Ticket.STATUS_ESCALATED_T2, request.user,
                            'จัดประเภทเป็น Incident — ส่งต่อให้ Tier 2',
                        )
                    elif route == TicketForm.ROUTE_ASSIGN_ADMIN:
                        ticket.transition_to(
                            Ticket.STATUS_AWAITING_CONTAINMENT, request.user,
                            'จัดประเภทเป็น Incident — มอบหมายให้ผู้ดูแลระบบ',
                        )

                    if locked_triage:
                        locked_triage.ticket = ticket
                        locked_triage.decision = (
                            TriageRecord.DECISION_FP
                            if ticket.classification == Ticket.CLASSIFICATION_EVENT
                            else TriageRecord.DECISION_TP
                        )
                        locked_triage.claimed_by = None
                        locked_triage.claimed_at = None
                        locked_triage.save(update_fields=[
                            'ticket', 'decision', 'claimed_by', 'claimed_at',
                        ])

                    if locked_alert:
                        now = timezone.now()
                        locked_alert.triage_status = (
                            WazuhAlert.TRIAGE_FALSE_POSITIVE
                            if ticket.classification == Ticket.CLASSIFICATION_EVENT
                            else WazuhAlert.TRIAGE_TRUE_POSITIVE
                        )
                        locked_alert.triaged_by = request.user
                        locked_alert.triaged_at = now
                        locked_alert.escalated_to_tier = None
                        locked_alert.claimed_by = None
                        locked_alert.claimed_at = None
                        locked_alert.save(update_fields=[
                            'triage_status', 'triaged_by', 'triaged_at',
                            'escalated_to_tier', 'claimed_by', 'claimed_at',
                        ])

                        # Stamp analyst response time once (alert actionable →
                        # ticket raised). now() is within sub-second of the
                        # ticket's auto_now_add created_at. Guard against clock
                        # skew that would otherwise yield a negative duration.
                        delta = now - locked_alert.ingested_at
                        if delta.total_seconds() >= 0:
                            ticket.alert_conversion_duration = delta
                            ticket.save(update_fields=['alert_conversion_duration'])

                    for evidence_file in request.FILES.getlist('evidence_files'):
                        validate_attachment_size(evidence_file)
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

            # Notify the assigned admin immediately if the ticket was
            # auto-routed to AWAITING_CONTAINMENT above
            if ticket and ticket.status == Ticket.STATUS_AWAITING_CONTAINMENT:
                _notify_containment(ticket, None, request)

            if ticket:
                return redirect('ticket_detail', pk=ticket.pk)
    else:
        initial = {}
        if triage:
            initial['device_name'] = triage.source_ip
            initial['issue_description'] = triage.alert_description
        if request.GET.get('wazuh_alert'):
            initial['wazuh_alert'] = request.GET['wazuh_alert']
        if request.GET.get('issue_description'):
            initial['issue_description'] = request.GET['issue_description']
        if request.GET.get('severity'):
            initial['severity'] = request.GET['severity']
        if request.GET.get('detailed_issue2') in dict(Ticket.DETAILED_ISSUE_CHOICES2):
            initial['detailed_issue2'] = request.GET['detailed_issue2']
        form = TicketForm(initial=initial, user=request.user)

    return render(request, 'incidents/ticket_form.html', {
        'form': form,
        'triage_id': triage_id or '',
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
        and Ticket.STATUS_AWAITING_CONTAINMENT in transition_codes
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
            assignment_form = AdminAssignmentForm(request.POST, instance=ticket)
            note = request.POST.get('decision_note', '').strip()
            if not can_assign_admin:
                messages.error(request, 'This ticket cannot be assigned by the current user.')
            elif not note:
                messages.error(request, 'A review note is required.')
            elif assignment_form.is_valid():
                try:
                    with transaction.atomic():
                        ticket = assignment_form.save()
                        ticket.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, request.user, note)
                    _notify_containment(ticket, None, request)
                except ValidationError as e:
                    messages.error(request, e.message)

        elif action == 'containment':
            if not can_submit_containment:
                messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
            else:
                # The System Admin writes the countermeasure (containment_report)
                # and investigation-findings (remediation_summary) fields, then
                # returns the ticket to Tier 1. Classification is NOT set here —
                # it is Tier 1's (or Tier 2's) decision.
                report = request.POST.get('containment_report', '').strip()
                remediation = request.POST.get('remediation_summary', '').strip()
                note = request.POST.get('note', '').strip()

                if not report:
                    messages.error(request, 'กรุณากรอกรายงานการควบคุม')
                else:
                    ticket.containment_report = report
                    if remediation:
                        ticket.remediation_summary = remediation
                    try:
                        ticket.transition_to(
                            Ticket.STATUS_CONTAINMENT_REPORTED,
                            request.user,
                            note or 'ส่งรายงานการควบคุมแล้ว',
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

    subtasks = ticket.subtasks.all()
    subtask_form = SubtaskForm()
    subtask_update_form = SubtaskUpdateForm()
    can_create_subtask = request.user.is_superuser or (profile and profile.is_soc)

    return render(request, 'incidents/ticket_detail.html', {
        'ticket': ticket,
        'logs': logs,
        'attachments': attachments,
        'attachment_form': attachment_form,
        'profile': profile,
        'is_terminal': is_terminal,
        'can_submit_containment': can_submit_containment,
        'valid_status_choices': valid_status_choices,
        'transition_actions': transition_actions,
        'can_t2_review': can_t2_review,
        't2_review_form': TicketReviewForm(instance=ticket),
        'can_assign_admin': can_assign_admin,
        'assignment_form': AdminAssignmentForm(instance=ticket),
        'can_set_emergency': ticket.can_set_emergency(request.user),
        'CLASSIFICATION_CHOICES': Ticket.CLASSIFICATION_CHOICES,
        'subtasks': subtasks,
        'subtask_form': subtask_form,
        'subtask_update_form': subtask_update_form,
        'can_create_subtask': can_create_subtask,
    })


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
        form = SubtaskUpdateForm(request.POST, instance=subtask)
        if form.is_valid():
            form.save()
            messages.success(request, f'อัปเดตงานย่อย "{subtask.title}" เรียบร้อยแล้ว')
        else:
            messages.error(request, 'ไม่สามารถอัปเดตงานย่อยได้ — กรุณาตรวจสอบข้อมูล')
    return redirect('ticket_detail', pk=ticket.pk)


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

    stats = {
        'total':          my_tickets.count(),
        'active':         active_qs.count(),
        'closed':         closed_qs.count(),
        'sla_breaches':   active_qs.filter(sla_deadline__lt=F('created_at')).count(),
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
