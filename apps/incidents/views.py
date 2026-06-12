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
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

logger = logging.getLogger(__name__)

from apps.wazuh_ingest.models import WazuhAlert
from .forms import AttachmentForm, SubtaskForm, SubtaskUpdateForm, TicketForm, TriageForm
from .models import Ticket, TicketAttachment, TicketLog, TicketSubtask, TriageRecord
from .notifications import (
    notify_containment_required,
    notify_system_owner_created,
    notify_system_owner_closed,
)


# ── Private helpers ──────────────────────────────────────────────────── #

def _valid_soc_status_choices(ticket, user):
    profile = getattr(user, 'profile', None)
    if not user.is_superuser and (profile is None or not profile.is_soc):
        return []

    status_map = dict(Ticket.STATUS_CHOICES)
    result = [(ticket.status, status_map.get(ticket.status, ticket.status))]

    for next_status in Ticket.ALLOWED_TRANSITIONS.get(ticket.status, []):
        perm = Ticket.TRANSITION_PERMISSIONS.get((ticket.status, next_status))
        if user.is_superuser:
            result.append((next_status, status_map.get(next_status, next_status)))
        elif perm == 'SOC':
            result.append((next_status, status_map.get(next_status, next_status)))
        elif perm == 'MANAGER' and (
            user.is_superuser or (profile and profile.is_soc_manager)
        ):
            result.append((next_status, status_map.get(next_status, next_status)))

    return result


def _notify_containment(ticket, reason, request):
    if not ticket.assigned_admin_id:
        messages.warning(request, 'Ticket routed — ไม่สามารถส่งอีเมลแจ้งเตือนได้: ยังไม่ได้กำหนดผู้ดูแลระบบ')
        return
    admin = ticket.assigned_admin
    if not admin.email:
        messages.warning(request, f'Ticket routed — {admin.get_full_name() or admin.username} ไม่มีอีเมล')
        return
    if not notify_containment_required(ticket, reason=reason):
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
    tickets_qs = visible.exclude(status__in=list(Ticket.TERMINAL_STATUSES))

    search = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '').strip()
    severity_filter = request.GET.get('severity', '').strip()
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

    sort_map = {
        'sla':    'sla_deadline',   # most urgent deadline first
        'newest': '-created_at',
        'oldest': 'created_at',
    }
    if sort not in sort_map:
        sort = 'sla'
    tickets_qs = tickets_qs.order_by(sort_map[sort])

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    sla_breach_count = visible.filter(
        sla_deadline__lt=timezone.now()
    ).exclude(status__in=list(Ticket.TERMINAL_STATUSES)).count()

    return render(request, 'incidents/ticket_list.html', {
        'tickets': page_obj,
        'page_obj': page_obj,
        'result_count': paginator.count,
        'sla_breach_count': sla_breach_count,
        'search': search,
        'status_filter': status_filter,
        'severity_filter': severity_filter,
        'sort': sort,
        'active_status_choices': active_status_choices,
        'severity_choices': Ticket.SEVERITY_CHOICES,
    })


@login_required
def create_ticket(request):
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_soc):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเปิดเคสใหม่ได้')
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

                    if locked_triage:
                        locked_triage.ticket = ticket
                        locked_triage.save(update_fields=['ticket'])

                    if locked_alert:
                        locked_alert.triage_status = WazuhAlert.TRIAGE_TRUE_POSITIVE
                        locked_alert.triaged_by = request.user
                        locked_alert.triaged_at = timezone.now()
                        locked_alert.escalated_to_tier = None
                        locked_alert.claimed_by = None
                        locked_alert.claimed_at = None
                        locked_alert.save(update_fields=[
                            'triage_status', 'triaged_by', 'triaged_at',
                            'escalated_to_tier', 'claimed_by', 'claimed_at',
                        ])

                    for evidence_file in request.FILES.getlist('evidence_files'):
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

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'containment':
            if not can_submit_containment:
                messages.error(request, 'คุณไม่มีสิทธิ์ดำเนินการนี้')
            else:
                report = request.POST.get('containment_report', '').strip()
                disposition = request.POST.get('disposition', '').strip()
                note = request.POST.get('note', '').strip()

                if not report:
                    messages.error(request, 'กรุณากรอกรายงานการควบคุม')
                elif not disposition:
                    messages.error(request, 'กรุณาระบุการวินิจฉัยเหตุการณ์ (True/False Positive)')
                else:
                    ticket.disposition = disposition
                    ticket.containment_report = report
                    try:
                        ticket.transition_to(
                            Ticket.STATUS_CONTAINMENT_REPORTED,
                            request.user,
                            note or 'ส่งรายงานการควบคุมแล้ว',
                        )
                    except ValidationError as e:
                        messages.error(request, e.message)

        elif action == 'soc_update':
            new_note = request.POST.get('update_notes', '').strip()
            new_status = request.POST.get('status')
            prev_status = ticket.status

            if not new_note:
                messages.error(request, 'กรุณากรอกบันทึกการดำเนินการ')
            elif new_status:
                try:
                    ticket.transition_to(new_status, request.user, new_note)

                    # Notify Security Admin when routed to AWAITING_CONTAINMENT
                    if new_status == Ticket.STATUS_AWAITING_CONTAINMENT:
                        reason = new_note if prev_status == Ticket.STATUS_UNDER_REVIEW else None
                        _notify_containment(ticket, reason, request)

                    # Stage 11 — notify System Owner on closure
                    if new_status in (Ticket.STATUS_APPROVED, Ticket.STATUS_CLOSED_FP):
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
        'DISPOSITION_CHOICES': Ticket.DISPOSITION_CHOICES,
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

    if status_filter in (Ticket.STATUS_APPROVED, Ticket.STATUS_CLOSED_FP):
        query_set = query_set.filter(status=status_filter)

    if severity_filter:
        query_set = query_set.filter(severity=severity_filter)

    if approved_by_filter:
        try:
            query_set = query_set.filter(approved_by_id=int(approved_by_filter))
        except ValueError:
            approved_by_filter = ''

    tickets_qs = query_set.prefetch_related('logs').order_by('-updated_at')

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
        'approved_by_filter': approved_by_filter,
        'approver_choices': approver_choices,
        'start_date': start_date,
        'end_date': end_date,
        'all_time': all_time,
        'severity_choices': Ticket.SEVERITY_CHOICES,
        'approved_count': Ticket.objects.visible_to(request.user).filter(status=Ticket.STATUS_APPROVED).count(),
        'fp_count': Ticket.objects.visible_to(request.user).filter(status=Ticket.STATUS_CLOSED_FP).count(),
    })


# ── Triage views ─────────────────────────────────────────────────────── #

@login_required
def triage_list(request):
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_soc):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่เข้าถึงหน้านี้ได้')
        return redirect('home')

    if request.user.is_superuser:
        my_triages = TriageRecord.objects.all().order_by('-created_at')
        assigned_escalations = TriageRecord.objects.filter(
            decision=TriageRecord.DECISION_ESCALATED,
            ticket__isnull=True,
            t2_decision__in=['', TriageRecord.DECISION_TP],
        ).order_by('-created_at')
    else:
        my_triages = TriageRecord.objects.filter(analyst=request.user).order_by('-created_at')
        assigned_escalations = TriageRecord.objects.filter(
            escalated_to=request.user,
            ticket__isnull=True,
            t2_decision__in=['', TriageRecord.DECISION_TP],
        ).order_by('-created_at')

    return render(request, 'incidents/triage_list.html', {
        'my_triages': my_triages,
        'assigned_escalations': assigned_escalations,
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
        form = TriageForm(request.POST, user=request.user)
        if form.is_valid():
            triage = form.save(commit=False)
            triage.analyst = request.user
            triage.save()

            if triage.decision == TriageRecord.DECISION_TP:
                messages.success(request, 'บันทึก True Positive แล้ว — กรุณาสร้าง Ticket สำหรับกรณีนี้')
                return redirect(f"{reverse('create_ticket')}?triage_id={triage.pk}")
            elif triage.decision == TriageRecord.DECISION_FP:
                messages.success(request, 'บันทึก False Positive เรียบร้อยแล้ว — ไม่จำเป็นต้องสร้าง Ticket')
                return redirect('triage_list')
            else:
                messages.success(request, f'Escalate ไปยัง T2 เรียบร้อยแล้ว')
                return redirect('triage_list')
    else:
        form = TriageForm(user=request.user)

    return render(request, 'incidents/triage_form.html', {'form': form})


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
        'sla_breaches':   active_qs.filter(sla_deadline__lt=timezone.now()).count(),
    }

    recent_tickets = active_qs.order_by('-created_at')[:10]
    closed_tickets = closed_qs.order_by('-updated_at')[:10]

    return render(request, 'incidents/system_owner_dashboard.html', {
        'stats':          stats,
        'recent_tickets': recent_tickets,
        'closed_tickets': closed_tickets,
        'profile':        profile,
        'is_superuser_view': request.user.is_superuser,
    })


@login_required
def respond_escalation(request, triage_id):
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (
        profile is None
        or not profile.is_soc_staff
        or profile.tier != profile.TIER_T2
    ):
        return redirect('home')

    triage_qs = TriageRecord.objects.all()
    if not request.user.is_superuser:
        triage_qs = triage_qs.filter(escalated_to=request.user)
    triage = get_object_or_404(triage_qs, pk=triage_id)
    if triage.t2_decision:
        messages.error(request, 'This escalation has already been decided.')
        return redirect('triage_list')

    if request.method == 'POST':
        t2_decision = request.POST.get('t2_decision')
        t2_notes = request.POST.get('t2_notes', '').strip()

        if t2_decision not in [TriageRecord.DECISION_FP, TriageRecord.DECISION_TP]:
            messages.error(request, 'กรุณาเลือกการตัดสินใจ')
        elif not t2_notes:
            messages.error(request, 'A decision note is required.')
        else:
            with transaction.atomic():
                locked_qs = TriageRecord.objects.select_for_update().filter(
                    pk=triage_id, t2_decision='',
                )
                if not request.user.is_superuser:
                    locked_qs = locked_qs.filter(escalated_to=request.user)
                triage = get_object_or_404(locked_qs)
                triage.t2_decision = t2_decision
                triage.t2_notes = t2_notes
                triage.t2_decided_at = timezone.now()
                triage.save(update_fields=['t2_decision', 't2_notes', 't2_decided_at'])

            if t2_decision == TriageRecord.DECISION_TP:
                messages.success(request, 'T2 ยืนยัน True Positive — กรุณาสร้าง Ticket')
                return redirect(f"{reverse('create_ticket')}?triage_id={triage.pk}")
            else:
                messages.success(request, 'T2 ยืนยัน False Positive — บันทึกเรียบร้อย ไม่จำเป็นต้องสร้าง Ticket')
                return redirect('triage_list')

    return render(request, 'incidents/respond_escalation.html', {'triage': triage})
