import calendar
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import AttachmentForm, TicketForm, TriageForm
from .models import Ticket, TicketAttachment, TicketLog, TriageRecord
from .notifications import (
    notify_containment_required,
    notify_system_owner_created,
    notify_system_owner_closed,
)


# ── Private helpers ──────────────────────────────────────────────────── #

def _valid_soc_status_choices(ticket, user):
    profile = getattr(user, 'profile', None)
    if profile is None or not profile.is_soc:
        return []

    status_map = dict(Ticket.STATUS_CHOICES)
    result = [(ticket.status, status_map.get(ticket.status, ticket.status))]

    for next_status in Ticket.ALLOWED_TRANSITIONS.get(ticket.status, []):
        perm = Ticket.TRANSITION_PERMISSIONS.get((ticket.status, next_status))
        if perm == 'SOC':
            result.append((next_status, status_map.get(next_status, next_status)))
        elif perm == 'MANAGER' and profile.is_soc_manager:
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

@login_required
def ticket_list(request):
    visible = Ticket.objects.visible_to(request.user)
    tickets = visible.exclude(status__in=list(Ticket.TERMINAL_STATUSES)).order_by('created_at')
    sla_breach_count = visible.filter(
        sla_deadline__lt=timezone.now()
    ).exclude(status__in=list(Ticket.TERMINAL_STATUSES)).count()
    return render(request, 'incidents/ticket_list.html', {
        'tickets': tickets,
        'sla_breach_count': sla_breach_count,
    })


@login_required
def create_ticket(request):
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเปิดเคสใหม่ได้')
        return redirect('ticket_list')

    # Pre-fill from triage if coming from a TP triage decision
    triage = None
    triage_id = request.GET.get('triage_id') or request.POST.get('triage_id')
    if triage_id:
        try:
            triage = TriageRecord.objects.get(pk=triage_id)
        except TriageRecord.DoesNotExist:
            pass

    if request.method == 'POST':
        form = TicketForm(request.POST)
        if form.is_valid():
            ticket = form.save(commit=False)
            ticket.created_by = request.user
            ticket.save()

            # Link triage record if present
            if triage and not triage.ticket:
                triage.ticket = ticket
                triage.save(update_fields=['ticket'])

            # Stage 5 — notify System Owner
            if ticket.system_owner and ticket.system_owner.email:
                if not notify_system_owner_created(ticket):
                    messages.warning(request, 'Ticket สร้างแล้ว แต่ส่งอีเมลแจ้ง System Owner ไม่สำเร็จ')

            return redirect('ticket_detail', pk=ticket.pk)
    else:
        initial = {}
        if triage:
            initial['device_name'] = triage.source_ip
            initial['issue_description'] = triage.alert_description
        form = TicketForm(initial=initial)

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
        and profile is not None
        and profile.is_system_admin
        and ticket.assigned_admin_id == request.user.pk
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
    })


@login_required
def edit_log(request, log_id):
    log = get_object_or_404(TicketLog, id=log_id)
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=log.ticket_id)
    ticket_id = log.ticket.id

    if request.method == 'POST':
        log.note = request.POST.get('note')
        log.save()
        return redirect('ticket_detail', pk=ticket_id)

    return render(request, 'incidents/edit_log.html', {'log': log})


@login_required
def ticket_history(request):
    query_set = Ticket.objects.visible_to(request.user).filter(
        status__in=list(Ticket.TERMINAL_STATUSES)
    )

    search_ticket = request.GET.get('search_ticket')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    if not start_date and not end_date:
        today = timezone.now()
        start_date_obj = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_day = calendar.monthrange(today.year, today.month)[1]
        end_date_obj = today.replace(day=last_day, hour=23, minute=59, second=59, microsecond=999999)
        query_set = query_set.filter(created_at__range=[start_date_obj, end_date_obj])
        start_date = start_date_obj.strftime('%Y-%m-%d')
        end_date = end_date_obj.strftime('%Y-%m-%d')
    else:
        if start_date and end_date:
            query_set = query_set.filter(created_at__date__range=[start_date, end_date])

    if search_ticket:
        query_set = query_set.filter(ticket_id__icontains=search_ticket)

    tickets = query_set.prefetch_related('logs').order_by('-updated_at')

    return render(request, 'incidents/ticket_history.html', {
        'tickets': tickets,
        'search_ticket': search_ticket,
        'start_date': start_date,
        'end_date': end_date,
    })


# ── Triage views ─────────────────────────────────────────────────────── #

@login_required
def triage_list(request):
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่เข้าถึงหน้านี้ได้')
        return redirect('home')

    my_triages = TriageRecord.objects.filter(analyst=request.user).order_by('-created_at')
    pending_escalations = TriageRecord.objects.filter(
        escalated_to=request.user, t2_decision=''
    ).order_by('-created_at')

    return render(request, 'incidents/triage_list.html', {
        'my_triages': my_triages,
        'pending_escalations': pending_escalations,
    })


@login_required
def create_triage(request):
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถ Triage ได้')
        return redirect('home')

    if request.method == 'POST':
        form = TriageForm(request.POST)
        if form.is_valid():
            triage = form.save(commit=False)
            triage.analyst = request.user
            triage.save()

            if triage.decision == TriageRecord.DECISION_TP:
                messages.success(request, 'บันทึก True Positive แล้ว — กรุณาสร้าง Ticket สำหรับกรณีนี้')
                return redirect(f"{__import__('django.urls', fromlist=['reverse']).reverse('create_ticket')}?triage_id={triage.pk}")
            elif triage.decision == TriageRecord.DECISION_FP:
                messages.success(request, 'บันทึก False Positive เรียบร้อยแล้ว — ไม่จำเป็นต้องสร้าง Ticket')
                return redirect('triage_list')
            else:
                messages.success(request, f'Escalate ไปยัง T2 เรียบร้อยแล้ว')
                return redirect('triage_list')
    else:
        form = TriageForm()

    return render(request, 'incidents/triage_form.html', {'form': form})


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
    can_delete = (profile and profile.is_soc) or (att.uploaded_by == request.user)
    if request.method == 'POST' and can_delete:
        att.file.delete(save=False)
        att.delete()
        messages.success(request, 'ลบไฟล์เรียบร้อยแล้ว')
    return redirect('ticket_detail', pk=ticket.pk)


# ── System Owner dashboard ────────────────────────────────────────────── #

@login_required
def system_owner_dashboard(request):
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_system_owner:
        return redirect('home')

    my_tickets = Ticket.objects.filter(system_owner=request.user)
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
    })


@login_required
def respond_escalation(request, triage_id):
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        return redirect('home')

    triage = get_object_or_404(TriageRecord, pk=triage_id, escalated_to=request.user)

    if request.method == 'POST':
        t2_decision = request.POST.get('t2_decision')
        t2_notes = request.POST.get('t2_notes', '').strip()

        if t2_decision not in [TriageRecord.DECISION_FP, TriageRecord.DECISION_TP]:
            messages.error(request, 'กรุณาเลือกการตัดสินใจ')
        else:
            triage.t2_decision = t2_decision
            triage.t2_notes = t2_notes
            triage.t2_decided_at = timezone.now()
            triage.save()

            if t2_decision == TriageRecord.DECISION_TP:
                messages.success(request, 'T2 ยืนยัน True Positive — กรุณาสร้าง Ticket')
                from django.urls import reverse
                return redirect(f"{reverse('create_ticket')}?triage_id={triage.pk}")
            else:
                messages.success(request, 'T2 ยืนยัน False Positive — บันทึกเรียบร้อย ไม่จำเป็นต้องสร้าง Ticket')
                return redirect('triage_list')

    return render(request, 'incidents/respond_escalation.html', {'triage': triage})
