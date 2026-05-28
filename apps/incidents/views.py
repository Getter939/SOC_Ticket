import calendar
import openpyxl
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import TicketForm
from .models import Ticket, TicketLog
from .notifications import notify_containment_required


# ── Private view helpers ─────────────────────────────────────────────────── #

def _valid_soc_status_choices(ticket, user):
    """
    Return (code, label) choices for the SOC update-status dropdown.

    Rules:
    - Returns [] if the user is not SOC (staff or manager).
    - Always includes the current status first (SOC note-only update).
    - Includes each allowed next-state whose required permission is 'SOC'.
    - Also includes 'MANAGER' states if the user is a SOC manager.
    - Never includes 'ASSIGNED_ADMIN' transitions — those are handled by
      the separate containment-report form.
    """
    profile = getattr(user, 'profile', None)
    if profile is None or not profile.is_soc:
        return []

    status_map = dict(Ticket.STATUS_CHOICES)

    # Current status first (allows note-only update without state change)
    result = [(ticket.status, status_map.get(ticket.status, ticket.status))]

    for next_status in Ticket.ALLOWED_TRANSITIONS.get(ticket.status, []):
        perm = Ticket.TRANSITION_PERMISSIONS.get((ticket.status, next_status))
        if perm == 'SOC':
            result.append((next_status, status_map.get(next_status, next_status)))
        elif perm == 'MANAGER' and profile.is_soc_manager:
            result.append((next_status, status_map.get(next_status, next_status)))

    return result


def _notify_containment(ticket, reason, request):
    """
    Non-fatal wrapper around notify_containment_required.

    Sends the email after a successful transition to AWAITING_CONTAINMENT.
    Attaches a messages.warning to the request if delivery is skipped or
    fails — the transition has already been committed, so we never roll it
    back over an email problem.

    reason — None for initial routing (NEW → AWAITING_CONTAINMENT);
             the analyst's note for the rejection loop
             (UNDER_REVIEW → AWAITING_CONTAINMENT).
    """
    if not ticket.assigned_admin_id:
        messages.warning(
            request,
            'Ticket routed — ไม่สามารถส่งอีเมลแจ้งเตือนได้: '
            'ยังไม่ได้กำหนดผู้ดูแลระบบ',
        )
        return

    # Accessing .email requires a DB hit if the FK isn't cached; that's fine —
    # we already know assigned_admin_id is set.
    admin = ticket.assigned_admin
    if not admin.email:
        messages.warning(
            request,
            f'Ticket routed — ไม่สามารถส่งอีเมลแจ้งเตือนได้: '
            f'{admin.get_full_name() or admin.username} ไม่มีที่อยู่อีเมล',
        )
        return

    sent = notify_containment_required(ticket, reason=reason)
    if not sent:
        messages.warning(
            request,
            'Ticket routed แต่ส่งอีเมลแจ้งเตือนไม่สำเร็จ — '
            'โปรดแจ้งผู้ดูแลระบบด้วยตนเอง',
        )


# ── Views ────────────────────────────────────────────────────────────────── #

@login_required
def ticket_list(request):
    visible = Ticket.objects.visible_to(request.user)
    tickets = visible.exclude(
        status__in=list(Ticket.TERMINAL_STATUSES)
    ).order_by('created_at')
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

    if request.method == 'POST':
        form = TicketForm(request.POST)
        if form.is_valid():
            ticket = form.save(commit=False)
            ticket.created_by = request.user
            ticket.save()
            return redirect('ticket_detail', pk=ticket.pk)
    else:
        form = TicketForm()
    return render(request, 'incidents/ticket_form.html', {'form': form})


@login_required
def ticket_detail(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    profile = getattr(request.user, 'profile', None)
    is_terminal = ticket.status in Ticket.TERMINAL_STATUSES

    # Only the exact assigned admin can submit the containment form, and
    # only while the ticket is in AWAITING_CONTAINMENT.
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
                    # Set fields on the instance BEFORE calling transition_to so
                    # that transition_to's self.save() persists them atomically.
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
            # Capture before transition so we know which leg triggered the
            # AWAITING_CONTAINMENT state (initial dispatch vs rejection loop).
            prev_status = ticket.status

            if not new_note:
                messages.error(request, 'กรุณากรอกบันทึกการดำเนินการ')
            elif new_status:
                try:
                    ticket.transition_to(new_status, request.user, new_note)

                    # ── Email notification ───────────────────────────────── #
                    # Only triggered when the ticket lands on AWAITING_CONTAINMENT.
                    # Rejection loop (UNDER_REVIEW → AWAITING_CONTAINMENT) passes
                    # the analyst's note as 'reason' so the admin knows what to fix.
                    # Email failure is non-fatal: transition is already committed.
                    if new_status == Ticket.STATUS_AWAITING_CONTAINMENT:
                        reason = (
                            new_note
                            if prev_status == Ticket.STATUS_UNDER_REVIEW
                            else None
                        )
                        _notify_containment(ticket, reason, request)

                except ValidationError as e:
                    messages.error(request, e.message)

        return redirect('ticket_detail', pk=pk)

    logs = ticket.logs.all()
    valid_status_choices = _valid_soc_status_choices(ticket, request.user)

    return render(request, 'incidents/ticket_detail.html', {
        'ticket': ticket,
        'logs': logs,
        'profile': profile,
        'is_terminal': is_terminal,
        'can_submit_containment': can_submit_containment,
        'valid_status_choices': valid_status_choices,
        'DISPOSITION_CHOICES': Ticket.DISPOSITION_CHOICES,
    })


@login_required
def edit_log(request, log_id):
    log = get_object_or_404(TicketLog, id=log_id)
    # Enforce visibility on the parent ticket — 404 here means the user
    # can reach the log URL but cannot see the ticket it belongs to.
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

    context = {
        'tickets': tickets,
        'search_ticket': search_ticket,
        'start_date': start_date,
        'end_date': end_date,
    }
    return render(request, 'incidents/ticket_history.html', context)


@login_required
def export_tickets_excel(request):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Ticket History"

    columns = ['Ticket', 'IP Source', 'รายละเอียด', 'การแก้ไข (ล่าสุด)', 'วันที่แจ้ง', 'วันที่แก้ไขเสร็จ']
    ws.append(columns)

    tickets = Ticket.objects.visible_to(request.user).filter(
        status__in=list(Ticket.TERMINAL_STATUSES)
    ).distinct()

    for ticket in tickets:
        last_log = ticket.logs.order_by('-created_at').first()
        repair_detail = last_log.note if last_log else 'ไม่มีข้อมูลบันทึก'
        row = [
            ticket.ticket_id,
            ticket.device_name,
            ticket.issue_description,
            repair_detail,
            ticket.created_at.strftime('%d/%m/%Y %H:%M'),
            ticket.updated_at.strftime('%d/%m/%Y %H:%M'),
        ]
        ws.append(row)

    for col in ws.columns:
        max_length = max((len(str(cell.value)) for cell in col if cell.value), default=0)
        ws.column_dimensions[col[0].column_letter].width = max_length + 2

    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = 'attachment; filename=ticket_history.xlsx'
    wb.save(response)
    return response
