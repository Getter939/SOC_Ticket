import calendar
import openpyxl
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.db.models import Count

from .forms import TicketForm
from .models import Ticket, TicketLog


def _valid_status_choices(ticket):
    allowed = [ticket.status] + Ticket.ALLOWED_TRANSITIONS.get(ticket.status, [])
    return [(code, label) for code, label in Ticket.STATUS_CHOICES if code in allowed]


@login_required
def ticket_list(request):
    tickets = Ticket.objects.exclude(status__in=['Resolved', 'Closed']).order_by('created_at')
    sla_breach_count = Ticket.objects.filter(
        sla_deadline__lt=timezone.now()
    ).exclude(status__in=['Resolved', 'Closed']).count()
    return render(request, 'incidents/ticket_list.html', {
        'tickets': tickets,
        'sla_breach_count': sla_breach_count,
    })


@login_required
def create_ticket(request):
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
    ticket = get_object_or_404(Ticket, pk=pk)

    if request.method == 'POST':
        new_note = request.POST.get('update_notes', '').strip()
        new_status = request.POST.get('status')

        if new_note and new_status:
            try:
                ticket.transition_to(new_status, request.user, new_note)
            except ValidationError as e:
                messages.error(request, e.message)
                logs = ticket.logs.all()
                return render(request, 'incidents/ticket_detail.html', {
                    'ticket': ticket,
                    'logs': logs,
                    'valid_status_choices': _valid_status_choices(ticket),
                })

        return redirect('ticket_detail', pk=pk)

    logs = ticket.logs.all()
    return render(request, 'incidents/ticket_detail.html', {
        'ticket': ticket,
        'logs': logs,
        'valid_status_choices': _valid_status_choices(ticket),
    })


@login_required
def edit_log(request, log_id):
    log = get_object_or_404(TicketLog, id=log_id)
    ticket_id = log.ticket.id

    if request.method == 'POST':
        log.note = request.POST.get('note')
        log.save()
        return redirect('ticket_detail', pk=ticket_id)

    return render(request, 'incidents/edit_log.html', {'log': log})


@login_required
def ticket_history(request):
    query_set = Ticket.objects.filter(status__in=['Resolved', 'Closed'])

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

    tickets = Ticket.objects.filter(status__in=['Resolved', 'Closed']).distinct()

    for ticket in tickets:
        last_log = ticket.logs.order_by('-created_at').first()
        repair_detail = last_log.note if last_log else "ไม่มีข้อมูลบันทึก"
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

    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=ticket_history.xlsx'
    wb.save(response)
    return response
