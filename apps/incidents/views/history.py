import calendar
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_date

from ..models import (
    Ticket,
    TicketLog, TicketLogRevision,
)

logger = logging.getLogger('apps.incidents.views')


def _parse_date_param(value):
    """A YYYY-MM-DD query value as a date, or None when blank or malformed."""
    try:
        return parse_date(value) if value else None
    except ValueError:  # well-formed but impossible, e.g. 2026-02-31
        return None


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
    classification_filter = request.GET.get('classification', '').strip()
    emergency_filter = request.GET.get('emergency', '').strip()
    sort = request.GET.get('sort', 'newest').strip()
    approved_by_filter = request.GET.get('approved_by', '').strip()
    start_date = request.GET.get('start_date', '').strip()
    end_date = request.GET.get('end_date', '').strip()
    all_time = request.GET.get('all_time', '').strip()

    # A hand-edited or truncated date must not 500 the page: an unparseable
    # value is treated as absent, like the other filters below.
    start_date_obj = _parse_date_param(start_date)
    end_date_obj = _parse_date_param(end_date)
    if start_date and start_date_obj is None:
        start_date = ''
    if end_date and end_date_obj is None:
        end_date = ''

    if not start_date and not end_date and not all_time:
        # The current month in local (Bangkok) time. timezone.now() is UTC, so
        # using it here dropped tickets opened 00:00–06:59 on the 1st and, before
        # 07:00 on the 1st, showed the previous month altogether.
        today = timezone.localtime()
        start_date_obj = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_day = calendar.monthrange(today.year, today.month)[1]
        end_date_obj = today.replace(day=last_day, hour=23, minute=59, second=59, microsecond=999999)
        query_set = query_set.filter(created_at__range=[start_date_obj, end_date_obj])
        start_date = start_date_obj.strftime('%Y-%m-%d')
        end_date = end_date_obj.strftime('%Y-%m-%d')
    elif start_date and end_date:
        query_set = query_set.filter(created_at__date__range=[start_date_obj, end_date_obj])

    if search_ticket:
        query_set = query_set.filter(ticket_id__icontains=search_ticket)

    if status_filter in Ticket.TERMINAL_STATUSES:
        query_set = query_set.filter(status=status_filter)

    if severity_filter in dict(Ticket.SEVERITY_CHOICES):
        query_set = query_set.filter(severity=severity_filter)
    else:
        severity_filter = ''

    if classification_filter in dict(Ticket.CLASSIFICATION_CHOICES):
        query_set = query_set.filter(classification=classification_filter)
    else:
        classification_filter = ''

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
        'classification_filter': classification_filter,
        'emergency_filter': emergency_filter,
        'sort': sort,
        'approved_by_filter': approved_by_filter,
        'approver_choices': approver_choices,
        'start_date': start_date,
        'end_date': end_date,
        'all_time': all_time,
        'severity_choices': Ticket.SEVERITY_CHOICES,
        'classification_choices': Ticket.CLASSIFICATION_CHOICES,
        'approved_count': Ticket.objects.visible_to(request.user).filter(status=Ticket.STATUS_APPROVED).count(),
        'event_count': Ticket.objects.visible_to(request.user).filter(status=Ticket.STATUS_CLOSED_EVENT).count(),
    })
