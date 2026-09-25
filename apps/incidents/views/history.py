import calendar
import logging
from types import SimpleNamespace

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.db.models import Count, F, IntegerField, OuterRef, Q, Subquery
from django.db.models.functions import Coalesce
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from ..models import (
    Ticket,
    TicketLog, TicketLogRevision,
)
from ._helpers import (
    _apply_date_range,
    _bulk_export_context,
    _by,
    _choice_label_expr,
    _column_sort_headers,
    _person_name_expr,
    _status_order_expr,
    _ticket_name_expr,
    _date_presets,
    _date_range_label,
    _date_range_params,
    _filter_chip,
    _int_param,
    _ticket_search_q,
)

logger = logging.getLogger('apps.incidents.views')


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


def _with_closer(qs):
    """Annotate ``closer_id``: who closed each terminal ticket.

    approved_by is stamped only on the Incident path into APPROVED, so an Event
    close or a cancellation leaves it blank. The timeline carries the same fact:
    the first CLOSED_EVENT row is the Tier 2 / manager close (the same row
    selectors.get_closed_event_signoff reads) and the first CANCELLED row is the
    manager who decided the cancellation.
    """
    first_terminal_author = Subquery(
        TicketLog.objects.filter(
            ticket_id=OuterRef('pk'),
            status_at_time__in=list(Ticket.TERMINAL_STATUSES),
        ).order_by('created_at', 'pk').values('author_id')[:1]
    )
    return qs.annotate(closer_id=Coalesce(
        'approved_by_id', first_terminal_author, output_field=IntegerField(),
    ))


# Table columns in cell order: (label, first-click sort, second-click sort,
# first click ascending?, th class) — see _helpers._column_sort_headers. The
# free-text columns (description, latest log note) aren't sortable.
HISTORY_COLUMNS = (
    ('เลขที่เคส', '-id', 'id', False, 'ps-4'),
    ('ชื่อเรื่อง', 'name', '-name', True, ''),
    ('รายละเอียดเหตุการณ์', None, None, True, ''),
    ('ความรุนแรง', 'severity', 'severity_asc', False, ''),
    ('ประเภท', 'classification', '-classification', True, ''),
    ('การแก้ไขล่าสุด', None, None, True, ''),
    ('วันที่ปิด', 'closed', 'closed_oldest', False, ''),
    ('สถานะ', 'status', '-status', True, ''),
    ('ผู้อนุมัติ/ปิดเคส', 'closer', '-closer', True, ''),
    ('', None, None, True, ''),
)
HISTORY_SORT_OPTIONS = (
    ('closed', 'ปิดล่าสุดก่อน'),
    ('closed_oldest', 'ปิดเก่าสุดก่อน'),
    ('emergency', 'Emergency ก่อน'),
    ('severity', 'ความรุนแรง'),
)


# (status code, pill label, status_counts key) — in display order.
HISTORY_STATUS_PILLS = (
    ('', 'ทั้งหมด', 'all'),
    (Ticket.STATUS_APPROVED, 'อนุมัติแล้ว', 'approved'),
    (Ticket.STATUS_CLOSED_EVENT, 'Event', 'event'),
    (Ticket.STATUS_CANCELLED, 'ยกเลิกแล้ว', 'cancelled'),
)


def _filter_history(request, params):
    """The closed-ticket list, filtered and sorted from `params`.

    Shared by the page (params = request.GET) and the bulk report export
    (params = the page's querystring, re-posted), so the ZIP holds exactly the
    tickets the page shows. Returns a namespace: `qs` plus the validated filter
    state and the result-pill counts the page renders.
    """
    terminal = Ticket.objects.visible_to(request.user).filter(
        status__in=list(Ticket.TERMINAL_STATUSES)
    )
    query_set = _with_closer(terminal).annotate(
        close_date=Coalesce('closed_at', 'approved_at'),
    )

    # `q` matches Active Tickets; `search_ticket` is the old name, still read
    # so existing links and bookmarks keep working.
    search = (params.get('q') or params.get('search_ticket') or '').strip()
    status_filter = params.get('status', '').strip()
    severity_filter = params.get('severity', '').strip()
    classification_filter = params.get('classification', '').strip()
    emergency_filter = params.get('emergency', '').strip()
    sort = params.get('sort', 'closed').strip()
    approved_by_filter = params.get('approved_by', '').strip()
    all_time = params.get('all_time', '').strip()
    start_date, end_date, start_date_obj, end_date_obj = _date_range_params(params)
    # The date inputs echo only what the user chose, not the implied default
    # month — otherwise the next filter change would pin that month explicitly.
    date_input_start, date_input_end = start_date, end_date
    is_default_month = not start_date and not end_date and not all_time

    if is_default_month:
        # The current month by opening date, in local (Bangkok) time. Computing
        # it from UTC dropped tickets opened 00:00–06:59 on the 1st and, before
        # 07:00 on the 1st, showed the previous month altogether.
        today = timezone.localdate()
        start_date_obj = today.replace(day=1)
        end_date_obj = today.replace(
            day=calendar.monthrange(today.year, today.month)[1])
        start_date = start_date_obj.isoformat()
        end_date = end_date_obj.isoformat()
    # A lone From or To date bounds one side (it used to be ignored entirely).
    query_set = _apply_date_range(query_set, 'created_at', start_date_obj, end_date_obj)

    if search:
        query_set = query_set.filter(_ticket_search_q(search))

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

    closer_pk = _int_param(approved_by_filter)
    if closer_pk:
        query_set = query_set.filter(closer_id=closer_pk)
    else:
        approved_by_filter = ''

    # Pill counts follow every filter except the result pill itself, so each
    # pill says how many rows clicking it would show.
    status_counts = query_set.aggregate(
        all=Count('pk'),
        approved=Count('pk', filter=Q(status=Ticket.STATUS_APPROVED)),
        event=Count('pk', filter=Q(status=Ticket.STATUS_CLOSED_EVENT)),
        cancelled=Count('pk', filter=Q(status=Ticket.STATUS_CANCELLED)),
    )
    status_pills = [
        {'code': code, 'label': label, 'count': status_counts[key]}
        for code, label, key in HISTORY_STATUS_PILLS
    ]

    if status_filter in Ticket.TERMINAL_STATUSES:
        query_set = query_set.filter(status=status_filter)
    else:
        status_filter = ''

    # Every option orders by a column the table shows, ending on the close
    # date then -pk so ties stay stable across pages. Legacy rows with no close
    # date go last either way (Postgres puts NULL first on DESC).
    newest_close = F('close_date').desc(nulls_last=True)
    tie = (newest_close, '-pk')
    closer_name = Subquery(
        User.objects.filter(pk=OuterRef('closer_id'))
        .annotate(sort_name=_person_name_expr()).values('sort_name')[:1]
    )
    sort_map = {
        # Dropdown presets.
        'closed': tie,
        'closed_oldest': (F('close_date').asc(nulls_last=True), 'pk'),
        'emergency': ('-is_emergency', *tie),
        # -sev_rank, NOT 'severity': the raw CharField sorts alphabetically.
        'severity': ('-sev_rank', *tie),
        # Column headers (HISTORY_COLUMNS).
        '-id': ('-ticket_id', '-pk'),
        'id': ('ticket_id', 'pk'),
        'name': (_by(_ticket_name_expr()), *tie),
        '-name': (_by(_ticket_name_expr(), descending=True), *tie),
        'severity_asc': ('sev_rank', *tie),
        'classification': (_by(_choice_label_expr('classification')), *tie),
        '-classification': (_by(_choice_label_expr('classification'), descending=True), *tie),
        'status': (_status_order_expr(), *tie),
        '-status': (_status_order_expr().desc(), *tie),
        'closer': (_by(closer_name), *tie),
        '-closer': (_by(closer_name, descending=True), *tie),
    }
    if sort not in sort_map:
        sort = 'closed'
    if sort in ('severity', 'severity_asc'):
        query_set = query_set.with_severity_rank()
    return SimpleNamespace(
        qs=query_set.order_by(*sort_map[sort]), terminal=terminal,
        search=search, status_filter=status_filter, status_pills=status_pills,
        severity_filter=severity_filter, classification_filter=classification_filter,
        emergency_filter=emergency_filter, sort=sort,
        approved_by_filter=approved_by_filter, closer_pk=closer_pk, all_time=all_time,
        start_date=start_date, end_date=end_date,
        date_input_start=date_input_start, date_input_end=date_input_end,
        is_default_month=is_default_month,
    )


@login_required
def ticket_history(request):
    f = _filter_history(request, request.GET)
    terminal, search, status_filter = f.terminal, f.search, f.status_filter
    status_pills, severity_filter = f.status_pills, f.severity_filter
    classification_filter, emergency_filter, sort = (
        f.classification_filter, f.emergency_filter, f.sort)
    approved_by_filter, closer_pk, all_time = f.approved_by_filter, f.closer_pk, f.all_time
    start_date, end_date = f.start_date, f.end_date
    date_input_start, date_input_end = f.date_input_start, f.date_input_end
    is_default_month = f.is_default_month
    tickets_qs = f.qs.select_related('project_incident').prefetch_related('logs')

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))
    # One lookup for the page's closers instead of a query per row.
    page_obj.object_list = list(page_obj.object_list)
    closers = User.objects.in_bulk(
        {ticket.closer_id for ticket in page_obj.object_list if ticket.closer_id}
    )
    for ticket in page_obj.object_list:
        ticket.closer = closers.get(ticket.closer_id)

    # Only people who closed a ticket this viewer can see.
    approver_choices = (
        User.objects.filter(pk__in=_with_closer(terminal).values('closer_id'))
        .order_by('first_name', 'username')
    )

    date_presets = _date_presets(start_date, end_date)
    date_label = _date_range_label(start_date, end_date, date_presets)
    # One chip per active filter. The result pills already show the status, so
    # it has no chip. Removing a date range means "all time", not the default
    # month, so the chip sets all_time.
    filter_chips = []
    if search:
        filter_chips.append(_filter_chip(request, f'ค้นหา: “{search}”', ('q', 'search_ticket')))
    if severity_filter:
        filter_chips.append(_filter_chip(
            request, f'ความรุนแรง: {dict(Ticket.SEVERITY_CHOICES)[severity_filter]}', ('severity',)))
    if closer_pk:
        closer = User.objects.filter(pk=closer_pk).first()
        closer_name = (closer.get_full_name() or closer.username) if closer else closer_pk
        filter_chips.append(_filter_chip(
            request, f'ผู้อนุมัติ/ปิดเคส: {closer_name}', ('approved_by',)))
    if date_label:
        filter_chips.append(_filter_chip(
            request, f'วันที่แจ้ง: {date_label}', ('start_date', 'end_date'),
            set_params={'all_time': '1'}, is_default=is_default_month))
    if classification_filter:
        filter_chips.append(_filter_chip(
            request, f'ประเภท: {dict(Ticket.CLASSIFICATION_CHOICES)[classification_filter]}',
            ('classification',)))
    if emergency_filter:
        filter_chips.append(_filter_chip(
            request, 'เฉพาะเคสฉุกเฉิน' if emergency_filter == '1' else 'เฉพาะเคสปกติ',
            ('emergency',)))

    return render(request, 'incidents/ticket_history.html', {
        'page_obj': page_obj,
        'tickets': page_obj,
        'result_count': paginator.count,
        'search': search,
        'status_filter': status_filter,
        'status_pills': status_pills,
        'severity_filter': severity_filter,
        'classification_filter': classification_filter,
        'emergency_filter': emergency_filter,
        'sort': sort,
        'approved_by_filter': approved_by_filter,
        'approver_choices': approver_choices,
        'start_date': start_date,
        'end_date': end_date,
        'date_input_start': date_input_start,
        'date_input_end': date_input_end,
        'all_time': all_time,
        'date_presets': date_presets,
        'date_label': date_label,
        # The implied current month isn't a choice the user made, so the
        # control isn't highlighted for it; "ทุกช่วงเวลา" is the empty option.
        'date_is_set': bool(date_label) and not is_default_month,
        'date_is_empty': bool(all_time) and not start_date and not end_date,
        'filter_chips': filter_chips,
        # "Clear all" returns to the default view (current month, every result);
        # it has nothing to do when that's what is already showing.
        'has_clearable_filters': bool(
            status_filter or all_time
            or any(not chip['is_default'] for chip in filter_chips)),
        'more_filter_count': sum(bool(value) for value in (
            classification_filter, emergency_filter)),
        **_bulk_export_context(request, reverse('ticket_history_reports_pdf')),
        'sort_options': HISTORY_SORT_OPTIONS,
        'sort_headers': _column_sort_headers(HISTORY_COLUMNS, sort),
        'sort_is_from_column': sort not in dict(HISTORY_SORT_OPTIONS),
        'severity_choices': Ticket.SEVERITY_CHOICES,
        'classification_choices': Ticket.CLASSIFICATION_CHOICES,
    })
