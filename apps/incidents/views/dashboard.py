import logging

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import redirect, render
from django.utils import timezone

from ..models import (
    Ticket,
)
from ._helpers import (
    _by,
    _column_sort_headers,
    _filter_chip,
    _status_order_expr,
    _ticket_name_expr,
    _ticket_search_q,
)

logger = logging.getLogger('apps.incidents.views')


# ── System Owner dashboard ────────────────────────────────────────────── #

# The open-cases list: (label, first-click sort, second-click sort, first click
# ascending?, th class) — see _helpers._column_sort_headers.
OWNER_COLUMNS = (
    ('เลขที่เคส', '-id', 'id', False, 'ps-4'),
    ('ชื่อเรื่อง', 'name', '-name', True, ''),
    ('ความรุนแรง', 'severity', 'severity_asc', False, ''),
    ('สถานะ', 'status', '-status', True, ''),
    ('วันที่แจ้ง', 'newest', 'oldest', False, ''),
)
OWNER_SORT_OPTIONS = (
    ('newest', 'ล่าสุด'),
    ('emergency', 'Emergency ก่อน'),
)


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
    # The stat cards describe everything the owner has, before any filter.
    now = timezone.now()
    stats = {
        'total':          my_tickets.count(),
        'active':         active_qs.count(),
        'closed':         closed_qs.count(),
        'ola_breaches':   active_qs.filter(ola_contain_deadline__lt=now).count(),
    }

    # The open cases are a full, paged list — it used to stop at the newest 10,
    # so an owner with more open cases could not reach the rest. The filter bar
    # and headers are the same as every other ticket list.
    search = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '').strip()
    emergency_filter = request.GET.get('emergency', '').strip()
    sort = request.GET.get('sort', 'newest').strip()

    open_status_choices = [
        (code, label) for code, label in Ticket.STATUS_CHOICES if code not in terminal
    ]
    open_list = active_qs.with_severity_rank()
    if search:
        open_list = open_list.filter(_ticket_search_q(search))
    if status_filter in dict(open_status_choices):
        open_list = open_list.filter(status=status_filter)
    else:
        status_filter = ''
    if emergency_filter in ('1', '0'):
        open_list = open_list.filter(is_emergency=emergency_filter == '1')
    else:
        emergency_filter = ''

    tie = ('-created_at', '-pk')
    sort_map = {
        'newest': tie,
        'oldest': ('created_at', 'pk'),
        'emergency': ('-is_emergency', *tie),
        '-id': ('-ticket_id', '-pk'),
        'id': ('ticket_id', 'pk'),
        'name': (_by(_ticket_name_expr()), *tie),
        '-name': (_by(_ticket_name_expr(), descending=True), *tie),
        'severity': ('-sev_rank', *tie),
        'severity_asc': ('sev_rank', *tie),
        'status': (_status_order_expr(), *tie),
        '-status': (_status_order_expr().desc(), *tie),
    }
    if sort not in sort_map:
        sort = 'newest'
    paginator = Paginator(open_list.order_by(*sort_map[sort]), 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    # The latest-closed panel stays a short "recently finished" list; the bar
    # above belongs to the open cases.
    closed_tickets = closed_qs.order_by('-updated_at')[:10]

    filter_chips = []
    if search:
        filter_chips.append(_filter_chip(request, f'ค้นหา: “{search}”', ('q',)))
    if status_filter:
        filter_chips.append(_filter_chip(
            request, f'สถานะ: {dict(open_status_choices)[status_filter]}', ('status',)))
    if emergency_filter:
        filter_chips.append(_filter_chip(
            request, 'เฉพาะเคสฉุกเฉิน' if emergency_filter == '1' else 'เฉพาะเคสปกติ',
            ('emergency',)))

    return render(request, 'incidents/system_owner_dashboard.html', {
        'stats':          stats,
        'recent_tickets': page_obj,
        'page_obj':       page_obj,
        'closed_tickets': closed_tickets,
        'profile':        profile,
        'is_superuser_view': request.user.is_superuser,
        'search': search,
        'status_filter': status_filter,
        'open_status_choices': open_status_choices,
        'emergency_filter': emergency_filter,
        'sort': sort,
        'sort_options': OWNER_SORT_OPTIONS,
        'sort_headers': _column_sort_headers(OWNER_COLUMNS, sort),
        'sort_is_from_column': sort not in dict(OWNER_SORT_OPTIONS),
        'result_count': paginator.count,
        'result_total': stats['active'],
        'filter_chips': filter_chips,
        'has_clearable_filters': bool(filter_chips),
    })
