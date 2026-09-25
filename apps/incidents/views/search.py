import ipaddress
import logging

import requests
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db.models import CharField, F, Q, Value
from django.db.models.functions import NullIf
from django.http import JsonResponse
from django.shortcuts import render

from ..models import (
    Ticket,
    TriageRecord,
)
from ..ioc_values import INVENTORY_CATEGORY_CHOICES, normalize_for_category
from ._helpers import (
    _by,
    _choice_label_expr,
    _column_sort_headers,
    _status_order_expr,
)

logger = logging.getLogger('apps.incidents.views')

# The two result tables sort and page independently, so each has its own
# parameters: ts/tp for tickets, rs/rp for triage records. Columns are
# (label, first-click sort, second-click sort, first click ascending?, th class)
# — see _helpers._column_sort_headers. Free-text columns aren't sortable.
TICKET_RESULT_COLUMNS = (
    ('เลข Ticket', '-id', 'id', False, ''),
    ('IP ต้นทาง', 'device', '-device', True, ''),
    ('IoC ปลายทาง', 'dest', '-dest', True, ''),
    ('รายละเอียด', None, None, True, ''),
    ('สถานะ', 'status', '-status', True, ''),
    ('วันที่แจ้ง', 'newest', 'oldest', False, ''),
    ('', None, None, True, ''),
)
TRIAGE_RESULT_COLUMNS = (
    ('แหล่งที่มา', 'source', '-source', True, ''),
    ('IP ต้นทาง', 'ip', '-ip', True, ''),
    ('รายละเอียด Alert', None, None, True, ''),
    ('การตัดสินใจ', 'decision', '-decision', True, ''),
    ('วันที่', 'newest', 'oldest', False, ''),
    ('', None, None, True, ''),
)


def _blank_as_null(field):
    return NullIf(field, Value(''), output_field=CharField())


def _ticket_result_order(sort):
    """(ordering, annotations) for the ticket results. The query is DISTINCT
    (the IOC join fans out), and Postgres requires every ORDER BY expression of
    a DISTINCT query to be selected — so computed keys go in as annotations."""
    tie = ('-created_at', '-pk')
    orders = {
        'newest': (tie, {}),
        'oldest': (('created_at', 'pk'), {}),
        '-id': (('-ticket_id', '-pk'), {}),
        'id': (('ticket_id', 'pk'), {}),
        'device': ((_by(F('device_name')), *tie), {}),
        '-device': ((_by(F('device_name'), descending=True), *tie), {}),
        # Blank destination is '' (shown as "-"): NULL it so it sorts last.
        'dest': ((_by(F('sort_dest')), *tie), {'sort_dest': _blank_as_null('destination_ip')}),
        '-dest': ((_by(F('sort_dest'), descending=True), *tie),
                  {'sort_dest': _blank_as_null('destination_ip')}),
        'status': (('sort_status', *tie), {'sort_status': _status_order_expr()}),
        '-status': (('-sort_status', *tie), {'sort_status': _status_order_expr()}),
    }
    return orders.get(sort)


def _triage_result_order(sort):
    tie = ('-created_at', '-pk')
    source = _choice_label_expr('source', TriageRecord)
    decision = _choice_label_expr('decision', TriageRecord)
    orders = {
        'newest': tie,
        'oldest': ('created_at', 'pk'),
        'source': (_by(source), *tie),
        '-source': (_by(source, descending=True), *tie),
        'ip': (_by(F('source_ip')), *tie),
        '-ip': (_by(F('source_ip'), descending=True), *tie),
        'decision': (_by(decision), *tie),
        '-decision': (_by(decision, descending=True), *tie),
    }
    return orders.get(sort)



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
    # User + Command are their own fields (kept out of the TicketIOC table / IOC
    # Database), but should still be findable here.
    'ioc_user', 'ioc_command',
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


def _ticket_search_match(term):
    # Legacy free-text fields (substring) + the structured TicketIOC rows. The
    # IOC values are matched as a substring and, where the term normalizes for a
    # category, as an exact normalized value so defanged input (1[.]2[.]3[.]4)
    # finds the stored form. Callers must .distinct() — the iocs join fans out.
    match = _substring_match(TICKET_SEARCH_FIELDS, term)
    match |= Q(iocs__value__icontains=term)
    for category, _label in INVENTORY_CATEGORY_CHOICES:
        try:
            value = normalize_for_category(category, term)
        except ValidationError:
            continue
        if value and value != term:
            match |= Q(iocs__value=value)
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

    ticket_sort = request.GET.get('ts', 'newest').strip()
    ticket_order = _ticket_result_order(ticket_sort)
    if ticket_order is None:
        ticket_sort = 'newest'
        ticket_order = _ticket_result_order(ticket_sort)
    triage_sort = request.GET.get('rs', 'newest').strip()
    triage_order = _triage_result_order(triage_sort)
    if triage_order is None:
        triage_sort = 'newest'
        triage_order = _triage_result_order(triage_sort)

    if query:
        # Tickets match on their own fields and their structured IOC values, so a
        # hash/IP/domain search surfaces the cases it appeared on (handy for
        # triage). IOC coverage vs the TI platform lives on the IOC Database page.
        ordering, annotations = ticket_order
        ticket_qs = (
            Ticket.objects.visible_to(request.user)
            .filter(_ticket_search_match(query))
            .annotate(**annotations)
            .distinct()
            .order_by(*ordering)
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
                .order_by(*triage_order)
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
        'ticket_sort': ticket_sort,
        'triage_sort': triage_sort,
        'ticket_sort_headers': _column_sort_headers(
            TICKET_RESULT_COLUMNS, ticket_sort, request=request, param='ts', page_param='tp'),
        'triage_sort_headers': _column_sort_headers(
            TRIAGE_RESULT_COLUMNS, triage_sort, request=request, param='rs', page_param='rp'),
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
