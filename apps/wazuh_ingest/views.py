from datetime import timedelta
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import CharField, Count, F, Q, TextField
from django.db.models.functions import Cast
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from apps.incidents.views._helpers import _column_sort_headers, _filter_chip

from .models import WazuhAlert

ESCALATE_TIER_CHOICES = dict(WazuhAlert.TIER_CHOICES)

# Page sizes offered on the triage queue. 25 stays the default; the larger
# steps exist because scanning one screen beats paging when an analyst is
# looking for related alerts across a burst.
PER_PAGE_CHOICES = (25, 50, 100)
DEFAULT_PER_PAGE = 25

# Every ordering the queue table offers, as (label, ascending key, descending
# key). A None pair is a column that cannot be sorted: OLA is a pure function
# of timestamp (see ola_deadline), so it sorts with เวลา rather than on its own,
# and the action column holds buttons.
QUEUE_COLUMNS = (
    ('เวลา', 'ola', 'newest'),
    ('OLA', None, None),
    ('Agent', 'agent', '-agent'),
    ('Agent IP', 'ip', '-ip'),
    ('Level', 'level_asc', 'level'),
    ('Rule', 'rule', '-rule'),
    ('สถานะ', 'status', '-status'),
    ('ผู้รับเรื่อง', 'owner', '-owner'),
    ('ดำเนินการ', None, None),
)

# Second key is always the tie-break, so equal values stay in a stable, useful
# order (oldest first — the OLA reading) instead of whatever the planner picks.
#
# nulls_last on agent_ip and claimed_by: an alert with no IP or no owner is
# missing information, and burying it at the top of an ascending sort would
# push real rows off the first screen.
#
# rule_id sorts lexically because it is a CharField of digits ('100888' before
# '204'). Left alone deliberately: this sort exists to gather identical rules
# together, and grouping is unaffected by the numeric ordering being odd.
SORT_MAP = {
    'ola': ('timestamp', '-rule_level'),
    'newest': ('-timestamp', '-rule_level'),
    'level': ('-rule_level', 'timestamp'),
    'level_asc': ('rule_level', 'timestamp'),
    'agent': ('agent_name', 'timestamp'),
    '-agent': ('-agent_name', 'timestamp'),
    'ip': (F('agent_ip').asc(nulls_last=True), 'timestamp'),
    '-ip': (F('agent_ip').desc(nulls_last=True), 'timestamp'),
    'rule': ('rule_id', 'timestamp'),
    '-rule': ('-rule_id', 'timestamp'),
    'status': ('triage_status', 'timestamp'),
    '-status': ('-triage_status', 'timestamp'),
    'owner': (F('claimed_by__username').asc(nulls_last=True), 'timestamp'),
    '-owner': (F('claimed_by__username').desc(nulls_last=True), 'timestamp'),
}

# The three the sort dropdown offers. Anything else came from a column header,
# and the dropdown says so rather than silently showing the wrong option.
DROPDOWN_SORTS = ('ola', 'level', 'newest')


def _sort_headers(current_sort):
    """Header cells for the queue table, each carrying the sort it links to.

    Clicking a header applies its ascending sort; clicking the one already
    active flips it. Delegates to the builder every ticket list uses (and
    renders through the same incidents/_sortable_headers.html), so this queue's
    headers look and behave like theirs. The action column is right-aligned.
    """
    columns = [
        (label, asc_key, desc_key, True, 'text-end' if index == len(QUEUE_COLUMNS) - 1 else '')
        for index, (label, asc_key, desc_key) in enumerate(QUEUE_COLUMNS)
    ]
    return _column_sort_headers(columns, current_sort)

# Triage no longer collects an incident category — the ticket form owns the
# threat taxonomy (Ticket.DETAILED_ISSUE_HIERARCHY), so the coarse alert-side
# mapping that used to pre-fill detailed_issue2 from it is gone. The
# WazuhAlert.incident_category column stays for the alerts that already carry
# a value; nothing writes it now.


def _posted_alert_id(request):
    """The POSTed alert_id as an int, or None when missing or non-numeric.

    Filtering pk= on a non-numeric string raises inside the ORM (a 500); None
    simply matches no alert, so each view takes its normal "not yours" path.
    """
    try:
        return int(request.POST.get('alert_id', ''))
    except (TypeError, ValueError):
        return None


def _severity_for_rule_level(rule_level):
    """Map a Wazuh rule.level to a Ticket severity choice."""
    if rule_level >= 13:
        return 'Critical'
    if rule_level >= 10:
        return 'High'
    if rule_level >= 7:
        return 'Medium'
    return 'Low'


def _user_tier(profile):
    """Return the WazuhAlert tier code this user receives escalations for, or None."""
    if profile.is_soc_manager:
        return WazuhAlert.TIER_MANAGER
    if profile.tier in (WazuhAlert.TIER_T1, WazuhAlert.TIER_T2):
        return profile.tier
    return None


def _has_soc_access(user):
    profile = getattr(user, 'profile', None)
    return user.is_superuser or (profile is not None and profile.is_soc)


def _has_tier1_access(user):
    """Triage (claim / create-ticket / release) is a Tier 1 activity."""
    profile = getattr(user, 'profile', None)
    return user.is_superuser or (profile is not None and profile.is_tier1)


def _allowed_escalation_tiers(profile, user=None):
    """Return only tiers higher than the current analyst's tier."""
    if user is not None and user.is_superuser:
        return list(WazuhAlert.TIER_CHOICES)
    tier = _user_tier(profile)
    if tier == WazuhAlert.TIER_T1:
        allowed = (WazuhAlert.TIER_T2, WazuhAlert.TIER_MANAGER)
    elif tier == WazuhAlert.TIER_T2:
        allowed = (WazuhAlert.TIER_MANAGER,)
    else:
        allowed = ()
    return [choice for choice in WazuhAlert.TIER_CHOICES if choice[0] in allowed]


@login_required
def triage_queue(request):
    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถเข้าถึง Triage Queue ได้')
        return redirect('ticket_list')

    # kind=DETECTION scopes the whole page, facet counts included. Vulnerability
    # alerts are never stored (they are excluded at ingest — see
    # WazuhAlert.KIND_VULNERABILITY and ingest.py), so this filter mainly guards
    # against any legacy rows: without it the queue would be ~90% kernel CVEs
    # and every OLA facet would read as breached.
    queue = WazuhAlert.objects.filter(
        kind=WazuhAlert.KIND_DETECTION,
        triage_status__in=[WazuhAlert.TRIAGE_PENDING, WazuhAlert.TRIAGE_TRIAGING],
    )
    queue_total = queue.count()

    # The queue opens on work this analyst can act on: alerts nobody has claimed
    # plus alerts they already hold. Other analysts' claims remain one click away
    # for team awareness, without pushing actionable work onto later pages.
    claim_filter = request.GET.get('claim', 'actionable').strip()
    if claim_filter not in ('actionable', 'unclaimed', 'mine', 'others', 'all'):
        claim_filter = 'actionable'

    ola_filter = request.GET.get('ola', '').strip()
    if ola_filter not in ('breached', 'due', 'on_track'):
        ola_filter = ''

    # These are disjoint Wazuh rule-level bands, not Ticket severity. Severity
    # belongs to a judged case and is selected on the ticket form.
    rule_level_filter = request.GET.get('rule_level_filter', '').strip()
    if rule_level_filter not in ('under12', '12', '15'):
        rule_level_filter = ''

    search_query = request.GET.get('q', '').strip()[:200]
    now = timezone.now()
    breached_before = now - timedelta(hours=WazuhAlert.OLA_HOURS)
    due_within_hour_before = now - timedelta(hours=WazuhAlert.OLA_HOURS - 1)
    ready_q = Q(
        triage_status=WazuhAlert.TRIAGE_PENDING,
        claimed_by__isnull=True,
    )
    mine_q = Q(
        triage_status=WazuhAlert.TRIAGE_TRIAGING,
        claimed_by=request.user,
    )

    def _apply_claim(qs, value=claim_filter):
        if value == 'actionable':
            return qs.filter(ready_q | mine_q)
        if value == 'unclaimed':
            return qs.filter(ready_q)
        if value == 'mine':
            return qs.filter(mine_q)
        if value == 'others':
            return qs.filter(
                triage_status=WazuhAlert.TRIAGE_TRIAGING,
                claimed_by__isnull=False,
            ).exclude(claimed_by=request.user)
        return qs

    def _apply_ola(qs):
        if ola_filter == 'breached':
            return qs.filter(timestamp__lt=breached_before)
        if ola_filter == 'due':
            return qs.filter(
                timestamp__gte=breached_before,
                timestamp__lte=due_within_hour_before,
            )
        if ola_filter == 'on_track':
            return qs.filter(timestamp__gt=due_within_hour_before)
        return qs

    def _apply_level(qs):
        if rule_level_filter == '15':
            return qs.filter(rule_level__gte=15)
        if rule_level_filter == '12':
            return qs.filter(rule_level__gte=12, rule_level__lt=15)
        if rule_level_filter == 'under12':
            return qs.filter(rule_level__lt=12)
        return qs

    def _apply_search(qs):
        if not search_query:
            return qs
        return qs.annotate(
            search_agent_ip=Cast('agent_ip', output_field=CharField()),
            search_mitre_ids=Cast('mitre_ids', output_field=TextField()),
        ).filter(
            Q(agent_name__icontains=search_query)
            | Q(search_agent_ip__icontains=search_query)
            | Q(rule_id__icontains=search_query)
            | Q(rule_description__icontains=search_query)
            | Q(alert_id__icontains=search_query)
            | Q(search_mitre_ids__icontains=search_query)
        )

    alerts = _apply_claim(_apply_ola(_apply_level(_apply_search(queue))))

    # ola_deadline is timestamp + a flat OLA_HOURS, so ordering by timestamp
    # ascending is the OLA order — no annotation needed.
    sort = request.GET.get('sort', 'ola').strip()
    if sort not in SORT_MAP:
        sort = 'ola'
    alerts = alerts.select_related('claimed_by').order_by(*SORT_MAP[sort])

    try:
        per_page = int(request.GET.get('per_page', DEFAULT_PER_PAGE))
    except (TypeError, ValueError):
        per_page = DEFAULT_PER_PAGE
    if per_page not in PER_PAGE_CHOICES:
        per_page = DEFAULT_PER_PAGE

    paginator = Paginator(alerts, per_page)
    page_obj = paginator.get_page(request.GET.get('page'))

    # Facets are cross-filtered: each count says what clicking that pill would
    # produce while retaining the other active dimensions and search text.
    claim_scope = _apply_ola(_apply_level(_apply_search(queue)))
    claim_tally = claim_scope.aggregate(
        total=Count('id'),
        actionable=Count('id', filter=ready_q | mine_q),
        unclaimed=Count('id', filter=ready_q),
        mine=Count('id', filter=mine_q),
        others=Count(
            'id',
            filter=(
                Q(triage_status=WazuhAlert.TRIAGE_TRIAGING)
                & Q(claimed_by__isnull=False)
                & ~Q(claimed_by=request.user)
            ),
        ),
    )
    claim_facets = [
        {'key': None, 'label': 'พร้อมดำเนินการ', 'count': claim_tally['actionable'],
         'active': claim_filter == 'actionable'},
        {'key': 'unclaimed', 'label': 'พร้อมรับ', 'count': claim_tally['unclaimed'],
         'active': claim_filter == 'unclaimed'},
        {'key': 'mine', 'label': 'ที่ฉันรับไว้', 'count': claim_tally['mine'],
         'active': claim_filter == 'mine'},
        {'key': 'others', 'label': 'ผู้อื่นรับไว้', 'count': claim_tally['others'],
         'active': claim_filter == 'others'},
        {'key': 'all', 'label': 'ทั้งหมด', 'count': claim_tally['total'],
         'active': claim_filter == 'all'},
    ]

    ola_scope = _apply_claim(_apply_level(_apply_search(queue)))
    ola_tally = ola_scope.aggregate(
        total=Count('id'),
        breached=Count('id', filter=Q(timestamp__lt=breached_before)),
        due=Count(
            'id',
            filter=Q(
                timestamp__gte=breached_before,
                timestamp__lte=due_within_hour_before,
            ),
        ),
        on_track=Count('id', filter=Q(timestamp__gt=due_within_hour_before)),
    )
    ola_facets = [
        {'key': None, 'label': 'ทั้งหมด', 'count': ola_tally['total'],
         'active': not ola_filter},
        {'key': 'breached', 'label': 'เกิน OLA', 'count': ola_tally['breached'],
         'active': ola_filter == 'breached'},
        {'key': 'due', 'label': 'ครบใน 1 ชม.', 'count': ola_tally['due'],
         'active': ola_filter == 'due'},
        {'key': 'on_track', 'label': 'ยังไม่เร่งด่วน', 'count': ola_tally['on_track'],
         'active': ola_filter == 'on_track'},
    ]

    level_scope = _apply_claim(_apply_ola(_apply_search(queue)))
    level_tally = level_scope.aggregate(
        total=Count('id'),
        lvl15=Count('id', filter=Q(rule_level__gte=15)),
        lvl12=Count('id', filter=Q(rule_level__gte=12, rule_level__lt=15)),
        under12=Count('id', filter=Q(rule_level__lt=12)),
    )
    level_facets = [
        {'key': None, 'label': 'ทั้งหมด', 'count': level_tally['total'],
         'active': not rule_level_filter},
        {'key': '15', 'label': '15+', 'count': level_tally['lvl15'],
         'active': rule_level_filter == '15'},
        {'key': '12', 'label': '12–14', 'count': level_tally['lvl12'],
         'active': rule_level_filter == '12'},
    ]
    # Keep lower ingested alerts accounted for without making the secondary
    # bucket permanent. The default ingestion policy admits level 10+
    # (ingest_wazuh_alerts --min-level, default 10), so a level 10–11 bucket
    # only appears when such alerts are actually present.
    if level_tally['under12'] or rule_level_filter == 'under12':
        level_facets.append({
            'key': 'under12', 'label': 'ต่ำกว่า 12', 'count': level_tally['under12'],
            'active': rule_level_filter == 'under12',
        })

    return render(request, 'wazuh_ingest/triage_queue.html', {
        'page_obj': page_obj,
        'alerts': page_obj,
        'queue_total': queue_total,
        'filtered_count': paginator.count,
        'ready_count': claim_tally['unclaimed'],
        'mine_count': claim_tally['mine'],
        'claim_facets': claim_facets,
        'claim_filter': claim_filter,
        'ola_facets': ola_facets,
        'ola_filter': ola_filter,
        'level_facets': level_facets,
        'rule_level_filter': rule_level_filter,
        'search_query': search_query,
        'sort': sort,
        'sort_headers': _sort_headers(sort),
        'sort_is_from_column': sort not in DROPDOWN_SORTS,
        'sort_options': (
            ('ola', 'OLA ใกล้ครบกำหนด'),
            ('level', 'Rule level สูงสุด'),
            ('newest', 'Alert ล่าสุด'),
        ),
        'per_page': per_page,
        'per_page_choices': PER_PAGE_CHOICES,
        # The three pill rows show their own selection; only the free-text
        # search needs a chip. "Clear all" returns to the default scope
        # (พร้อมดำเนินการ, every OLA band and level).
        'filter_chips': (
            [_filter_chip(request, f'ค้นหา: “{search_query}”', ('q',))] if search_query else []
        ),
        'has_clearable_filters': bool(
            claim_filter != 'actionable' or ola_filter or rule_level_filter or search_query),
    })


@login_required
def claim_alert(request):
    if request.method != 'POST':
        return redirect('triage_queue')

    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถรับ Alert มา Triage ได้')
        return redirect('triage_queue')

    alert_id = _posted_alert_id(request)
    # kind is re-checked here, not just in the queue's SELECT: claiming is the
    # only door into TRIAGING, and everything downstream (triage_action, the
    # ticket form's alert selector) gates on "claimed by me". Guarding this one
    # UPDATE therefore keeps a vulnerability alert out of every later step, even
    # from a hand-crafted POST carrying an id that was never rendered.
    updated = WazuhAlert.objects.filter(
        pk=alert_id,
        kind=WazuhAlert.KIND_DETECTION,
        triage_status=WazuhAlert.TRIAGE_PENDING,
        claimed_by__isnull=True,
    ).update(
        triage_status=WazuhAlert.TRIAGE_TRIAGING,
        claimed_by=request.user,
        claimed_at=timezone.now(),
    )
    if not updated:
        messages.error(request, 'Alert นี้ถูกเจ้าหน้าที่คนอื่นรับไปแล้ว หรือไม่ได้อยู่ในสถานะ Pending')
        return redirect('triage_queue')

    messages.success(request, f'คุณรับ Alert #{alert_id} มา Triage แล้ว')
    return redirect('triage_queue')


@login_required
def release_alert(request):
    if request.method != 'POST':
        return redirect('triage_queue')

    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('triage_queue')

    # A reason is REQUIRED when releasing a claimed alert back to the queue.
    reason = request.POST.get('release_reason', '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการคืน Alert กลับเข้า Queue')
        return redirect('triage_queue')

    alert_id = _posted_alert_id(request)
    with transaction.atomic():
        alert = (
            WazuhAlert.objects.select_for_update()
            .filter(
                pk=alert_id,
                triage_status=WazuhAlert.TRIAGE_TRIAGING,
                claimed_by=request.user,
            )
            .first()
        )
        if alert is None:
            messages.error(request, 'Alert นี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
            return redirect('triage_queue')
        alert.release_reason = reason
        alert.triage_note = reason
        alert.triage_status = WazuhAlert.TRIAGE_PENDING
        alert.claimed_by = None
        alert.claimed_at = None
        alert.save(update_fields=[
            'release_reason', 'triage_note', 'triage_status',
            'claimed_by', 'claimed_at',
        ])

    messages.success(request, f'คืน Alert #{alert_id} กลับเข้า Queue พร้อมเหตุผลแล้ว')
    return redirect('triage_queue')


@login_required
def triage_action(request):
    """Tier 1 triage has exactly two actions after claiming an alert:
    create a ticket (here) or release it back to the queue (release_alert).

    The old triage-level Close (FP) and Escalate actions are gone — the
    Event/Incident and escalation decisions now live on the ticket.

    Because creating a ticket is the only forward move, this step asks the
    analyst for nothing: there is no alternative to justify. It only records
    which destination they picked. The threat taxonomy is captured on the
    ticket form, which owns it properly (a validated detailed_issue →
    detailed_issue2 cascade), and the Critical triage OLA runs from incident
    time (Ticket.OLA_TARGETS), so anything asked for here is spent from that
    30-minute budget before the ticket even exists.
    """
    if request.method != 'POST':
        return redirect('triage_queue')

    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('triage_queue')

    action = request.POST.get('action', '')

    if action not in ('create_ticket', 'create_project_incident'):
        messages.error(
            request,
            'การดำเนินการไม่ถูกต้อง — Tier 1 สามารถสร้าง Ticket หรือคืน Alert เท่านั้น',
        )
        return redirect('triage_queue')

    # Read-only ownership gate: nothing is written here, so no row lock is
    # needed. The alert deliberately stays claimed and TRIAGING until the
    # Ticket is saved — a cancelled ticket form must not lose the claim.
    alert = get_object_or_404(WazuhAlert, pk=_posted_alert_id(request))
    owns_triage = (
        alert.triage_status == WazuhAlert.TRIAGE_TRIAGING
        and alert.claimed_by_id == request.user.id
    )
    if not (owns_triage or (
        request.user.is_superuser
        and alert.triage_status == WazuhAlert.TRIAGE_TRIAGING
    )):
        messages.error(request, f'Alert #{alert.pk} ไม่ได้อยู่ในความรับผิดชอบของคุณ หรือถูกดำเนินการไปแล้ว')
        return redirect('triage_queue')

    params = {
        'wazuh_alert': alert.pk,
        'issue_description': alert.rule_description,
        'severity': _severity_for_rule_level(alert.rule_level),
    }

    # Same claimed-alert intake, two destinations: a single ticket or a
    # multi-system Project Incident (case bundle). Both pre-fill from the alert;
    # the alert stays claimed until the target form is saved.
    target = (
        'create_project_incident'
        if action == 'create_project_incident'
        else 'create_ticket'
    )
    return redirect(f"{reverse(target)}?{urlencode(params)}")
