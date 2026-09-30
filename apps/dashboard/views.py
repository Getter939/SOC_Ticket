import math
from datetime import timedelta
from urllib.parse import urlencode
from statistics import mean as _mean, median as _median

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.core.exceptions import PermissionDenied
from django.db.models import Case, CharField, Count, F, OuterRef, Q, Subquery, Value, When
from django.db.models.functions import (
    Coalesce, Concat, Lower, NullIf, Trim, TruncDate, TruncHour,
)
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_date

from apps.accounts.models import UserProfile
from apps.incidents import ola as ola_buckets
from apps.incidents.models import Ticket, TicketLog, TicketSubtask
from apps.wazuh_ingest.models import IngestWatermark

# ====================================================================== #
# Data-model facts this view relies on (verified against                 #
# apps/incidents/models.py — keep in sync if the model changes):         #
#                                                                        #
#   a) OLA deadlines  → Ticket.ola_triage_deadline (raise-in-time) and    #
#      Ticket.ola_contain_deadline (resolve). Auto-set in Ticket.save()   #
#      from (incident_datetime or now()) + per-severity Ticket.OLA_TARGETS.#
#      This view buckets on the CONTAIN deadline; Medium/Low have none    #
#      (notification-only) and are excluded from the pressure chart.      #
#   b) Resolution time→ there is NO resolved_at/closed_at field. The     #
#      authoritative "moved to a terminal state" timestamp is the first  #
#      TicketLog row whose status_at_time is in TERMINAL_STATUSES        #
#      (written by Ticket.transition_to). We Coalesce that with          #
#      approved_at then updated_at so tickets seeded directly into a     #
#      terminal state (no log row) still get a sensible timestamp.       #
#   c) Terminal slugs → 'APPROVED', 'CLOSED_EVENT'                       #
#      (Ticket.TERMINAL_STATUSES).                                       #
#   d) Severity       → Ticket.severity, ranked by Ticket.SEVERITY_RANK  #
#      (Critical=4 … Unknown=0). HIGHEST rank slug is 'Critical' (=4),   #
#      so "active_critical" filters severity == 'Critical'.              #
#   e) Assignee       → Ticket.assigned_to (FK to auth.User).            #
#                                                                        #
#   e) Statuses      → Ticket.STATUS_CHOICES is the single source of      #
#      truth for both the slug set and the display order; this module     #
#      never hardcodes the list. Terminal = Ticket.TERMINAL_STATUSES      #
#      ({APPROVED, CLOSED_EVENT}); the other 10 are active. The current   #
#      lifecycle is documented in docs/architecture/ticket-lifecycle-states.md.                #
#   f) Threat type   → Ticket.detailed_issue (DETAILED_ISSUE_CHOICES);    #
#      source channel → issue_type. (The Event/Incident axis is           #
#      Ticket.classification.)                                            #
# ====================================================================== #

# Active statuses the OPENING ANALYST must personally act on, vs. those
# parked with someone else. Drives the Analyst Workload heatmap, which asks
# "what does this analyst have to chase?" — so AWAITING_OWNER counts as their
# work (they chase the owner), even though the executive dashboard files the
# same status under EXTERNAL because it asks a different question ("who blocks
# closure?"). Both readings are correct; see _EXEC_COURT_GROUPS.
#
# INVARIANT: OWN + BLOCKED together cover every non-terminal status exactly
# once — enforced by AnalystHeatmapTest.
_ANALYST_OWN_STATUSES = list(Ticket.TIER1_QUEUE_STATUSES)
_ANALYST_BLOCKED_STATUSES = [
    Ticket.STATUS_ESCALATED_T2,
    Ticket.STATUS_PENDING_MGR_TRIAGE,
    Ticket.STATUS_AWAITING_CONTAINMENT,
    Ticket.STATUS_CONTAINMENT_REPORTED,
    Ticket.STATUS_PENDING_T2_REVIEW,
    Ticket.STATUS_PENDING_MANAGER,
    Ticket.STATUS_PENDING_MGR_EVENT_REVIEW,
]
_ANALYST_CLAIMED_KEY = '__T2_CLAIMED__'


def humanize_minutes(total_minutes):
    """
    Render a minute count as a compact duration ('3d 2h', '2h 15m', '45m').

    Magnitude only — the sign is the caller's to interpret, since an overdue
    deadline reads as "overdue by 3d 2h" rather than a negative number.
    """
    minutes = abs(int(total_minutes))
    days, rem = divmod(minutes, 1440)
    hours, mins = divmod(rem, 60)
    if days:
        return f'{days}d {hours}h' if hours else f'{days}d'
    if hours:
        return f'{hours}h {mins}m' if mins else f'{hours}h'
    return f'{mins}m'


def _wazuh_ingest_freshness(now):
    """Return Wazuh poll and source-event ages, separate from page render time."""
    watermark = IngestWatermark.objects.only(
        'last_timestamp', 'last_successful_poll_at',
    ).first()
    if not watermark:
        return None

    def age_label(timestamp):
        if not timestamp:
            return None
        age_minutes = max(0, int((now - timestamp).total_seconds() // 60))
        return humanize_minutes(age_minutes)

    return {
        'poll_at': watermark.last_successful_poll_at,
        'event_at': watermark.last_timestamp,
        'poll_age': age_label(watermark.last_successful_poll_at),
        'event_age': age_label(watermark.last_timestamp),
    }


def _with_resolved_at(queryset):
    """Annotate terminal tickets with their authoritative resolution time."""
    terminal = list(Ticket.TERMINAL_STATUSES)
    first_terminal_log = (
        TicketLog.objects
        .filter(ticket=OuterRef('pk'), status_at_time__in=terminal)
        .order_by('created_at')
        .values('created_at')[:1]
    )
    return queryset.annotate(
        resolved_at=Coalesce(
            Subquery(first_terminal_log), F('approved_at'), F('updated_at'),
        )
    )


def _mttr_stats(resolved_queryset, now):
    """Return 30-day ticket-grain MTTR median, mean, and sample size."""
    mttr_rows = (
        resolved_queryset
        .filter(resolved_at__gte=now - timedelta(days=30))
        .values_list('resolved_at', 'created_at')
    )
    hours = [
        (resolved - created).total_seconds() / 3600
        for resolved, created in mttr_rows
        if resolved and created and resolved >= created
    ]
    if not hours:
        return {'mttr_median': None, 'mttr_mean': None, 'mttr_n': 0}
    return {
        'mttr_median': round(_median(hours), 1),
        'mttr_mean': round(_mean(hours), 1),
        'mttr_n': len(hours),
    }

@login_required
def dashboard(request):
    profile = getattr(request.user, 'profile', None)

    # System Owners see their own portal, not the SOC dashboard
    if not request.user.is_superuser and profile and profile.is_system_owner:
        return redirect('system_owner_dashboard')
    if not request.user.is_superuser and profile and profile.is_system_admin:
        return redirect('ticket_list')
    # Response teams (Forensic Analyst / Red Team Manager) work single requests
    # under a response-only access model — org-wide aggregates (active counts,
    # per-analyst workload, MTTR) are outside their need-to-know. Send them to
    # their own queue, mirroring the System Admin rule above.
    if not request.user.is_superuser and profile and profile.is_response_team:
        return redirect('response_request_queue')
    # FAIL CLOSED — this must be the last word before any data is read.
    #
    # The redirects above are ROUTING, not authorization. Each is written
    # `and profile and ...`, so a user with NO UserProfile matches none of them
    # and used to fall straight through to the query below — which exposed the
    # org-wide queue and aggregates without a role profile. The detail table is
    # server-paginated now, but its aggregate scope remains org-wide.
    #
    # That state is routine, not hypothetical: nothing auto-creates a
    # UserProfile, and Django's BaseUserAdmin hides the UserProfileInline on the
    # "Add user" form — so an admin-created account has no profile until someone
    # re-opens it and fills the inline. It can log in during that gap.
    #
    # An explicit allowlist rather than Ticket.objects.visible_to(): this page is
    # an org-wide aggregate view, which is a coarser question than "which tickets
    # may this user open". visible_to() returns none() for EXECUTIVE, so routing
    # the query through it would silently blank a dashboard executives are meant
    # to see (they reach /executive/ from this page's sidebar). Roles listed here
    # are exactly those already trusted with org-wide data; anything new — or
    # anything with no profile — is denied until someone decides otherwise.
    may_see_org_wide = request.user.is_superuser or (
        profile is not None
        and (profile.is_soc or profile.is_executive)
    )
    if not may_see_org_wide:
        raise PermissionDenied

    today = timezone.now()
    now   = today
    local_now = timezone.localtime(now)
    wazuh_ingest_freshness = _wazuh_ingest_freshness(now)
    terminal = list(Ticket.TERMINAL_STATUSES)

    # ── GET filters: date range / status / severity ──────────────────────── #
    # Presentation-level scoping only. Default 'all' / '' preserves the
    # original unfiltered behavior, so existing callers are unaffected.
    date_range      = request.GET.get('date_range', 'all')
    try:
        date_from = parse_date(request.GET.get('date_from', '').strip())
    except ValueError:
        date_from = None
    try:
        date_to = parse_date(request.GET.get('date_to', '').strip())
    except ValueError:
        date_to = None
    if date_from and date_to and date_from > date_to:
        date_from, date_to = date_to, date_from
    if date_from or date_to:
        date_range = 'custom'
    elif date_range not in {'today', 'week', 'month', 'all'}:
        date_range = 'all'
    status_filter   = request.GET.get('status', '')
    severity_filter = request.GET.get('severity', '')

    # Org-wide by design; reachable only via the may_see_org_wide gate above.
    all_tickets = Ticket.objects.all()

    if date_range == 'custom':
        if date_from:
            all_tickets = all_tickets.filter(created_at__date__gte=date_from)
        if date_to:
            all_tickets = all_tickets.filter(created_at__date__lte=date_to)
    elif date_range == 'today':
        all_tickets = all_tickets.filter(created_at__date=local_now.date())
    elif date_range == 'week':
        week_start = (local_now - timedelta(days=local_now.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0)
        all_tickets = all_tickets.filter(created_at__gte=week_start)
    elif date_range == 'month':
        month_start = local_now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        all_tickets = all_tickets.filter(created_at__gte=month_start)

    if severity_filter:
        all_tickets = all_tickets.filter(severity=severity_filter)

    if status_filter:
        all_tickets = all_tickets.filter(status=status_filter)

    active_qs   = all_tickets.exclude(status__in=terminal)
    closed_qs   = all_tickets.filter(status__in=Ticket.RESOLVED_STATUSES)

    # ── Resolution timestamp (no resolved_at field — derive from TicketLog) ─ #
    # First time the ticket entered a terminal state. Coalesced with
    # approved_at / updated_at for rows seeded straight into a terminal state.
    resolved_qs = _with_resolved_at(closed_qs)

    # ── MTTR over the last 30 days (hours), median/mean/n ─────────────────── #
    # resolved_at is derived from TicketLog, so it always exists; median is
    # computed in Python to stay database-agnostic.
    mttr_stats = _mttr_stats(resolved_qs, now)

    stats = {
        'cancelled': all_tickets.filter(status=Ticket.STATUS_CANCELLED).count(),
        'active': active_qs.count(),
        **mttr_stats,
    }

    # ── Pipeline chart — ACTIVE statuses only, in STATUS_CHOICES order ───── #
    status_map   = dict(Ticket.STATUS_CHOICES)
    # Terminal statuses are deliberately excluded: this is the *active* pipeline
    # (where work is piling up now). Closed cases would otherwise accumulate and
    # dwarf the live columns; their count is on the "Closed This Month" KPI tile
    # and in Ticket History. (2026-07-23)
    status_order = [s for s, _ in Ticket.STATUS_CHOICES
                    if s not in Ticket.TERMINAL_STATUSES]
    # ── Pipeline by severity × status (stacked-bar source) ───────────────── #
    # statuses: STATUS_CHOICES progression order, active states only.
    # severities: SEVERITY_RANK order, HIGHEST first (Critical=4 … Unknown=0).
    # Respects the active GET filters via active_qs. Single group-by query (no
    # N+1); the matrix is zero-filled so every status appears under every severity.
    sev_display      = dict(Ticket.SEVERITY_CHOICES)
    severity_order   = sorted(
        sev_display, key=lambda s: Ticket.SEVERITY_RANK.get(s, 0), reverse=True)
    pipeline_matrix  = {
        sev: {st: 0 for st in status_order} for sev in severity_order
    }
    for row in active_qs.values('severity', 'status').annotate(c=Count('id')):
        sev, st = row['severity'], row['status']
        if sev in pipeline_matrix and st in pipeline_matrix[sev]:
            pipeline_matrix[sev][st] = row['c']
    pipeline_by_severity = {
        'statuses':   [(s, status_map[s]) for s in status_order],
        'severities': [(s, sev_display[s]) for s in severity_order],
        'matrix':     pipeline_matrix,
    }
    # Status-ordered rows for the visually-hidden a11y table (templates can't
    # index a dict by a loop variable). Cells align to status_order.
    pipeline_rows = [
        {'severity': sev_display[sev],
         'cells':    [pipeline_matrix[sev][st] for st in status_order]}
        for sev in severity_order
    ]

    # ── Active-case detail table — sort and paginate in the database ──────── #
    sort_fields = {
        'ticket': 'ticket_id',
        'sev': 'sev_rank',
        'created': 'created_at',
        'age': 'created_at',
        'statusAge': 'status_age_anchor',
        'caseName': 'case_name_sort',
        'openedBy': 'opened_by_sort',
        'status': 'status_label_sort',
        'sc': 'status_changed_at',
    }
    sort_key = request.GET.get('sort', 'sev')
    if sort_key not in sort_fields:
        sort_key = 'sev'
    sort_direction = request.GET.get('dir', 'desc')
    if sort_direction not in {'asc', 'desc'}:
        sort_direction = 'desc'

    case_name_fallback = Case(
        *[
            When(detailed_issue2=code, then=Value(label))
            for code, label in Ticket.DETAILED_ISSUE_CHOICES2
        ],
        default=F('detailed_issue2'),
        output_field=CharField(),
    )
    status_label = Case(
        *[
            When(status=code, then=Value(label))
            for code, label in Ticket.STATUS_CHOICES
        ],
        default=F('status'),
        output_field=CharField(),
    )
    table_qs = active_qs.select_related('created_by').with_severity_rank()
    # ?ola=<bucket> narrows the table only (the runway's band links set it);
    # the rest of the page keeps showing the whole filtered queue.
    ola_filter = request.GET.get('ola', '')
    if ola_filter not in ola_buckets.BUCKET_KEYS:
        ola_filter = ''
    if ola_filter:
        table_qs = table_qs.filter(
            ola_contain_deadline__isnull=False,
        ).filter(ola_buckets.bucket_filter(ola_filter, now))
    if sort_key == 'caseName':
        table_qs = table_qs.annotate(
            case_name_sort=Lower(Coalesce(
                NullIf(Trim(F('incident_name')), Value('')),
                case_name_fallback,
                output_field=CharField(),
            ))
        )
    elif sort_key == 'openedBy':
        opened_by_name = Trim(Concat(
            F('created_by__first_name'), Value(' '), F('created_by__last_name'),
        ))
        table_qs = table_qs.annotate(
            opened_by_sort=Lower(Coalesce(
                NullIf(opened_by_name, Value('')),
                F('created_by__username'),
                output_field=CharField(),
            ))
        )
    elif sort_key == 'status':
        table_qs = table_qs.annotate(status_label_sort=Lower(status_label))
    elif sort_key == 'statusAge':
        table_qs = table_qs.annotate(
            status_age_anchor=Coalesce('status_changed_at', 'created_at')
        )

    # Age sorts reverse their timestamp direction: older cases have earlier
    # created/status timestamps. Keep null timestamps last for other columns.
    ascending_order = sort_direction == 'asc'
    if sort_key in {'age', 'statusAge'}:
        ascending_order = not ascending_order
    primary_order = F(sort_fields[sort_key])
    primary_order = (
        primary_order.asc(nulls_last=True) if ascending_order
        else primary_order.desc(nulls_last=True)
    )
    ordered_tickets = table_qs.order_by(primary_order, '-created_at', '-pk')

    case_paginator = Paginator(ordered_tickets, 25)
    recent_page = case_paginator.get_page(request.GET.get('page'))
    recent_tickets = list(recent_page.object_list)
    for ticket in recent_tickets:
        ticket.age_minutes = max(
            0, int((now - ticket.created_at).total_seconds() // 60))
        ticket.age_label = humanize_minutes(ticket.age_minutes)
        status_started_at = ticket.status_changed_at or ticket.created_at
        ticket.status_age_minutes = max(
            0, int((now - status_started_at).total_seconds() // 60))
        ticket.status_age_label = humanize_minutes(ticket.status_age_minutes)

    sort_params = request.GET.copy()
    for param in ('page', 'sort', 'dir'):
        sort_params.pop(param, None)
    sort_links = {}
    for key in sort_fields:
        params = sort_params.copy()
        next_direction = (
            ('asc' if sort_direction == 'desc' else 'desc')
            if key == sort_key else 'asc'
        )
        params['sort'] = key
        params['dir'] = next_direction
        sort_links[key] = '?' + params.urlencode()

    def case_page_url(number):
        params = request.GET.copy()
        params['page'] = number
        return '?' + params.urlencode()

    recent_page_links = []
    for number in case_paginator.get_elided_page_range(
            recent_page.number, on_each_side=2, on_ends=1):
        if number == case_paginator.ELLIPSIS:
            recent_page_links.append({'ellipsis': True})
        else:
            recent_page_links.append({
                'number': number,
                'url': case_page_url(number),
                'current': number == recent_page.number,
            })

    # ====================================================================== #
    # Live SOC dashboard KPIs — scoped by opened date, status, and severity.   #
    # ====================================================================== #
    MONTH_ABBR = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    active_total    = active_qs.count()
    active_critical = active_qs.filter(severity='Critical').count()  # highest rank

    crit_soonest = (
        active_qs.filter(severity='Critical', ola_contain_deadline__isnull=False)
        .order_by('ola_contain_deadline')
        .values('ticket_id', 'ola_contain_deadline')
        .first()
    )
    if crit_soonest:
        _minutes_remaining = round(
            (crit_soonest['ola_contain_deadline'] - now).total_seconds() / 60)
        critical_soonest_deadline = {
            'ticket_id': crit_soonest['ticket_id'],
            'minutes_remaining': _minutes_remaining,
            'overdue': _minutes_remaining < 0,
            'label': humanize_minutes(_minutes_remaining),
        }
    else:
        critical_soonest_deadline = None

    runway = _containment_runway(active_qs, now, request.GET, ola_filter)
    ola_filter_label = next(
        (b['label'] for b in runway['bands'] if b['key'] == ola_filter), '')

    # Closed this / last calendar month — terminal-entry time from the log.
    this_month_start = local_now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_month_start = (this_month_start - timedelta(days=1)).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0)
    closed_this_month = resolved_qs.filter(resolved_at__gte=this_month_start).count()
    closed_last_month = resolved_qs.filter(
        resolved_at__gte=last_month_start, resolved_at__lt=this_month_start).count()
    closed_delta = closed_this_month - closed_last_month

    # Assignee heatmap — analysts with assigned active work, current Tier 2
    # claims, or completed Tier 1/2 cases. Lifecycle status columns cover the
    # opening analyst's own queue; blocked work stays separate, and a Tier 2
    # claim appears as a status in the ticket owner's expanded breakdown.
    #
    # 'load' is the own-court queue and 'blocked' is somebody else's turn;
    # 'total' remains every active ticket assigned to the analyst, so it
    # continues to reconcile to the dashboard's unique active-ticket count.
    assignee_heatmap_statuses = [(s, status_map[s]) for s in _ANALYST_OWN_STATUSES]
    workload_labels = {
        Ticket.STATUS_NEW: 'แจ้งใหม่',
        Ticket.STATUS_MONITORING: 'เฝ้าระวัง',
        Ticket.STATUS_AWAITING_OWNER: 'ติดตามเจ้าของ',
        Ticket.STATUS_OWNER_REMEDIATED: 'ตรวจผลแก้ไข',
    }
    workload_columns = [
        {'slug': slug, 'label': workload_labels.get(slug, display), 'description': display}
        for slug, display in assignee_heatmap_statuses
    ]
    workload_columns.append({
        'slug': _ANALYST_CLAIMED_KEY,
        'label': 'รับเรื่อง Tier 2',
        'description': 'เคสในคิว Tier 2 ที่นักวิเคราะห์รับเรื่องแล้ว',
        'kind': 'claimed',
    })
    waiting_labels = {
        Ticket.STATUS_ESCALATED_T2: 'ส่งต่อ Tier 2',
        Ticket.STATUS_PENDING_MGR_TRIAGE: 'รอผู้จัดการ SOC',
        Ticket.STATUS_AWAITING_CONTAINMENT: 'รอผู้ดูแลระบบ',
        Ticket.STATUS_CONTAINMENT_REPORTED: 'รายงานควบคุมแล้ว',
        Ticket.STATUS_PENDING_T2_REVIEW: 'รอ Tier 2 ตรวจ',
        Ticket.STATUS_PENDING_MANAGER: 'รอผู้จัดการ',
        Ticket.STATUS_PENDING_MGR_EVENT_REVIEW: 'รอตรวจปิด Event',
    }
    workload_columns.extend(
        {
            'slug': slug,
            'label': waiting_labels.get(slug, status_map[slug]),
            'description': status_map[slug],
            'kind': 'waiting',
        }
        for slug in _ANALYST_BLOCKED_STATUSES
    )
    heatmap_slugs = [s for s, _ in assignee_heatmap_statuses]
    heat = {}

    def ensure_heat_row(uid, first_name, last_name, username):
        if uid not in heat:
            name = f'{first_name} {last_name}'.strip() or username
            heat[uid] = {
                'name': name, 'counts': {}, 'load': 0, 'blocked': 0,
                'total': 0, 'finished': 0, 'claimed': 0,
            }
        return heat[uid]

    for r in (active_qs.filter(assigned_to__isnull=False)
              .values('assigned_to', 'assigned_to__first_name',
                      'assigned_to__last_name', 'assigned_to__username', 'status')
              .annotate(c=Count('id'))):
        uid = r['assigned_to']
        row = ensure_heat_row(
            uid, r['assigned_to__first_name'], r['assigned_to__last_name'],
            r['assigned_to__username'],
        )
        row['counts'][r['status']] = r['c']
        if r['status'] in _ANALYST_BLOCKED_STATUSES:
            row['blocked'] += r['c']
        else:
            row['load'] += r['c']
        row['total'] += r['c']

    # A Tier 2 claim is tracked outside Ticket.status. Show the claim as a
    # breakdown status in the ticket owner's row; the lifecycle state remains
    # blocked work, because the owner is waiting for Tier 2 to act.
    claimed_rows = (
        active_qs.filter(
            status__in=Ticket.TIER2_QUEUE_STATUSES,
            t2_claimed_by__isnull=False,
            assigned_to__isnull=False,
        )
        .values('assigned_to', 'assigned_to__first_name',
                'assigned_to__last_name', 'assigned_to__username')
        .annotate(c=Count('id'))
    )
    for r in claimed_rows:
        row = ensure_heat_row(
            r['assigned_to'], r['assigned_to__first_name'],
            r['assigned_to__last_name'], r['assigned_to__username'],
        )
        row['counts'][_ANALYST_CLAIMED_KEY] = r['c']
        row['claimed'] = r['c']

    # Attribute a resolved case to its Tier 2 verifier when available (the
    # manager may perform the final approval), otherwise use the actor who
    # entered the terminal state. Tickets completed by either Tier 1 or Tier 2
    # therefore appear in the same Finished column under the analyst's row.
    finished_tickets = all_tickets.filter(status__in=Ticket.RESOLVED_STATUSES)
    finished_logs = (
        TicketLog.objects
        .filter(
            ticket__in=finished_tickets,
            status_at_time__in=Ticket.RESOLVED_STATUSES,
        )
        .filter(Q(author__isnull=False) | Q(ticket__verified_by__isnull=False))
        .select_related(
            'author__profile', 'ticket__verified_by__profile',
        )
    )

    def is_tier_analyst(user):
        profile = getattr(user, 'profile', None) if user else None
        return bool(profile and (profile.is_tier1 or profile.is_tier2))

    finished_seen = set()
    for log in finished_logs:
        analyst = log.ticket.verified_by or log.author
        if not is_tier_analyst(analyst):
            continue
        ticket_actor_key = (log.ticket_id, analyst.pk)
        if ticket_actor_key in finished_seen:
            continue
        finished_seen.add(ticket_actor_key)
        row = ensure_heat_row(
            analyst.pk, analyst.first_name, analyst.last_name, analyst.username,
        )
        row['finished'] += 1

    # Imported or directly seeded resolved tickets may not have a terminal
    # TicketLog. Use the recorded verifier/approver first, then the case owner
    # as the available attribution for those rows.
    for ticket in (finished_tickets.exclude(
            logs__status_at_time__in=Ticket.RESOLVED_STATUSES)
            .select_related(
                'verified_by__profile', 'approved_by__profile',
                'assigned_to__profile', 'created_by__profile',
            )):
        analyst = next((candidate for candidate in (
            ticket.verified_by, ticket.approved_by,
            ticket.assigned_to, ticket.created_by,
        ) if is_tier_analyst(candidate)), None)
        if analyst is None:
            continue
        row = ensure_heat_row(
            analyst.pk, analyst.first_name, analyst.last_name, analyst.username,
        )
        row['finished'] += 1
    # Busiest ACTIONABLE queue first — a row full of blocked tickets is not a
    # workload problem, so 'load' (not 'total') sets the order.
    assignee_heatmap = sorted(
        heat.values(), key=lambda x: (x['load'], x['total']), reverse=True)
    # Template can't index a dict by a loop variable — pre-build status-ordered
    # cells for the actionable columns and a complete status breakdown for the
    # expandable detail row. The claimed signal is an overlapping subset of
    # blocked tickets, so it is shown in detail without increasing workload.
    max_load = max((a['load'] for a in assignee_heatmap), default=0)
    for a in assignee_heatmap:
        a['cells'] = [a['counts'].get(s, 0) for s in heatmap_slugs]
        a['breakdown'] = [
            {
                'label': col['label'],
                'count': a['counts'].get(col['slug'], 0),
                'kind': col.get('kind', 'own'),
            }
            for col in workload_columns
        ]
        a['load_pct'] = round(a['load'] / max_load * 100) if max_load else 0

    unassigned_active = active_qs.filter(assigned_to__isnull=True).count()

    # Daily volume trend scoped to the active GET filters. Zero-filled so the
    # line has no gaps. Window depends on date_range:
    #   today → hourly buckets (00:00 … current hour, local time)
    #   week  → current calendar week (same Monday-to-date cohort as the filter)
    #   else  → last 30 days
    # All bucketing uses the active timezone (TruncDate/TruncHour + localdate).
    today_local = timezone.localdate()
    daily_trend_filtered = []
    daily_trend_labels   = []

    if date_range == 'today':
        current_hour = timezone.localtime(now).hour
        rows = (
            all_tickets.filter(created_at__date=today_local)
            .annotate(h=TruncHour('created_at'))
            .values('h').annotate(c=Count('id'))
        )
        hour_counts = {}
        for r in rows:
            hh = timezone.localtime(r['h']).hour if timezone.is_aware(r['h']) else r['h'].hour
            hour_counts[hh] = hour_counts.get(hh, 0) + r['c']
        for h in range(current_hour + 1):
            daily_trend_filtered.append(
                {'date': f"{today_local:%Y-%m-%d} {h:02d}:00",
                 'count': hour_counts.get(h, 0)})
            daily_trend_labels.append(f"{h:02d}:00")
    else:
        if date_range == 'custom':
            end_date = date_to or today_local
            start_date = date_from or (end_date - timedelta(days=29))
            if start_date > end_date:
                end_date = start_date
        else:
            start_date = (
                today_local - timedelta(days=today_local.weekday())
                if date_range == 'week'
                else today_local - timedelta(days=29)
            )
            end_date = today_local
        rows = (
            all_tickets.filter(
                created_at__date__gte=start_date,
                created_at__date__lte=end_date,
            )
            .annotate(d=TruncDate('created_at'))
            .values('d').annotate(c=Count('id'))
        )
        day_counts = {r['d']: r['c'] for r in rows}
        day = start_date
        while day <= end_date:
            daily_trend_filtered.append(
                {'date': day.strftime('%Y-%m-%d'), 'count': day_counts.get(day, 0)})
            daily_trend_labels.append(f"{day.day:02d} {MONTH_ABBR[day.month]}")
            day += timedelta(days=1)

    daily_trend_data = [d['count'] for d in daily_trend_filtered]
    if date_range == 'today':
        volume_title = 'Hourly Case Volume (วันนี้) — ปริมาณเคสรายชั่วโมง'
    elif date_range == 'week':
        volume_title = 'Daily Case Volume (สัปดาห์นี้) — ปริมาณเคสรายวัน'
    elif date_range == 'custom':
        volume_title = 'Daily Case Volume (ช่วงวันที่เลือก) — ปริมาณเคสรายวัน'
    else:
        volume_title = 'Daily Case Volume (30 วัน) — ปริมาณเคสรายวัน'
    volume_window = f"{daily_trend_filtered[0]['date']} – {daily_trend_filtered[-1]['date']}"

    # One line for the filter bar saying what the whole page is showing —
    # every figure on it follows these three filters.
    if date_range == 'custom':
        if date_from and date_to:
            range_text = f'เปิด {date_from:%d %b %Y} – {date_to:%d %b %Y}'
        elif date_from:
            range_text = f'เปิดตั้งแต่ {date_from:%d %b %Y}'
        else:
            range_text = f'เปิดถึง {date_to:%d %b %Y}'
    else:
        range_text = {
            'today': 'เปิดวันนี้', 'week': 'เปิดสัปดาห์นี้',
            'month': 'เปิดเดือนนี้', 'all': 'ทุกช่วงเวลา',
        }[date_range]
    filter_summary = ' · '.join([
        range_text,
        dict(Ticket.STATUS_CHOICES).get(status_filter, 'ทุกสถานะ'),
        dict(Ticket.SEVERITY_CHOICES).get(severity_filter, 'ทุกระดับความรุนแรง'),
    ])

    return render(request, 'dashboard/dashboard.html', {
        'filter_summary':      filter_summary,
        'stats':               stats,
        'now':                 now,
        'wazuh_ingest_freshness': wazuh_ingest_freshness,
        'pipeline_by_severity': pipeline_by_severity,
        'pipeline_rows':        pipeline_rows,
        'recent_tickets':      recent_tickets,
        'recent_page':          recent_page,
        'recent_page_links':    recent_page_links,
        'recent_prev_url': (
            case_page_url(recent_page.previous_page_number())
            if recent_page.has_previous() else None
        ),
        'recent_next_url': (
            case_page_url(recent_page.next_page_number())
            if recent_page.has_next() else None
        ),
        'recent_start': (
            recent_page.start_index() if case_paginator.count else 0
        ),
        'recent_end': (
            recent_page.end_index() if case_paginator.count else 0
        ),
        'recent_total': case_paginator.count,
        'recent_sort': sort_key,
        'recent_sort_direction': sort_direction,
        'recent_sort_links': sort_links,
        # ── Management KPIs (Session 3) ────────────────────────────────── #
        'active_total':              active_total,
        'active_critical':           active_critical,
        'critical_soonest_deadline': critical_soonest_deadline,
        'runway':                    runway,
        'ola_filter':                ola_filter,
        'ola_filter_label':          ola_filter_label,
        'closed_this_month':        closed_this_month,
        'closed_last_month':         closed_last_month,
        'closed_delta':              closed_delta,
        'unassigned_active':         unassigned_active,
        'assignee_heatmap':          assignee_heatmap,
        'assignee_heatmap_statuses': assignee_heatmap_statuses,
        'workload_columns':          workload_columns,
        'volume_title':              volume_title,
        'volume_window':             volume_window,
        'daily_trend_filtered':      daily_trend_filtered,
        'daily_trend_labels':        daily_trend_labels,
        'daily_trend_data':          daily_trend_data,
        # Filter bar state
        'status_choices':      Ticket.STATUS_CHOICES,
        'severity_choices':    Ticket.SEVERITY_CHOICES,
        'filters': {
            'date_range': date_range,
            'date_from': date_from.isoformat() if date_from else '',
            'date_to': date_to.isoformat() if date_to else '',
            'status':     status_filter,
            'severity':   severity_filter,
        },
    })


# ====================================================================== #
# Executive dashboard                                                     #
# ====================================================================== #

# Active statuses grouped by whose court the ball is in — the executive
# summary's backbone. Membership follows Ticket.ALLOWED_TRANSITIONS: whoever
# drives the next transition owns the state.
#
# INVARIANT: every non-terminal status appears exactly once. Add a status to
# the FSM → add it here, or the executive verdict goes blind to it (which is
# exactly the bug this replaced). Enforced by
# ExecutiveSummaryCourtTest.test_court_groups_cover_every_active_status_exactly_once.
#
# AWAITING_OWNER sits under EXTERNAL because the executive question is "who
# blocks closure?" (the owner, who must fix it) — even though Tier 1 drives the
# transition out of it. The analyst heatmap on the monitoring dashboard groups
# the same status the other way, under the analyst, because it asks a different
# question: "what must this analyst chase?".
def _incident_count(qs):
    """Count real-world incidents, not ticket rows.

    A Project Incident fans one incident out into N member tickets — one per
    affected system — so a raw .count() reports a 5-system bundle as 5
    incidents. Members of the same bundle collapse to one; unbundled tickets
    stay 1:1 because their own pk is the distinct key.

    Used ONLY for "how many incidents" figures. Status-grain counts (whose
    court, OLA pressure, the pipeline matrix) deliberately keep ticket grain:
    a bundle spans several statuses at once, so collapsing it there is
    meaningless — and five systems really are five units of work.
    """
    return (
        qs.annotate(
            _incident_key=Coalesce('project_incident_id', F('pk') * -1),
        )
        .values('_incident_key')
        .distinct()
        .count()
    )


_EXEC_COURT_GROUPS = {
    'COURT_SOC': [
        Ticket.STATUS_NEW,
        Ticket.STATUS_OWNER_REMEDIATED,
        # A monitored Event sits in its opening Tier 1's court for visibility
        # during the watch (Tier 2 concludes it).
        Ticket.STATUS_MONITORING,
    ],
    'COURT_MANAGER': [
        Ticket.STATUS_PENDING_MGR_TRIAGE,
        Ticket.STATUS_PENDING_MANAGER,
        Ticket.STATUS_PENDING_MGR_EVENT_REVIEW,
    ],
    'COURT_EXTERNAL': [
        Ticket.STATUS_AWAITING_CONTAINMENT,
        Ticket.STATUS_AWAITING_OWNER,
    ],
    'COURT_TIER2': [
        Ticket.STATUS_ESCALATED_T2,
        Ticket.STATUS_CONTAINMENT_REPORTED,
        Ticket.STATUS_PENDING_T2_REVIEW,
    ],
}


# Executive pipeline chart — every workflow status collapsed into a SANS-IR
# phase column. Drives both the stacked bars and the phase drill-down filter.
#
# INVARIANT: every status in Ticket.STATUS_CHOICES (active AND terminal) appears
# here exactly once. A status missing here is silently dropped from the exec
# pipeline and its filter — exactly the bug that hid PENDING_MGR_EVENT_REVIEW
# until 2026-07-23. Enforced by ExecutivePipelinePhaseTest.
_IR_PHASES = [
    ('PREPARATION',    'Preparation',             [Ticket.STATUS_NEW]),
    ('IDENTIFICATION', 'Identification',          [Ticket.STATUS_ESCALATED_T2,
                                                   Ticket.STATUS_PENDING_MGR_TRIAGE,
                                                   # SOC Manager verifying a Tier 2 Event
                                                   # downgrade — a disposition decision, not
                                                   # recovery. Added 2026-07-23.
                                                   Ticket.STATUS_PENDING_MGR_EVENT_REVIEW,
                                                   # Watch-and-wait on a benign Event before
                                                   # Tier 2 disposes of it. Added 2026-09-04.
                                                   Ticket.STATUS_MONITORING]),
    ('CONTAINMENT',    'Containment/Eradication', [Ticket.STATUS_AWAITING_CONTAINMENT,
                                                   Ticket.STATUS_CONTAINMENT_REPORTED,
                                                   Ticket.STATUS_AWAITING_OWNER,
                                                   Ticket.STATUS_OWNER_REMEDIATED]),
    # Recovery = the verification stages (work done, being signed off).
    ('RECOVERY',       'Recovery',                [Ticket.STATUS_PENDING_MANAGER,
                                                   Ticket.STATUS_PENDING_T2_REVIEW]),
    # Lessons Learned = both terminals. APPROVED lived under Recovery until
    # 2026-07-16, which read as "still recovering" for a closed case.
    ('LESSONS',        'Lessons Learned',         [Ticket.STATUS_APPROVED,
                                                   Ticket.STATUS_CLOSED_EVENT]),
    ('CANCELLED',      'ยกเลิกแล้ว',              [Ticket.STATUS_CANCELLED]),
]


# Containment runway: a piecewise time axis (hours to the contain deadline →
# % across the track) so the hours right around the deadline get most of the
# width. Days-to-months overdue share a compressed (log) strip on the left;
# past 180 days a case is summarised per lane, not drawn.
_RUNWAY_FAR_HOURS = -180 * 24
_RUNWAY_LOG_EDGE = -72          # the log strip runs from _RUNWAY_FAR_HOURS to here
_RUNWAY_LOG_PCT = 20
_RUNWAY_SEGMENTS = (
    (-72, -24, 20, 30), (-24, 0, 30, 44), (0, 1, 44, 57), (1, 4, 57, 76), (4, 24, 76, 100),
)
_RUNWAY_TICKS = (
    # (hours, label, minor) — minor ticks are hidden on phones.
    (_RUNWAY_FAR_HOURS, '−180 วัน', True), (-30 * 24, '−30 วัน', True),
    (-7 * 24, '−7 วัน', True), (-72, '−3 วัน', False), (-24, '−24 ชม.', True),
    (0, 'ครบกำหนด', False), (1, '1 ชม.', True), (4, '4 ชม.', False),
    (12, '12 ชม.', True), (24, '24 ชม.', False),
)
# Band labels follow apps/incidents/ola.py's buckets, in the same order.
_RUNWAY_BANDS = (
    (ola_buckets.OVERDUE, 'เกินกำหนด', _RUNWAY_FAR_HOURS, 0),
    (ola_buckets.DUE_1H, '≤ 1 ชม.', 0, ola_buckets.URGENT_HOURS),
    (ola_buckets.DUE_4H, '1–4 ชม.', ola_buckets.URGENT_HOURS, ola_buckets.DUE_SOON_HOURS),
    (ola_buckets.ON_TRACK, 'มากกว่า 4 ชม.', ola_buckets.DUE_SOON_HOURS, 24),
)


def _runway_pct(hours):
    hours = max(float(_RUNWAY_FAR_HOURS), min(24.0, hours))
    if hours < _RUNWAY_LOG_EDGE:
        span = math.log(_RUNWAY_FAR_HOURS / _RUNWAY_LOG_EDGE)
        return round(_RUNWAY_LOG_PCT * (1 - math.log(hours / _RUNWAY_LOG_EDGE) / span), 2)
    for lo, hi, left, right in _RUNWAY_SEGMENTS:
        if hours <= hi:
            return round(left + (hours - lo) / (hi - lo) * (right - left), 2)
    return 100.0


def _containment_runway(active_qs, now, query, ola_filter):
    """Every active case with a contain deadline, placed by time left.

    Same population and buckets as the OLA ควบคุม column and the ?ola= table
    filter (apps/incidents/ola.py): the deadline counts until the case closes.
    Medium/Low have no contain deadline, so they never appear.
    """
    issue_labels = dict(Ticket.DETAILED_ISSUE_CHOICES2)
    status_labels = dict(Ticket.STATUS_CHOICES)
    sev_labels = dict(Ticket.SEVERITY_CHOICES)
    rows = list(
        active_qs.filter(ola_contain_deadline__isnull=False)
        .values('pk', 'ticket_id', 'incident_name', 'detailed_issue2',
                'severity', 'status', 'ola_contain_deadline')
    )

    band_counts = {key: 0 for key, *_ in _RUNWAY_BANDS}
    lanes = {}
    for row in rows:
        deadline = row['ola_contain_deadline']
        hours = (deadline - now).total_seconds() / 3600
        bucket = ola_buckets.bucket_for(deadline, now)
        band_counts[bucket] += 1
        lane = lanes.setdefault(row['severity'], {'dots': [], 'far': 0})
        if hours < _RUNWAY_FAR_HOURS:
            lane['far'] += 1
            continue
        badge = ola_buckets.badge_for(deadline, now=now)
        name = (row['incident_name'] or '').strip() or issue_labels.get(
            row['detailed_issue2'], row['detailed_issue2'] or '')
        lane['dots'].append({
            'pk': row['pk'],
            'pct': _runway_pct(hours),
            'late': hours < 0,
            'dim': bool(ola_filter) and bucket != ola_filter,
            # Hover card lines (the template renders them; see the page script).
            'ticket_id': row['ticket_id'],
            'name': name,
            'sev_label': sev_labels.get(row['severity'], row['severity']),
            'status_label': status_labels.get(row['status'], row['status']),
            'left_label': badge['label'],
        })

    # Stack dots that would overlap: alternate rows above/below the lane's
    # centre line; past the last row they may touch.
    levels = (0, -1, 1, -2, 2)
    lane_list = []
    for sev in sorted(lanes, key=lambda s: Ticket.SEVERITY_RANK.get(s, 0), reverse=True):
        lane = lanes[sev]
        placed = []
        for dot in sorted(lane['dots'], key=lambda d: d['pct']):
            level = next((lv for lv in levels
                          if not any(p[1] == lv and dot['pct'] - p[0] < 1.4 for p in placed)), 0)
            placed.append((dot['pct'], level))
            dot['offset'] = level * 11
        target = Ticket.OLA_TARGETS.get(sev, Ticket.OLA_TARGETS['Unknown'])[1]
        target_hours = int(target.total_seconds() // 3600) if target else None
        lane_list.append({
            'severity': sev,
            'label': sev_labels.get(sev, sev),
            'filled': sev == 'Critical',
            'target': f'เป้า {target_hours} ชม.' if target_hours else '',
            'dots': lane['dots'],
            'far': lane['far'],
            'count': len(lane['dots']) + lane['far'],
        })

    base = query.copy()
    for key in ('page', 'ola'):
        base.pop(key, None)

    def link(bucket):
        params = base.copy()
        if bucket:
            params['ola'] = bucket
        encoded = params.urlencode()
        return ('?' + encoded if encoded else '?') + '#recent-cases'

    bands = [{
        'key': key, 'label': label, 'count': band_counts[key],
        'left': _runway_pct(lo), 'width': round(_runway_pct(hi) - _runway_pct(lo), 2),
        'selected': key == ola_filter,
        'url': link('' if key == ola_filter else key),
    } for key, label, lo, hi in _RUNWAY_BANDS]
    return {
        'total': len(rows),
        'late': band_counts[ola_buckets.OVERDUE],
        'lanes': lane_list,
        'bands': bands,
        'ticks': [{'pct': _runway_pct(h), 'label': label, 'minor': minor, 'zero': h == 0}
                  for h, label, minor in _RUNWAY_TICKS],
        'zero_pct': _runway_pct(0),
        'clear_url': link(''),
        'overdue_url': link(ola_buckets.OVERDUE),
    }


_MONTH_ABBR = ('', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
               'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def _response_flow_series(received_qs, completed_qs, first_day, last_day):
    """Running totals of requests received vs completed across the period.

    The same two counts as the in-vs-out card (received by creation date,
    completed by the date they moved to DONE), just spread over time so the
    card can show whether the gap is new or has been widening. Days are the
    bucket up to ~2 months; longer spans group by week (Monday start).

    ``first_day`` None means "from the first dated request"; ``last_day`` None
    means today. Returns None when the period is a single day (no trend to
    draw) or there is nothing to count.
    """
    def by_date(qs, field):
        return {
            row['d']: row['c']
            for row in qs.order_by().annotate(d=TruncDate(field))
            .values('d').annotate(c=Count('pk'))
            if row['d'] is not None
        }

    received = by_date(received_qs, 'created_at')
    completed = by_date(completed_qs, 'status_changed_at')
    dated = list(received) + list(completed)
    if not dated:
        return None                     # two flat zero lines say nothing
    if first_day is None:
        first_day = min(dated)
    today = timezone.localdate()
    last_day = min(last_day or today, today)   # no flat line into the future
    if last_day <= first_day:
        return None

    weekly = (last_day - first_day).days + 1 > 62
    if weekly:
        def bucket(day):
            return day - timedelta(days=day.weekday())
        step = timedelta(days=7)
    else:
        def bucket(day):
            return day
        step = timedelta(days=1)

    starts = []
    day = bucket(first_day)
    while day <= last_day:
        starts.append(day)
        day += step
    index = {start: i for i, start in enumerate(starts)}
    rec_counts = [0] * len(starts)
    com_counts = [0] * len(starts)
    for counts, source in ((rec_counts, received), (com_counts, completed)):
        for day, count in source.items():
            i = index.get(bucket(day))
            if i is not None:
                counts[i] += count

    def running(counts):
        total, out = 0, []
        for count in counts:
            total += count
            out.append(total)
        return out

    def short(day):
        return f'{day.day} {_MONTH_ABBR[day.month]}'

    rec_cum, com_cum = running(rec_counts), running(com_counts)
    titles = [('สัปดาห์ ' if weekly else '') + f'{short(d)} {d.year}' for d in starts]
    return {
        'unit': 'week' if weekly else 'day',
        'unit_label': 'รายสัปดาห์' if weekly else 'รายวัน',
        'labels': [short(d) for d in starts],
        'titles': titles,
        'received': rec_counts,
        'completed': com_counts,
        'received_cum': rec_cum,
        'completed_cum': com_cum,
        # For the visually-hidden table behind the chart.
        'rows': [
            {'label': t, 'received': r, 'completed': c, 'received_cum': rc, 'completed_cum': cc}
            for t, r, c, rc, cc in zip(titles, rec_counts, com_counts, rec_cum, com_cum)
        ],
    }


@login_required
def executive_dashboard(request):
    """Executive dashboard — glanceable posture summary for management.

    Follows the approved wireframe: KPI cards (total High/Critical count
    with month-over-month delta, 30-day MTTR), a date-scoped
    High/Critical closure progress bar, a six-criteria executive summary
    with an overall GOOD / WAITING / WARNING verdict, the date-scoped
    pipeline chart, and a date-scoped filterable ticket detail table.

    The summary criteria are grouped by "whose court is the ball in" so every
    active status is counted exactly once (see COURT_GROUPS below), plus two
    cross-cutting warning rows (Emergency, OLA overdue).

    Pipeline bars and summary criterion rows deep-link back to this page with
    ?f=<court group | IR phase | status slug | EMERGENCY | OLA_OVERDUE> —
    a single filter, last click wins. date_range scopes the charting/detail
    sections, while the executive verdict stays a live current-posture summary.

    Layout (2026-09-30): four headline KPI cards (Emergency, OLA overdue,
    MTTR, all-time High/Critical), then the response function holding up
    work beside requests in vs out and open High/Critical, then the pipeline
    chart; the criteria, response-team detail and ticket table sit in
    collapsible sections (?open=crit,resp,… or the active filter picks which
    start open; several may be open). The glance layer only re-arranges
    figures computed here — it defines no new metric. No per-ticket list sits
    above the fold on purpose: chasing individual tickets is the SOC
    Manager's job, not the executive's.
    """
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and not (
        profile and getattr(profile, 'is_executive', False)
    ):
        raise PermissionDenied

    now = timezone.now()
    local_now = timezone.localtime(now)
    terminal = list(Ticket.TERMINAL_STATUSES)
    HIGH_CRIT = ('Critical', 'High')

    all_tickets = Ticket.objects.all()
    active_qs = all_tickets.exclude(status__in=terminal)

    # ── Date-range scope ────────────────────────────────────────────────── #
    # A custom from/to range (date_from / date_to, ISO yyyy-mm-dd from the
    # date inputs) takes precedence over the preset buttons. Either bound may
    # be given alone (open-ended); a reversed range is swapped rather than
    # rejected. Bad input parses to None and is ignored.
    def _safe_date(value):
        try:
            return parse_date(value.strip()) if value else None
        except ValueError:
            return None

    date_from = _safe_date(request.GET.get('date_from', ''))
    date_to = _safe_date(request.GET.get('date_to', ''))
    if date_from and date_to and date_from > date_to:
        date_from, date_to = date_to, date_from

    range_tickets = all_tickets
    if date_from or date_to:
        date_range = 'custom'
        if date_from:
            range_tickets = range_tickets.filter(created_at__date__gte=date_from)
        if date_to:
            range_tickets = range_tickets.filter(created_at__date__lte=date_to)
        if date_from and date_to:
            range_label = f'{date_from:%d %b %Y} – {date_to:%d %b %Y}'
        elif date_from:
            range_label = f'ตั้งแต่ {date_from:%d %b %Y}'
        else:
            range_label = f'ถึง {date_to:%d %b %Y}'
    else:
        date_range = request.GET.get('date_range', 'all')
        if date_range not in {'today', 'week', 'month', 'all'}:
            date_range = 'all'
        if date_range == 'today':
            range_tickets = range_tickets.filter(created_at__date=local_now.date())
        elif date_range == 'week':
            week_start = (local_now - timedelta(days=local_now.weekday())).replace(
                hour=0, minute=0, second=0, microsecond=0)
            range_tickets = range_tickets.filter(created_at__gte=week_start)
        elif date_range == 'month':
            month_start = local_now.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0)
            range_tickets = range_tickets.filter(created_at__gte=month_start)
        range_label = {
            'today': 'วันนี้',
            'week': 'สัปดาห์นี้',
            'month': 'เดือนนี้',
            'all': 'ทุกช่วงเวลา',
        }[date_range]
    range_active_qs = range_tickets.exclude(status__in=terminal)

    # Response requests have their own dates. The selected period applies to
    # requests received/completed; outstanding work is always the live queue.
    response_date_q = Q()
    if date_range == 'custom':
        if date_from:
            response_date_q &= Q(created_at__date__gte=date_from)
        if date_to:
            response_date_q &= Q(created_at__date__lte=date_to)
    elif date_range == 'today':
        response_date_q = Q(created_at__date=local_now.date())
    elif date_range == 'week':
        response_date_q = Q(created_at__gte=week_start)
    elif date_range == 'month':
        response_date_q = Q(created_at__gte=month_start)

    # Reuse the same boundaries for completion. status_changed_at records the
    # transition into DONE for current rows; the legacy migration seeded it
    # from updated_at, so historical completion dates are approximate.
    completed_date_q = Q()
    if date_range == 'custom':
        if date_from:
            completed_date_q &= Q(status_changed_at__date__gte=date_from)
        if date_to:
            completed_date_q &= Q(status_changed_at__date__lte=date_to)
    elif date_range == 'today':
        completed_date_q = Q(status_changed_at__date=local_now.date())
    elif date_range == 'week':
        completed_date_q = Q(status_changed_at__gte=week_start)
    elif date_range == 'month':
        completed_date_q = Q(status_changed_at__gte=month_start)

    response_types = [
        (TicketSubtask.TYPE_VA, 'VA'),
        (TicketSubtask.TYPE_PENTEST, 'PenTest'),
        (TicketSubtask.TYPE_HARDENING, 'Hardening'),
        (TicketSubtask.TYPE_FORENSIC_RCA, 'Forensics / RCA'),
        (TicketSubtask.TYPE_VA_PT, 'VA/PT (เดิม)'),
        (TicketSubtask.TYPE_INFRA_SEC, 'Hardening (เดิม)'),
    ]
    active_response_q = (
        Q(status__in=(TicketSubtask.STATUS_OPEN, TicketSubtask.STATUS_IN_PROGRESS))
        & ~Q(ticket__status__in=terminal)
    )
    response_qs = TicketSubtask.objects.filter(
        subtask_type__in=TicketSubtask.RESPONSE_TYPES)
    aged_before = now - timedelta(days=7)
    response_counts = {
        row['subtask_type']: row for row in response_qs.values('subtask_type').annotate(
            active=Count('pk', filter=active_response_q),
            received=Count('pk', filter=response_date_q),
            completed=Count('pk', filter=Q(status=TicketSubtask.STATUS_DONE) & completed_date_q),
            aged=Count('pk', filter=active_response_q & Q(created_at__lt=aged_before)),
        )
    }
    configured_managers = {
        p.redteam_function: p.user.get_full_name() or p.user.username
        for p in UserProfile.objects.filter(
            role=UserProfile.ROLE_REDTEAM_MANAGER,
            redteam_function__in=(
                UserProfile.REDTEAM_VA, UserProfile.REDTEAM_PENTEST,
                UserProfile.REDTEAM_HARDENING,
            ),
        ).select_related('user')
    }
    response_functions = []
    for type_key, label in response_types:
        counts = response_counts.get(type_key, {})
        if type_key in (TicketSubtask.TYPE_VA_PT, TicketSubtask.TYPE_INFRA_SEC) and not counts:
            continue
        manager = configured_managers.get(type_key, 'ยังไม่กำหนด')
        if type_key == TicketSubtask.TYPE_FORENSIC_RCA:
            manager = 'Forensic Analyst'
        elif type_key in (TicketSubtask.TYPE_VA_PT, TicketSubtask.TYPE_INFRA_SEC):
            manager = 'ตามคำขอเดิม'
        response_functions.append({
            'type': type_key, 'label': label, 'manager': manager,
            'active': counts.get('active', 0), 'received': counts.get('received', 0),
            'completed': counts.get('completed', 0), 'aged': counts.get('aged', 0),
        })
    response_totals = {
        key: sum(row[key] for row in response_functions)
        for key in ('active', 'received', 'completed', 'aged')
    }
    response_hc_tickets = response_qs.filter(
        active_response_q, ticket__severity__in=('Critical', 'High'),
    ).values('ticket_id').distinct().count()

    response_type = request.GET.get('response_type', '')
    if response_type not in {key for key, _ in response_types}:
        response_type = ''
    response_status = request.GET.get('response_status', 'ACTIVE')
    if response_status not in {
        'ACTIVE', 'OPEN', 'IN_PROGRESS', 'DONE', 'RECEIVED', 'AGED', 'HIGH_CRIT',
    }:
        response_status = 'ACTIVE'
    def _response_filtered(status):
        """Requests behind one status filter (and the selected function)."""
        qs = response_qs
        if response_type:
            qs = qs.filter(subtask_type=response_type)
        if status == 'DONE':
            return qs.filter(status=TicketSubtask.STATUS_DONE).filter(completed_date_q)
        if status == 'RECEIVED':
            return qs.filter(response_date_q)
        qs = qs.filter(active_response_q)
        if status in {'OPEN', 'IN_PROGRESS'}:
            qs = qs.filter(status=status)
        elif status == 'AGED':
            qs = qs.filter(created_at__lt=aged_before)
        elif status == 'HIGH_CRIT':
            qs = qs.filter(ticket__severity__in=('Critical', 'High'))
        return qs

    # Counts for the filter pills the page shows. OPEN / IN_PROGRESS stay
    # valid URL values (older links) but no longer get a pill of their own.
    response_status_counts = {
        status: _response_filtered(status).count()
        for status in ('ACTIVE', 'AGED', 'HIGH_CRIT', 'RECEIVED', 'DONE')
    }
    response_detail_qs = _response_filtered(response_status).select_related(
        'ticket', 'assigned_to')
    if response_status == 'DONE':
        response_detail_qs = response_detail_qs.order_by('-status_changed_at', '-pk')
    elif response_status == 'RECEIVED':
        response_detail_qs = response_detail_qs.order_by('-created_at', '-pk')
    else:
        # High/Critical and older outstanding requests surface first.
        response_detail_qs = response_detail_qs.annotate(
            severity_rank=Case(
                When(ticket__severity='Critical', then=Value(0)),
                When(ticket__severity='High', then=Value(1)),
                default=Value(2),
            ),
        ).order_by('severity_rank', 'created_at', 'pk')
    response_page_obj = Paginator(response_detail_qs, 8).get_page(
        request.GET.get('response_page'))
    response_requests = list(response_page_obj.object_list)
    for item in response_requests:
        age_end = (
            item.status_changed_at
            if item.status in TicketSubtask.TERMINAL_STATUSES and item.status_changed_at
            else now
        )
        item.age_days = max(0, (
            timezone.localtime(age_end).date() - timezone.localtime(item.created_at).date()
        ).days)

    # MTTR intentionally stays on a fixed rolling 30-day window rather than
    # following the dashboard's date-range control. This matches the SOC
    # dashboard definition and keeps the executive KPI comparable over time.
    executive_resolved_qs = _with_resolved_at(
        all_tickets.filter(status__in=Ticket.RESOLVED_STATUSES)
    )
    mttr_stats = _mttr_stats(executive_resolved_qs, now)

    # ── KPI 1: all-time High/Critical total + month-to-date comparison ───── #
    # Incident grain, not ticket grain — see _incident_count. The executive
    # view answers "how many incidents", so a multi-system bundle counts once.
    total_hc = _incident_count(all_tickets.filter(severity__in=HIGH_CRIT))

    this_month_start = local_now.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0)
    previous_month_last_day = this_month_start.date() - timedelta(days=1)
    previous_month_start = this_month_start.replace(
        year=previous_month_last_day.year,
        month=previous_month_last_day.month,
    )
    comparison_days = min(local_now.day, previous_month_last_day.day)
    previous_month_cutoff = previous_month_start + timedelta(days=comparison_days)

    this_month_hc = _incident_count(
        all_tickets
        .filter(
            severity__in=HIGH_CRIT,
            created_at__gte=this_month_start,
            created_at__lte=now,
        )
    )
    previous_month_hc = _incident_count(
        all_tickets
        .filter(
            severity__in=HIGH_CRIT,
            created_at__gte=previous_month_start,
            created_at__lt=previous_month_cutoff,
        )
    )
    total_hc_delta = this_month_hc - previous_month_hc

    # ── Progress bar: closure rate over ALL High/Critical tickets ───────── #
    hc_range = range_tickets.filter(severity__in=HIGH_CRIT).exclude(status=Ticket.STATUS_CANCELLED)
    hc_total = _incident_count(hc_range)
    # A bundle counts as closed only when EVERY member is (matches
    # ProjectIncident.all_closed) — otherwise a partly-contained bundle would
    # be both open and closed, and the two would not sum to hc_total.
    hc_open = _incident_count(hc_range.exclude(status__in=terminal))
    hc_closed = hc_total - hc_open
    hc_progress_pct = round(hc_closed / hc_total * 100) if hc_total else 0

    # ── Executive summary — 6 criteria, priority Warning > Waiting > Good ─ #
    #
    # Grouped by whose court the ball is in (_EXEC_COURT_GROUPS), so every
    # ACTIVE status is counted exactly once and the verdict can never read GOOD
    # while work is queued somewhere. The two warning rows are cross-cutting (an
    # emergency or an overdue case may sit in any court), so a ticket can appear
    # in one warning row AND one court row — that is intentional: the warnings
    # answer "is anything on fire?", the court rows "who is holding it?".
    COURT_GROUPS = _EXEC_COURT_GROUPS

    # Incident grain: the Emergency verdict is decided ONCE at Project Review
    # and inherited by every member, so a single emergency call must not read
    # as N emergencies here.
    emergency_active = _incident_count(active_qs.filter(is_emergency=True))
    # Live contain-OLA breach (mirrors Ticket.is_ola_contain_breached). Medium/
    # Low have no contain deadline, so they never count here.
    ola_overdue = active_qs.filter(
        ola_contain_deadline__lt=now,
    ).count()
    # Cross-cutting (like Emergency / OLA): active cases with an outstanding
    # response-team request (Forensic / Red Team). These block final approval
    # (Ticket.has_open_response_requests) but may sit in any court, so this is an
    # overlay row, not a court group. Mirrors the ORM form of that property.
    response_pending = active_qs.filter(
        subtasks__subtask_type__in=TicketSubtask.RESPONSE_TYPES,
        subtasks__status__in=(
            TicketSubtask.STATUS_OPEN, TicketSubtask.STATUS_IN_PROGRESS,
        ),
    ).distinct().count()
    court_counts = {
        key: active_qs.filter(status__in=sts).count()
        for key, sts in COURT_GROUPS.items()
    }

    summary_criteria = [
        {
            'label': 'เคสฉุกเฉิน (Emergency) ที่ยังไม่ปิด',
            'count': emergency_active,
            'level': 'warning' if emergency_active else 'good',
            'filter': 'EMERGENCY',
        },
        {
            'label': 'เคสที่เกินกำหนด OLA',
            'count': ola_overdue,
            'level': 'warning' if ola_overdue else 'good',
            'filter': 'OLA_OVERDUE',
        },
        {
            'label': 'เคสที่รอ SOC (Tier 1) ดำเนินการ',
            'count': court_counts['COURT_SOC'],
            'level': 'waiting' if court_counts['COURT_SOC'] else 'good',
            'filter': 'COURT_SOC',
        },
        {
            'label': 'เคสที่รอผู้จัดการ SOC',
            'count': court_counts['COURT_MANAGER'],
            'level': 'waiting' if court_counts['COURT_MANAGER'] else 'good',
            'filter': 'COURT_MANAGER',
        },
        {
            'label': 'เคสที่รอผู้ดูแลระบบ / เจ้าของระบบ',
            'count': court_counts['COURT_EXTERNAL'],
            'level': 'waiting' if court_counts['COURT_EXTERNAL'] else 'good',
            'filter': 'COURT_EXTERNAL',
        },
        {
            'label': 'เคสที่รอ Tier 2 ตรวจสอบ',
            'count': court_counts['COURT_TIER2'],
            'level': 'waiting' if court_counts['COURT_TIER2'] else 'good',
            'filter': 'COURT_TIER2',
        },
        {
            'label': 'เคสที่รอทีมตอบสนอง (Forensic Analyst / Red Team Manager)',
            'count': response_pending,
            'level': 'waiting' if response_pending else 'good',
            'filter': 'RESPONSE_PENDING',
        },
    ]
    if any(c['level'] == 'warning' for c in summary_criteria):
        overall_status = 'WARNING'
    elif any(c['level'] == 'waiting' for c in summary_criteria):
        overall_status = 'WAITING'
    else:
        overall_status = 'GOOD'

    # Criteria tallies for the collapsed summary of the criteria section.
    active_total = sum(court_counts.values())
    level_counts = {
        level: sum(1 for c in summary_criteria if c['level'] == level)
        for level in ('warning', 'waiting', 'good')
    }

    # ── Pipeline — executive view tracks only High/Critical cases, grouped by
    # SANS-IR phase: several workflow statuses collapse into one phase column.
    # Emergency counts are a subset overlay per phase, not an extra segment.
    status_map = dict(Ticket.STATUS_CHOICES)
    phase_order = [key for key, _, _ in _IR_PHASES]
    phase_display = {key: label for key, label, _ in _IR_PHASES}
    phase_statuses = {key: sts for key, _, sts in _IR_PHASES}
    status_to_phase = {st: key for key, _, sts in _IR_PHASES for st in sts}

    sev_display = dict(Ticket.SEVERITY_CHOICES)
    severity_order = sorted(
        (s for s in sev_display if s in HIGH_CRIT),
        key=lambda s: Ticket.SEVERITY_RANK.get(s, 0),
        reverse=True,
    )
    pipeline_matrix = {
        sev: {ph: 0 for ph in phase_order} for sev in severity_order
    }
    pipeline_qs = range_tickets.filter(severity__in=HIGH_CRIT)
    for row in pipeline_qs.values('severity', 'status').annotate(c=Count('id')):
        sev, ph = row['severity'], status_to_phase.get(row['status'])
        if ph and sev in pipeline_matrix:
            pipeline_matrix[sev][ph] += row['c']
    emergency_by_status = {ph: 0 for ph in phase_order}
    for row in (
        pipeline_qs
        .filter(is_emergency=True)
        .values('status')
        .annotate(c=Count('id'))
    ):
        ph = status_to_phase.get(row['status'])
        if ph:
            emergency_by_status[ph] += row['c']
    pipeline_by_severity = {
        'statuses': [(ph, phase_display[ph]) for ph in phase_order],
        'severities': [(s, sev_display[s]) for s in severity_order],
        'matrix': pipeline_matrix,
        'emergency_by_status': emergency_by_status,
    }
    pipeline_rows = [
        {'severity': sev_display[sev],
         'cells': [pipeline_matrix[sev][ph] for ph in phase_order]}
        for sev in severity_order
    ]
    pipeline_emergency_row = [emergency_by_status[ph] for ph in phase_order]

    # ── Detail table — single ?f= filter, last click wins ───────────────── #
    f = request.GET.get('f', '')
    filter_label = ''
    court_labels = {c['filter']: c['label'] for c in summary_criteria}
    if f == 'EMERGENCY':
        table_qs = range_active_qs.filter(is_emergency=True)
        filter_label = 'เคสฉุกเฉิน (Emergency)'
    elif f == 'OLA_OVERDUE':
        # Live breach — same rule as the summary criterion above.
        table_qs = range_active_qs.filter(ola_contain_deadline__lt=now)
        filter_label = court_labels.get(f, 'เคสที่เกินกำหนด OLA')
    elif f == 'RESPONSE_PENDING':
        # Cross-cutting — active cases with an open response-team request.
        table_qs = range_active_qs.filter(
            subtasks__subtask_type__in=TicketSubtask.RESPONSE_TYPES,
            subtasks__status__in=(
                TicketSubtask.STATUS_OPEN, TicketSubtask.STATUS_IN_PROGRESS,
            ),
        ).distinct()
        filter_label = court_labels.get(f, 'เคสที่รอทีมตอบสนอง')
    elif f in COURT_GROUPS:
        # Summary rows span several statuses (grouped by whose court), so they
        # filter on the whole group. Active-only: a court is about pending work.
        table_qs = range_active_qs.filter(status__in=COURT_GROUPS[f])
        filter_label = court_labels.get(f, f)
    elif f in phase_statuses:
        # Pipeline bars are SANS-IR phases, each covering one or more statuses.
        table_qs = range_tickets.filter(status__in=phase_statuses[f])
        filter_label = phase_display[f]
    elif f in status_map:
        # A status filter may target a terminal status (pipeline "close" bars),
        # so it searches the date-scoped tickets, not just the active queue.
        table_qs = range_tickets.filter(status=f)
        filter_label = status_map[f]
    else:
        f = ''
        table_qs = range_active_qs
    # Optional High/Critical-only view of whatever the filter selected. Phase
    # drill-downs otherwise list every severity while the pipeline counts only
    # High/Critical, so this is how the two line up.
    hc_only = request.GET.get('sev') == 'hc'
    if hc_only:
        table_qs = table_qs.filter(severity__in=HIGH_CRIT)
    phase_hc_count = None
    if f in phase_statuses:
        phase_hc_count = sum(pipeline_matrix[sev][f] for sev in severity_order)
    table_qs = (
        # project_incident is needed for the bundle badge — Ticket.bundle_ref
        # dereferences it, so without this the table costs a query per row.
        table_qs.select_related(
            'assigned_to', 'assigned_admin', 'project_incident')
        .annotate(status_age_anchor=Coalesce('status_changed_at', 'created_at'))
        # Put cases that have sat longest in their current status first. Notes
        # and other edits do not reset status_changed_at, unlike updated_at.
        .order_by('status_age_anchor', 'created_at', 'pk')
    )
    paginator = Paginator(table_qs, 10)
    page_obj = paginator.get_page(request.GET.get('page'))
    table_tickets = list(page_obj.object_list)
    for ticket in table_tickets:
        ticket.status_started_at = ticket.status_changed_at or ticket.created_at
        status_age_minutes = max(
            0, int((now - ticket.status_started_at).total_seconds() // 60))
        ticket.status_age_label = humanize_minutes(status_age_minutes)

    # ── Glance layer (headline + answer cards) ────────────────────────── #
    # Presentation only: every figure is one computed above, re-arranged so
    # the page answers "what now / which function / in vs out / which
    # High/Critical" before any detail is opened.
    max_function_active = max(
        (row['active'] for row in response_functions), default=0) or 1
    for row in response_functions:
        row['fresh_pct'] = round(
            (row['active'] - row['aged']) / max_function_active * 100)
        row['aged_pct'] = round(row['aged'] / max_function_active * 100)
    # The function holding up the most work: most requests older than 7 days,
    # then most outstanding. Ties keep the canonical function order.
    response_top = (
        max(response_functions, key=lambda row: (row['aged'], row['active']))
        if response_totals['active'] else None
    )
    flow_max = max(response_totals['received'], response_totals['completed']) or 1
    response_flow = {
        'diff': response_totals['received'] - response_totals['completed'],
        'received_pct': round(response_totals['received'] / flow_max * 100),
        'completed_pct': round(response_totals['completed'] / flow_max * 100),
    }
    response_flow['abs_diff'] = abs(response_flow['diff'])
    # The same two counts over time. 'today' is one bucket — no trend — so the
    # card keeps its two bars there.
    flow_first = flow_last = None
    if date_range == 'week':
        flow_first = week_start.date()
    elif date_range == 'month':
        flow_first = month_start.date()
    elif date_range == 'custom':
        flow_first, flow_last = date_from, date_to
    response_flow_series = None
    if date_range != 'today':
        response_flow_series = _response_flow_series(
            response_qs.filter(response_date_q),
            response_qs.filter(completed_date_q, status=TicketSubtask.STATUS_DONE),
            flow_first, flow_last,
        )

    # Open High/Critical Tickets in the range — the same rows the detail table
    # shows with ?sev=hc, which is where the card's link lands.
    hc_open_tickets = range_active_qs.filter(severity__in=HIGH_CRIT).count()

    # Which detail sections start open — any number of them. ?open=crit,resp
    # is taken as-is when present (the page's script sends exactly what the
    # viewer has open, plus the section a link points into); without it, open
    # whichever sections the URL is filtering.
    section_keys = ('crit', 'resp', 'tickets')
    if 'open' in request.GET:
        requested = set(request.GET.get('open', '').split(','))
        open_sections = [key for key in section_keys if key in requested]
    else:
        open_sections = []
        if {'response_type', 'response_status', 'response_page'} & set(request.GET):
            open_sections.append('resp')
        if f or hc_only or 'page' in request.GET:
            open_sections.append('tickets')

    # Query-string pieces the template reuses. range_query is always the three
    # date keys in this order; keep_query carries the non-default filters so a
    # date change does not drop them. Values are whitelisted or ISO dates.
    range_query = urlencode([
        ('date_range', date_range),
        ('date_from', date_from.isoformat() if date_from else ''),
        ('date_to', date_to.isoformat() if date_to else ''),
    ])
    keep_params = []
    if f:
        keep_params.append(('f', f))
    if response_type:
        keep_params.append(('response_type', response_type))
    if response_status != 'ACTIVE':
        keep_params.append(('response_status', response_status))
    if hc_only:
        keep_params.append(('sev', 'hc'))
    if open_sections:
        keep_params.append(('open', ','.join(open_sections)))
    keep_query = ('&' + urlencode(keep_params, safe=',')) if keep_params else ''

    # Short "what you are looking at" labels the page flashes on the results
    # after a filter changes them.
    response_status_label = {
        'ACTIVE': 'ค้างทั้งหมด', 'OPEN': 'รอรับงาน', 'IN_PROGRESS': 'กำลังทำ',
        'AGED': 'ค้างเกิน 7 วัน', 'HIGH_CRIT': 'ของ Ticket High/Critical',
        'RECEIVED': f'รับเข้า · {range_label}', 'DONE': f'ส่งงาน · {range_label}',
    }[response_status]
    response_type_label = dict(response_types).get(response_type, '')
    requests_flash = ' · '.join(filter(None, [
        response_status_label, response_type_label,
        f'{response_page_obj.paginator.count:,} คำขอ',
    ]))
    tickets_flash = ' · '.join(filter(None, [
        filter_label or f'Ticket ที่ยังไม่ปิด · {range_label}',
        'เฉพาะ High/Critical' if hc_only else '',
        f'{paginator.count:,} Ticket',
    ]))

    return render(request, 'dashboard/executive.html', {
        'requests_flash': requests_flash,
        'tickets_flash': tickets_flash,
        'range_query': range_query,
        'keep_query': keep_query,
        'cancelled_count': range_tickets.filter(status=Ticket.STATUS_CANCELLED).count(),
        'now': now,
        'wazuh_ingest_freshness': _wazuh_ingest_freshness(now),
        'total_hc': total_hc,
        'total_hc_delta': total_hc_delta,
        'emergency_active': emergency_active,
        'hc_total': hc_total,
        'hc_closed': hc_closed,
        'hc_open': hc_open,
        'hc_progress_pct': hc_progress_pct,
        **mttr_stats,
        'summary_criteria': summary_criteria,
        'overall_status': overall_status,
        'pipeline_by_severity': pipeline_by_severity,
        'pipeline_rows': pipeline_rows,
        'pipeline_emergency_row': pipeline_emergency_row,
        'response_functions': response_functions,
        'response_totals': response_totals,
        'response_hc_tickets': response_hc_tickets,
        'response_type': response_type,
        'response_status': response_status,
        'response_requests': response_requests,
        'response_page_obj': response_page_obj,
        'response_status_counts': response_status_counts,
        'response_top': response_top,
        'response_flow': response_flow,
        'response_flow_series': response_flow_series,
        'level_counts': level_counts,
        'active_total': active_total,
        'ola_overdue': ola_overdue,
        'hc_open_tickets': hc_open_tickets,
        'phase_hc_count': phase_hc_count,
        'hc_only': hc_only,
        'open_sections': open_sections,
        'table_tickets': table_tickets,
        'page_obj': page_obj,
        'filter_f': f,
        'filter_label': filter_label,
        'filters': {
            'date_range': date_range,
            'range_label': range_label,
            'date_from': date_from.isoformat() if date_from else '',
            'date_to': date_to.isoformat() if date_to else '',
        },
    })
