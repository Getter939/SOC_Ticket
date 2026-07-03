from datetime import timedelta
from statistics import mean as _mean, median as _median

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import (
    Case, Count, F, IntegerField, OuterRef, Q, Subquery, Value, When,
)
from django.db.models.functions import Coalesce, TruncDate, TruncHour
from django.shortcuts import redirect, render
from django.utils import timezone

from apps.incidents import ola as ola_buckets
from apps.incidents.models import Ticket, TicketLog

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
# STEP 0 findings (Session 3):                                           #
#   STATUS_CHOICES (order / slug → display):                            #
#     NEW                  → แจ้งเหตุใหม่                                  #
#     ESCALATED_T2         → ส่งต่อให้ Tier 2                             #
#     T1_REVIEW            → รอ Tier 1 ทบทวน                             #
#     AWAITING_CONTAINMENT → รอการจัดการจากผู้ดูแลระบบ                    #
#     CONTAINMENT_REPORTED → รายงานการควบคุมแล้ว                          #
#     PENDING_MANAGER      → รอผู้จัดการตรวจสอบ                           #
#     APPROVED             → อนุมัติแล้ว        (terminal)                #
#     CLOSED_EVENT         → ปิด (Event)        (terminal)               #
#   Non-terminal = the first 6; terminal = {APPROVED, CLOSED_EVENT}.     #
#   Threat type → Ticket.detailed_issue (DETAILED_ISSUE_CHOICES); source #
#     channel → issue_type. (The Event/Incident axis is classification.)  #
#   Containment deadline → Ticket.ola_contain_deadline (per-severity;     #
#     null for Medium/Low = notification-only).                          #
# ====================================================================== #

@login_required
def dashboard(request):
    # System Owners see their own portal, not the SOC dashboard
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and profile and profile.is_system_owner:
        from django.shortcuts import redirect
        return redirect('system_owner_dashboard')
    if not request.user.is_superuser and profile and profile.is_system_admin:
        from django.shortcuts import redirect
        return redirect('ticket_list')

    today = timezone.now()
    now   = today
    terminal = list(Ticket.TERMINAL_STATUSES)

    # ── GET filters: date_range / status / severity ──────────────────────── #
    # Presentation-level scoping only. Default 'all' / '' preserves the
    # original unfiltered behavior, so existing callers are unaffected.
    date_range      = request.GET.get('date_range', 'all')
    status_filter   = request.GET.get('status', '')
    severity_filter = request.GET.get('severity', '')

    all_tickets = Ticket.objects.all()

    if date_range == 'today':
        all_tickets = all_tickets.filter(created_at__date=now.date())
    elif date_range == 'week':
        week_start = (now - timedelta(days=now.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0)
        all_tickets = all_tickets.filter(created_at__gte=week_start)
    elif date_range == 'month':
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        all_tickets = all_tickets.filter(created_at__gte=month_start)

    if severity_filter:
        all_tickets = all_tickets.filter(severity=severity_filter)

    if status_filter:
        all_tickets = all_tickets.filter(status=status_filter)

    active_qs   = all_tickets.exclude(status__in=terminal)
    closed_qs   = all_tickets.filter(status__in=terminal)

    # ── Resolution timestamp (no resolved_at field — derive from TicketLog) ─ #
    # First time the ticket entered a terminal state. Coalesced with
    # approved_at / updated_at for rows seeded straight into a terminal state.
    first_terminal_log = (
        TicketLog.objects
        .filter(ticket=OuterRef('pk'), status_at_time__in=terminal)
        .order_by('created_at')
        .values('created_at')[:1]
    )
    resolved_at_expr = Coalesce(
        Subquery(first_terminal_log), F('approved_at'), F('updated_at'),
    )
    resolved_qs = closed_qs.annotate(resolved_at=resolved_at_expr)

    # ── MTTR over the last 30 days (hours), median/mean/n ─────────────────── #
    # resolved_at is derived from TicketLog, so it always exists; median is
    # computed in Python to stay database-agnostic.
    thirty_days_ago = now - timedelta(days=30)
    mttr_rows = (
        resolved_qs.filter(resolved_at__gte=thirty_days_ago)
        .values_list('resolved_at', 'created_at')
    )
    mttr_hours = [
        (resolved - created).total_seconds() / 3600
        for resolved, created in mttr_rows
        if resolved and created and resolved >= created
    ]
    if mttr_hours:
        mttr_n      = len(mttr_hours)
        mttr_median = round(_median(mttr_hours), 1)
        mttr_mean   = round(_mean(mttr_hours), 1)
    else:
        mttr_n      = 0
        mttr_median = None
        mttr_mean   = None

    stats = {
        'active':          active_qs.count(),
        'mttr_median':         mttr_median,            # hours, last 30 days (None if none)
        'mttr_mean':           mttr_mean,              # hours, last 30 days (None if none)
        'mttr_n':              mttr_n,                 # count of resolved in last 30 days
    }

    # ── Pipeline chart — all 7 statuses ──────────────────────────────────── #
    status_map   = dict(Ticket.STATUS_CHOICES)
    status_order = [s for s, _ in Ticket.STATUS_CHOICES]
    # ── Pipeline by severity × status (stacked-bar source) ───────────────── #
    # statuses: STATUS_CHOICES progression order (earliest → terminal).
    # severities: SEVERITY_RANK order, HIGHEST first (Critical=4 … Unknown=0).
    # All tickets (incl. terminal) so the funnel is complete; respects the
    # active GET filters via all_tickets. Single group-by query (no N+1);
    # the matrix is zero-filled so every status appears under every severity.
    sev_display      = dict(Ticket.SEVERITY_CHOICES)
    severity_order   = sorted(
        sev_display, key=lambda s: Ticket.SEVERITY_RANK.get(s, 0), reverse=True)
    pipeline_matrix  = {
        sev: {st: 0 for st in status_order} for sev in severity_order
    }
    for row in all_tickets.values('severity', 'status').annotate(c=Count('id')):
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

    # ── By Threat Type doughnut ──────────────────────────────────────────── #
    # Distribution of all tickets by detailed_issue (the threat type —
    # Malicious Logic, Reconnaissance, DoS, …). Display labels via
    # DETAILED_ISSUE_CHOICES; blank/unset excluded so the chart stays clean.
    detailed_display = dict(Ticket.DETAILED_ISSUE_CHOICES)
    by_category = list(
        all_tickets.exclude(detailed_issue__isnull=True).exclude(detailed_issue='')
                   .values('detailed_issue').annotate(count=Count('id')).order_by('-count')
    )
    # Cap to top 5 + an aggregated "อื่นๆ" (Others) bucket so the doughnut
    # stays readable (presentation only — see STEP 6c).
    top_cat = by_category[:5]
    rest_cat = by_category[5:]
    by_category_labels = [detailed_display.get(b['detailed_issue'], b['detailed_issue']) for b in top_cat]
    by_category_data   = [b['count'] for b in top_cat]
    if rest_cat:
        by_category_labels.append('อื่นๆ')
        by_category_data.append(sum(b['count'] for b in rest_cat))

    # ── Recent active cases — full active queue for the detail table ──────── #
    # The ENTIRE active queue is sent to the template (not a 15-row slice) so
    # the client-side script can sort + paginate the whole dataset without a
    # page reload (see the recent-cases <script> in dashboard.html). Default
    # server-side order — severity DESC (Critical first), then created_at DESC —
    # is also the table's initial order and the no-JS fallback.
    #
    # severity is a CharField, so ordering on it alphabetically would be wrong
    # (Critical < High < Low …). Annotate the SEVERITY_RANK weight and sort on
    # that instead; the weight is also emitted as a data-attribute for the JS.
    sev_rank_whens = [
        When(severity=slug, then=Value(rank))
        for slug, rank in Ticket.SEVERITY_RANK.items()
    ]
    recent_tickets = list(
        active_qs.select_related('assigned_to')
        .annotate(sev_rank=Case(
            *sev_rank_whens, default=Value(0), output_field=IntegerField()))
        .order_by('-sev_rank', '-created_at')
    )

    # ── Pre-zipped (label, value) pairs for the visually-hidden a11y tables ─ #
    chart_tables = {
        'by_category':    list(zip(by_category_labels, by_category_data)),
    }

    # ====================================================================== #
    # Management dashboard KPIs (Session 3) — additive.                       #
    # Audience: management. Everything respects the active GET filters        #
    # (date_range / status / severity).                                       #
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
        critical_soonest_deadline = {
            'ticket_id': crit_soonest['ticket_id'],
            'minutes_remaining': round(
                (crit_soonest['ola_contain_deadline'] - now).total_seconds() / 60),
        }
    else:
        critical_soonest_deadline = None

    # Closed this / last calendar month — terminal-entry time from the log.
    this_month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last_month_start = (this_month_start - timedelta(days=1)).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0)
    closed_this_month = resolved_qs.filter(resolved_at__gte=this_month_start).count()
    closed_last_month = resolved_qs.filter(
        resolved_at__gte=last_month_start, resolved_at__lt=this_month_start).count()
    closed_delta = closed_this_month - closed_last_month

    # Assignee heatmap — ALL analysts, counts per non-terminal status.
    assignee_heatmap_statuses = [
        (s, status_map[s]) for s in status_order if s not in terminal
    ]
    heatmap_slugs = [s for s, _ in assignee_heatmap_statuses]
    heat = {}
    for r in (active_qs.filter(assigned_to__isnull=False)
              .values('assigned_to', 'assigned_to__first_name',
                      'assigned_to__last_name', 'assigned_to__username', 'status')
              .annotate(c=Count('id'))):
        uid = r['assigned_to']
        if uid not in heat:
            name = (f"{r['assigned_to__first_name']} "
                    f"{r['assigned_to__last_name']}").strip() \
                or r['assigned_to__username']
            heat[uid] = {'name': name, 'counts': {}, 'total': 0}
        heat[uid]['counts'][r['status']] = r['c']
        heat[uid]['total'] += r['c']
    assignee_heatmap = sorted(heat.values(), key=lambda x: x['total'], reverse=True)
    # Template can't index a dict by a loop variable — pre-build status-ordered
    # cell lists aligned to assignee_heatmap_statuses.
    for a in assignee_heatmap:
        a['cells'] = [a['counts'].get(s, 0) for s in heatmap_slugs]

    # Avg MTTR by threat type (hours), last 30 days, ≥2 resolved per type.
    # NOTE: computed but not currently rendered (the Row 3 MTTR panel was
    # removed in Session 3C); kept available should the panel return.
    # OLA pressure — active queue bucketed by time-to-deadline. Answers the
    # manager's "what needs attention now?" Each bucket carries its severity mix
    # so a Critical that's overdue stands out (tooltip). Respects the same active
    # GET filters as the other active panels. Bucket thresholds live in
    # apps.incidents.ola (single source of truth, shared with the list filter).
    # Only tickets WITH a contain deadline are bucketed — Medium/Low are
    # notification-only (no contain OLA), so they're excluded from the chart.
    ola_sev_order = ['Critical', 'High', 'Medium', 'Low', 'Unknown']
    ola_counts = {key: {} for key, _, _ in ola_buckets.OLA_BUCKETS}
    for r in (active_qs.filter(ola_contain_deadline__isnull=False)
              .annotate(ola_bucket=ola_buckets.bucket_case(now))
              .values('ola_bucket', 'severity').annotate(c=Count('id'))):
        bucket = ola_counts.get(r['ola_bucket'])
        if bucket is not None:
            sev = r['severity'] if r['severity'] in ola_sev_order else 'Unknown'
            bucket[sev] = bucket.get(sev, 0) + r['c']
    ola_pressure = [
        {
            'key':   key,
            'label': label,
            'color': color,
            'count': sum(ola_counts[key].values()),
            'severities': [
                {'label': sev, 'count': ola_counts[key][sev]}
                for sev in ola_sev_order if ola_counts[key].get(sev)
            ],
        }
        for key, label, color in ola_buckets.OLA_BUCKETS
    ]
    # Headline: active cases needing attention now (overdue + due within 1h).
    ola_attention = (sum(ola_counts[ola_buckets.OVERDUE].values())
                     + sum(ola_counts[ola_buckets.DUE_1H].values()))

    # Daily volume trend scoped to the active GET filters. Zero-filled so the
    # line has no gaps. Window depends on date_range:
    #   today → hourly buckets (00:00 … current hour, local time)
    #   week  → last 7 days
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
        ndays = 7 if date_range == 'week' else 30
        start_date = today_local - timedelta(days=ndays - 1)
        rows = (
            all_tickets.filter(created_at__date__gte=start_date)
            .annotate(d=TruncDate('created_at'))
            .values('d').annotate(c=Count('id'))
        )
        day_counts = {r['d']: r['c'] for r in rows}
        for i in range(ndays):
            day = start_date + timedelta(days=i)
            daily_trend_filtered.append(
                {'date': day.strftime('%Y-%m-%d'), 'count': day_counts.get(day, 0)})
            daily_trend_labels.append(f"{day.day:02d} {MONTH_ABBR[day.month]}")

    daily_trend_data = [d['count'] for d in daily_trend_filtered]

    return render(request, 'dashboard/dashboard.html', {
        'stats':               stats,
        'now':                 now,
        'pipeline_by_severity': pipeline_by_severity,
        'pipeline_rows':        pipeline_rows,
        'by_category_labels':  by_category_labels,
        'by_category_data':    by_category_data,
        'chart_tables':        chart_tables,
        'recent_tickets':      recent_tickets,
        # ── Management KPIs (Session 3) ────────────────────────────────── #
        'active_total':              active_total,
        'active_critical':           active_critical,
        'critical_soonest_deadline': critical_soonest_deadline,
        'closed_this_month':         closed_this_month,
        'closed_last_month':         closed_last_month,
        'closed_delta':              closed_delta,
        'assignee_heatmap':          assignee_heatmap,
        'assignee_heatmap_statuses': assignee_heatmap_statuses,
        'ola_pressure':              ola_pressure,
        'ola_attention':             ola_attention,
        'daily_trend_filtered':      daily_trend_filtered,
        'daily_trend_labels':        daily_trend_labels,
        'daily_trend_data':          daily_trend_data,
        # Filter bar state
        'status_choices':      Ticket.STATUS_CHOICES,
        'severity_choices':    Ticket.SEVERITY_CHOICES,
        'filters': {
            'date_range': date_range,
            'status':     status_filter,
            'severity':   severity_filter,
        },
        # SOC managers are scoped to their own queue in the ticket list, so the
        # OLA deep-link can land on a shorter list than the team-wide chart
        # counts. Flag it so the template can note the difference (managers only).
        'is_manager_view': bool(
            profile and not request.user.is_superuser
            and getattr(profile, 'is_soc_manager', False)
        ),
    })


# ====================================================================== #
# Executive dashboard                                                     #
# ====================================================================== #

@login_required
def executive_dashboard(request):
    """Executive dashboard — glanceable posture summary for management.

    Follows the approved wireframe: KPI cards (total High/Critical count
    with month-over-month delta, MTTR placeholder), a date-scoped
    High/Critical closure progress bar, a four-criteria executive summary
    with an overall GOOD / WAITING / WARNING verdict, the date-scoped
    pipeline chart, and a date-scoped filterable ticket detail table.

    Pipeline bars and summary criterion rows deep-link back to this page
    with ?f=<status slug | EMERGENCY> — a single filter, last click wins.
    date_range scopes the charting/detail sections, while the executive
    verdict stays a live current-posture summary.
    """
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and profile and profile.is_system_owner:
        return redirect('system_owner_dashboard')
    if not request.user.is_superuser and profile and profile.is_system_admin:
        return redirect('ticket_list')

    now = timezone.now()
    terminal = list(Ticket.TERMINAL_STATUSES)
    HIGH_CRIT = ('Critical', 'High')

    all_tickets = Ticket.objects.all()
    active_qs = all_tickets.exclude(status__in=terminal)

    date_range = request.GET.get('date_range', 'all')
    if date_range not in {'today', 'week', 'month', 'all'}:
        date_range = 'all'
    range_tickets = all_tickets
    if date_range == 'today':
        range_tickets = range_tickets.filter(created_at__date=now.date())
    elif date_range == 'week':
        week_start = (now - timedelta(days=now.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0)
        range_tickets = range_tickets.filter(created_at__gte=week_start)
    elif date_range == 'month':
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        range_tickets = range_tickets.filter(created_at__gte=month_start)
    range_active_qs = range_tickets.exclude(status__in=terminal)
    range_labels = {
        'today': 'Today',
        'week': 'This Week',
        'month': 'This Month',
        'all': 'All Time',
    }

    # ── KPI 1: total High/Critical cases + delta vs start of this month ─── #
    total_hc = all_tickets.filter(severity__in=HIGH_CRIT).count()

    this_month_start = now.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0)
    prev_total_hc = (
        all_tickets
        .filter(severity__in=HIGH_CRIT, created_at__lt=this_month_start)
        .count()
    )
    total_hc_delta = total_hc - prev_total_hc

    # ── Progress bar: closure rate over ALL High/Critical tickets ───────── #
    hc_total = range_tickets.filter(severity__in=HIGH_CRIT).count()
    hc_closed = range_tickets.filter(
        severity__in=HIGH_CRIT, status__in=terminal).count()
    hc_open = hc_total - hc_closed
    hc_progress_pct = round(hc_closed / hc_total * 100) if hc_total else 0

    # ── Executive summary — 4 criteria, priority Warning > Waiting > Good ─ #
    crit_unassigned = active_qs.filter(
        severity='Critical', status=Ticket.STATUS_NEW,
        assigned_to__isnull=True,
    ).count()
    emergency_active = active_qs.filter(is_emergency=True).count()
    awaiting_containment = active_qs.filter(
        status=Ticket.STATUS_AWAITING_CONTAINMENT).count()
    # verified_by is stamped when T1 signs the containment off, so a null
    # here means the report is still waiting on T1's review.
    unverified_containment = active_qs.filter(
        status=Ticket.STATUS_CONTAINMENT_REPORTED,
        verified_by__isnull=True,
    ).count()

    summary_criteria = [
        {
            'label': 'เคส Critical ที่ยังไม่มีผู้รับผิดชอบ',
            'count': crit_unassigned,
            'level': 'warning' if crit_unassigned else 'good',
            'filter': Ticket.STATUS_NEW,
        },
        {
            'label': 'เคสฉุกเฉิน (Emergency) ที่ยังไม่ปิด',
            'count': emergency_active,
            'level': 'warning' if emergency_active else 'good',
            'filter': 'EMERGENCY',
        },
        {
            'label': 'เคสที่รอการจัดการจากผู้ดูแลระบบ',
            'count': awaiting_containment,
            'level': 'waiting' if awaiting_containment else 'good',
            'filter': Ticket.STATUS_AWAITING_CONTAINMENT,
        },
        {
            'label': 'การควบคุมที่รอ Tier 1 ตรวจสอบ',
            'count': unverified_containment,
            'level': 'waiting' if unverified_containment else 'good',
            'filter': Ticket.STATUS_CONTAINMENT_REPORTED,
        },
    ]
    if any(c['level'] == 'warning' for c in summary_criteria):
        overall_status = 'WARNING'
    elif any(c['level'] == 'waiting' for c in summary_criteria):
        overall_status = 'WAITING'
    else:
        overall_status = 'GOOD'

    # ── Pipeline — executive view tracks only High/Critical cases. Emergency
    # counts are a subset overlay per status, not an extra severity segment.
    status_map = dict(Ticket.STATUS_CHOICES)
    status_order = [s for s, _ in Ticket.STATUS_CHOICES]
    sev_display = dict(Ticket.SEVERITY_CHOICES)
    severity_order = sorted(
        (s for s in sev_display if s in HIGH_CRIT),
        key=lambda s: Ticket.SEVERITY_RANK.get(s, 0),
        reverse=True,
    )
    pipeline_matrix = {
        sev: {st: 0 for st in status_order} for sev in severity_order
    }
    pipeline_qs = range_tickets.filter(severity__in=HIGH_CRIT)
    for row in pipeline_qs.values('severity', 'status').annotate(c=Count('id')):
        sev, st = row['severity'], row['status']
        if sev in pipeline_matrix and st in pipeline_matrix[sev]:
            pipeline_matrix[sev][st] = row['c']
    emergency_by_status = {st: 0 for st in status_order}
    for row in (
        pipeline_qs
        .filter(is_emergency=True)
        .values('status')
        .annotate(c=Count('id'))
    ):
        if row['status'] in emergency_by_status:
            emergency_by_status[row['status']] = row['c']
    pipeline_by_severity = {
        'statuses': [(s, status_map[s]) for s in status_order],
        'severities': [(s, sev_display[s]) for s in severity_order],
        'matrix': pipeline_matrix,
        'emergency_by_status': emergency_by_status,
    }
    pipeline_rows = [
        {'severity': sev_display[sev],
         'cells': [pipeline_matrix[sev][st] for st in status_order]}
        for sev in severity_order
    ]
    pipeline_emergency_row = [emergency_by_status[st] for st in status_order]

    # ── Detail table — single ?f= filter, last click wins ───────────────── #
    f = request.GET.get('f', '')
    filter_label = ''
    if f == 'EMERGENCY':
        table_qs = range_active_qs.filter(is_emergency=True)
        filter_label = 'เคสฉุกเฉิน (Emergency)'
    elif f in status_map:
        # A status filter may target a terminal status (pipeline "close" bars),
        # so it searches the date-scoped tickets, not just the active queue.
        table_qs = range_tickets.filter(status=f)
        filter_label = status_map[f]
    else:
        f = ''
        table_qs = range_active_qs
    table_qs = (
        table_qs.select_related('assigned_to', 'assigned_admin')
        .order_by('-updated_at')
    )
    paginator = Paginator(table_qs, 10)
    page_obj = paginator.get_page(request.GET.get('page'))
    table_tickets = page_obj

    return render(request, 'dashboard/executive.html', {
        'now': now,
        'total_hc': total_hc,
        'total_hc_delta': total_hc_delta,
        'emergency_active': emergency_active,
        'hc_total': hc_total,
        'hc_closed': hc_closed,
        'hc_open': hc_open,
        'hc_progress_pct': hc_progress_pct,
        'summary_criteria': summary_criteria,
        'overall_status': overall_status,
        'pipeline_by_severity': pipeline_by_severity,
        'pipeline_rows': pipeline_rows,
        'pipeline_emergency_row': pipeline_emergency_row,
        'table_tickets': table_tickets,
        'page_obj': page_obj,
        'filter_f': f,
        'filter_label': filter_label,
        'filters': {
            'date_range': date_range,
            'range_label': range_labels[date_range],
        },
    })
