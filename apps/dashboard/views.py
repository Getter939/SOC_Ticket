from datetime import timedelta
from statistics import mean as _mean, median as _median

from django.contrib.auth.decorators import login_required
from django.db.models import Aggregate, Avg, Count, DurationField, F, OuterRef, Q, Subquery
from django.db.models.functions import Coalesce, TruncDate, TruncHour
from django.shortcuts import render
from django.utils import timezone

from apps.incidents.models import SOURCE_CHOICES, Ticket, TicketLog

# ====================================================================== #
# Data-model facts this view relies on (verified against                 #
# apps/incidents/models.py — keep in sync if the model changes):         #
#                                                                        #
#   a) SLA deadline   → Ticket.sla_deadline (DateTimeField). Auto-set in #
#      Ticket.save() to (incident_datetime or now()) + SLA_HOURS (4h).   #
#      It is an absolute resolution deadline, so "breach" = now() past   #
#      it while still active.                                            #
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
#   Containment deadline → NONE. The only deadline field is sla_deadline #
#     (there is no separate containment_deadline).                       #
# ====================================================================== #


class PercentileCont(Aggregate):
    """Postgres ordered-set aggregate: PERCENTILE_CONT(p) WITHIN GROUP (ORDER BY ...).

    Django has no built-in percentile function; this wraps the native Postgres
    one. Postgres-only — both prod and dev run Postgres.
    """
    function = 'PERCENTILE_CONT'
    name = 'percentilecont'
    template = '%(function)s(%(percentile)s) WITHIN GROUP (ORDER BY %(expressions)s)'
    output_field = DurationField()

    def __init__(self, expression, percentile=0.5, **extra):
        super().__init__(expression, percentile=percentile, **extra)


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

    # date_range + severity WITHOUT the status filter — used by
    # resolved_by_category, where a non-terminal status filter would
    # otherwise hide every closed ticket.
    date_sev_qs = all_tickets

    if status_filter:
        all_tickets = all_tickets.filter(status=status_filter)

    active_qs   = all_tickets.exclude(status__in=terminal)
    closed_qs   = all_tickets.filter(status__in=terminal)

    # Legacy "time-to-file" breach — kept so the existing dashboard.html banner
    # and breach_tickets list keep working untouched. The corrected, live
    # against-deadline figure is sla_breach_live below.
    sla_breached_qs = active_qs.filter(sla_deadline__lt=F('created_at'))

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

    # ── SLA compliance rate (% resolved within deadline) ──────────────────── #
    total_resolved = resolved_qs.count()
    if total_resolved:
        met = resolved_qs.filter(resolved_at__lte=F('sla_deadline')).count()
        sla_compliance_rate = round(met / total_resolved * 100, 1)
    else:
        sla_compliance_rate = None

    # ── Live SLA breach / at-risk (against the actual deadline, vs now()) ──── #
    sla_breach_live = active_qs.filter(sla_deadline__lt=now).count()
    sla_at_risk = active_qs.filter(
        sla_deadline__gte=now,
        sla_deadline__lte=now + timedelta(hours=4),
    ).count()

    # ── MTTR over the last 30 days (hours), median/mean/n ─────────────────── #
    # resolved_at is derived from TicketLog, so it always exists; median is
    # computed in Python to stay database-agnostic (PercentileCont is
    # Postgres-only and awkward to layer over a Subquery annotation).
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

    # ── Backlog aging (active tickets bucketed by age) ────────────────────── #
    fresh_cut = now - timedelta(hours=24)
    stale_cut = now - timedelta(days=3)
    backlog_aging = {
        'fresh': active_qs.filter(created_at__gte=fresh_cut).count(),
        'aging': active_qs.filter(
                     created_at__lt=fresh_cut, created_at__gte=stale_cut).count(),
        'stale': active_qs.filter(created_at__lt=stale_cut).count(),
    }

    # ── Assignee workload (top 8 by open count, with breach count) ────────── #
    workload_rows = (
        active_qs.filter(assigned_to__isnull=False)
        .values(
            'assigned_to__first_name',
            'assigned_to__last_name',
            'assigned_to__username',
        )
        .annotate(
            open=Count('id'),
            breached=Count('id', filter=Q(sla_deadline__lt=now)),
        )
        .order_by('-open')[:8]
    )
    assignee_workload = []
    for row in workload_rows:
        name = (f"{row['assigned_to__first_name']} "
                f"{row['assigned_to__last_name']}").strip() \
            or row['assigned_to__username']
        assignee_workload.append({
            'name':     name,
            'open':     row['open'],
            'breached': row['breached'],
        })

    # ── Severity breakdown (active tickets, critical first) ───────────────── #
    sev_display = dict(Ticket.SEVERITY_CHOICES)
    severity_breakdown = sorted(
        (
            {
                'label': sev_display.get(r['severity'], r['severity']),
                'count': r['count'],
                '_rank': Ticket.SEVERITY_RANK.get(r['severity'], 0),
            }
            for r in active_qs.values('severity').annotate(count=Count('id'))
        ),
        key=lambda x: x['_rank'],
        reverse=True,
    )
    for item in severity_breakdown:
        item.pop('_rank')

    # ── Analyst response time (alert actionable → ticket raised) ─────────── #
    # Median is reported as the headline figure (robust to the long tail from
    # ingestion/queue dwell); mean + n give context. Excludes manually-created
    # tickets, which have no source alert and therefore no conversion time.
    # PercentileCont is Postgres-only — safe here (prod and dev both Postgres).
    conv_qs = all_tickets.filter(alert_conversion_duration__isnull=False)
    conv = conv_qs.aggregate(
        n=Count('id'),
        median=PercentileCont('alert_conversion_duration', percentile=0.5),
        mean=Avg('alert_conversion_duration'),
    )
    conv_median_min = round(conv['median'].total_seconds() / 60, 1) if conv['median'] else None
    conv_mean_min = round(conv['mean'].total_seconds() / 60, 1) if conv['mean'] else None

    # ── Event/Incident classification counts (closed tickets only) ───────── #
    # Kept under the legacy tp_*/fp_* stat keys so the dashboard template keeps
    # working: tp_* now means Incident, fp_* means Event.
    tp_count = closed_qs.filter(classification=Ticket.CLASSIFICATION_INCIDENT).count()
    fp_count = closed_qs.filter(classification=Ticket.CLASSIFICATION_EVENT).count()
    total_disp = tp_count + fp_count
    tp_pct = round(tp_count / total_disp * 100) if total_disp else 0
    fp_pct = round(fp_count / total_disp * 100) if total_disp else 0

    stats = {
        # Ticket counts
        'total':           all_tickets.count(),
        'active':          active_qs.count(),
        'closed':          closed_qs.count(),
        'resolved_month':  closed_qs.filter(
                               updated_at__month=today.month,
                               updated_at__year=today.year,
                           ).count(),
        'sla_breaches':    sla_breached_qs.count(),
        # Actionable queues
        'awaiting_admin':   active_qs.filter(status=Ticket.STATUS_AWAITING_CONTAINMENT).count(),
        'awaiting_soc':     active_qs.filter(
                                status__in=[
                                    Ticket.STATUS_CONTAINMENT_REPORTED,
                                    Ticket.STATUS_T1_REVIEW,
                                    Ticket.STATUS_ESCALATED_T2,
                                ]
                            ).count(),
        'awaiting_manager': active_qs.filter(status=Ticket.STATUS_PENDING_MANAGER).count(),
        # Event / Incident
        'tp_count': tp_count,
        'fp_count': fp_count,
        'tp_pct':   tp_pct,
        'fp_pct':   fp_pct,
        # Analyst response time (alert → ticket)
        'conversion_n':          conv['n'],
        'conversion_median_min': conv_median_min,
        'conversion_mean_min':   conv_mean_min,
        # ── Enterprise-grade KPIs (corrected) ──────────────────────────── #
        'sla_compliance_rate': sla_compliance_rate,   # % resolved within deadline (None if no resolved)
        'sla_breach_live':     sla_breach_live,        # active & now() past deadline
        'sla_at_risk':         sla_at_risk,            # active & deadline within next 4h, not yet breached
        'mttr_median':         mttr_median,            # hours, last 30 days (None if none)
        'mttr_mean':           mttr_mean,              # hours, last 30 days (None if none)
        'mttr_n':              mttr_n,                 # count of resolved in last 30 days
        'backlog_aging':       backlog_aging,          # {'fresh','aging','stale'}
        'assignee_workload':   assignee_workload,      # top 8 [{'name','open','breached'}]
        'severity_breakdown':  severity_breakdown,     # active [{'label','count'}], critical first
    }

    # ── Pipeline chart — all 7 statuses ──────────────────────────────────── #
    status_map   = dict(Ticket.STATUS_CHOICES)
    status_order = [s for s, _ in Ticket.STATUS_CHOICES]
    counts_by_status = {
        row['status']: row['count']
        for row in all_tickets.values('status').annotate(count=Count('id'))
    }
    status_labels = [status_map[s] for s in status_order]
    status_data   = [counts_by_status.get(s, 0) for s in status_order]

    # ── Pipeline by severity × status (stacked-bar source) ───────────────── #
    # STEP 0 findings: the only pre-existing pipeline data is status_data
    # (totals per status — NOT broken down by severity), so this is a new key.
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

    # Event / Incident doughnut
    classification_labels = ['Incident', 'Event']
    classification_data   = [tp_count, fp_count]

    # ── By Source bar chart ──────────────────────────────────────────────── #
    # issue_type holds the reporting channel (SOURCE_CHOICES); map codes to
    # their human labels for display.
    source_display = dict(SOURCE_CHOICES)
    by_type = list(
        all_tickets.values('issue_type').annotate(count=Count('id')).order_by('-count')
    )
    by_type_labels = [source_display.get(b['issue_type'], b['issue_type']) for b in by_type]
    by_type_data   = [b['count']      for b in by_type]

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

    # ── Monthly trend (last 6 months) ────────────────────────────────────── #
    monthly = []
    for i in range(5, -1, -1):
        month = (today.month - i - 1) % 12 + 1
        year  = today.year if today.month - i > 0 else today.year - 1
        count = all_tickets.filter(created_at__month=month, created_at__year=year).count()
        monthly.append({'month': f"{year}/{month:02d}", 'count': count})

    monthly_labels = [m['month'] for m in monthly]
    monthly_data   = [m['count'] for m in monthly]

    # ── Recent & breach lists ─────────────────────────────────────────────── #
    # Top 15 active cases, most urgent first (nearest SLA deadline). NULL
    # deadlines sort last under Postgres ASC. select_related avoids N+1 on the
    # assignee column rendered in the detail table.
    recent_tickets = (
        active_qs.select_related('assigned_to').order_by('sla_deadline')[:15]
    )
    breach_tickets = sla_breached_qs.order_by('sla_deadline')[:5]

    # ── Backlog-aging & severity chart series (derived from stats above) ──── #
    backlog_labels = ['Fresh (0–24h)', 'Aging (1–3d)', 'Stale (>3d)']
    backlog_data   = [backlog_aging['fresh'], backlog_aging['aging'], backlog_aging['stale']]
    severity_labels = [s['label'] for s in severity_breakdown]
    severity_data   = [s['count'] for s in severity_breakdown]

    # ── Pre-zipped (label, value) pairs for the visually-hidden a11y tables ─ #
    chart_tables = {
        'pipeline':       list(zip(status_labels, status_data)),
        'classification': list(zip(classification_labels, classification_data)),
        'by_type':        list(zip(by_type_labels, by_type_data)),
        'by_category':    list(zip(by_category_labels, by_category_data)),
        'monthly':        list(zip(monthly_labels, monthly_data)),
        'backlog':        list(zip(backlog_labels, backlog_data)),
        'severity':       list(zip(severity_labels, severity_data)),
    }

    # ====================================================================== #
    # Management dashboard KPIs (Session 3) — additive.                       #
    # Audience: management. Everything respects the active GET filters        #
    # (date_range / status / severity) EXCEPT resolved_by_category, which     #
    # respects date_range + severity only (see date_sev_qs above).           #
    # ====================================================================== #
    MONTH_ABBR = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    active_total    = active_qs.count()
    active_critical = active_qs.filter(severity='Critical').count()  # highest rank

    crit_soonest = (
        active_qs.filter(severity='Critical', sla_deadline__isnull=False)
        .order_by('sla_deadline')
        .values('ticket_id', 'sla_deadline')
        .first()
    )
    if crit_soonest:
        critical_soonest_deadline = {
            'ticket_id': crit_soonest['ticket_id'],
            'minutes_remaining': round(
                (crit_soonest['sla_deadline'] - now).total_seconds() / 60),
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
    cat_durations = {}
    for cat, r_at, c_at in (resolved_qs.filter(resolved_at__gte=thirty_days_ago)
                            .exclude(detailed_issue__isnull=True).exclude(detailed_issue='')
                            .values_list('detailed_issue', 'resolved_at', 'created_at')):
        if r_at and c_at and r_at >= c_at:
            cat_durations.setdefault(cat, []).append(
                (r_at - c_at).total_seconds() / 3600)
    mttr_by_category = [
        {'label': detailed_display.get(cat, cat), 'avg_hours': round(_mean(durs), 1)}
        for cat, durs in cat_durations.items() if len(durs) >= 2
    ]
    mttr_by_category.sort(key=lambda x: x['avg_hours'], reverse=True)

    # Resolved tickets grouped by INCIDENT CATEGORY (detailed_issue), not the
    # Event/Incident classification. STEP 0: detailed_issue is a CharField with
    # DETAILED_ISSUE_CHOICES (Malicious Logic, Reconnaissance, DoS, …) — the
    # actual threat/incident category. Respects date_range + severity (NOT
    # status, since we count closed tickets). Null/blank excluded so management
    # doesn't see a noisy "Unknown" bar. Top 8, count desc.
    resolved_by_category = [
        {'label': detailed_display.get(r['detailed_issue'], r['detailed_issue']),
         'count': r['c']}
        for r in (date_sev_qs.filter(status__in=terminal)
                  .exclude(detailed_issue__isnull=True)
                  .exclude(detailed_issue='')
                  .values('detailed_issue').annotate(c=Count('id')).order_by('-c')[:8])
    ]

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
        'status_labels':       status_labels,
        'status_data':         status_data,
        'pipeline_by_severity': pipeline_by_severity,
        'pipeline_rows':        pipeline_rows,
        'classification_labels': classification_labels,
        'classification_data': classification_data,
        'by_type_labels':      by_type_labels,
        'by_type_data':        by_type_data,
        'by_category_labels':  by_category_labels,
        'by_category_data':    by_category_data,
        'monthly_labels':      monthly_labels,
        'monthly_data':        monthly_data,
        'backlog_labels':      backlog_labels,
        'backlog_data':        backlog_data,
        'severity_labels':     severity_labels,
        'severity_data':       severity_data,
        'chart_tables':        chart_tables,
        'recent_tickets':      recent_tickets,
        'breach_tickets':      breach_tickets,
        # ── Management KPIs (Session 3) ────────────────────────────────── #
        'active_total':              active_total,
        'active_critical':           active_critical,
        'critical_soonest_deadline': critical_soonest_deadline,
        'closed_this_month':         closed_this_month,
        'closed_last_month':         closed_last_month,
        'closed_delta':              closed_delta,
        'assignee_heatmap':          assignee_heatmap,
        'assignee_heatmap_statuses': assignee_heatmap_statuses,
        'mttr_by_category':          mttr_by_category,
        'resolved_by_category':      resolved_by_category,
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
    })
