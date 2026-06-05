import json
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import render
from django.utils import timezone

from apps.incidents.models import Ticket


@login_required
def dashboard(request):
    # System Owners see their own portal, not the SOC dashboard
    profile = getattr(request.user, 'profile', None)
    if profile and profile.is_system_owner:
        from django.shortcuts import redirect
        return redirect('system_owner_dashboard')
    if profile and profile.is_system_admin:
        from django.shortcuts import redirect
        return redirect('ticket_list')

    today = timezone.now()
    terminal = list(Ticket.TERMINAL_STATUSES)

    all_tickets = Ticket.objects.all()
    active_qs   = all_tickets.exclude(status__in=terminal)
    closed_qs   = all_tickets.filter(status__in=terminal)

    sla_breached_qs = active_qs.filter(sla_deadline__lt=today)

    # ── Disposition counts (closed tickets only) ─────────────────────────── #
    tp_count = closed_qs.filter(disposition=Ticket.DISP_TRUE_POSITIVE).count()
    fp_count = closed_qs.filter(disposition=Ticket.DISP_FALSE_POSITIVE).count()
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
                                    Ticket.STATUS_UNDER_REVIEW,
                                ]
                            ).count(),
        'awaiting_manager': active_qs.filter(status=Ticket.STATUS_VERIFIED).count(),
        # FP / TP
        'tp_count': tp_count,
        'fp_count': fp_count,
        'tp_pct':   tp_pct,
        'fp_pct':   fp_pct,
    }

    # ── Pipeline chart — all 7 statuses ──────────────────────────────────── #
    status_map   = dict(Ticket.STATUS_CHOICES)
    status_order = [s for s, _ in Ticket.STATUS_CHOICES]
    counts_by_status = {
        row['status']: row['count']
        for row in all_tickets.values('status').annotate(count=Count('id'))
    }
    status_labels = json.dumps([status_map[s] for s in status_order])
    status_data   = json.dumps([counts_by_status.get(s, 0) for s in status_order])

    # ── FP / TP doughnut ─────────────────────────────────────────────────── #
    fp_tp_labels = json.dumps(['True Positive', 'False Positive'])
    fp_tp_data   = json.dumps([tp_count, fp_count])

    # ── By Type bar chart ─────────────────────────────────────────────────── #
    by_type = list(
        all_tickets.values('issue_type').annotate(count=Count('id')).order_by('-count')
    )
    by_type_labels = json.dumps([b['issue_type'] for b in by_type])
    by_type_data   = json.dumps([b['count']      for b in by_type])

    # ── By Category doughnut ─────────────────────────────────────────────── #
    by_category = list(
        all_tickets.values('category').annotate(count=Count('id')).order_by('-count')
    )
    by_category_labels = json.dumps([b['category'] for b in by_category])
    by_category_data   = json.dumps([b['count']    for b in by_category])

    # ── Monthly trend (last 6 months) ────────────────────────────────────── #
    monthly = []
    for i in range(5, -1, -1):
        month = (today.month - i - 1) % 12 + 1
        year  = today.year if today.month - i > 0 else today.year - 1
        count = all_tickets.filter(created_at__month=month, created_at__year=year).count()
        monthly.append({'month': f"{year}/{month:02d}", 'count': count})

    monthly_labels = json.dumps([m['month'] for m in monthly])
    monthly_data   = json.dumps([m['count'] for m in monthly])

    # ── Recent & breach lists ─────────────────────────────────────────────── #
    recent_tickets = active_qs.order_by('-created_at')[:8]
    breach_tickets = sla_breached_qs.order_by('sla_deadline')[:5]

    return render(request, 'dashboard/dashboard.html', {
        'stats':               stats,
        'status_labels':       status_labels,
        'status_data':         status_data,
        'fp_tp_labels':        fp_tp_labels,
        'fp_tp_data':          fp_tp_data,
        'by_type_labels':      by_type_labels,
        'by_type_data':        by_type_data,
        'by_category_labels':  by_category_labels,
        'by_category_data':    by_category_data,
        'monthly_labels':      monthly_labels,
        'monthly_data':        monthly_data,
        'recent_tickets':      recent_tickets,
        'breach_tickets':      breach_tickets,
    })
