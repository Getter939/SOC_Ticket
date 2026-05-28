import json
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import redirect, render
from django.utils import timezone

from apps.incidents.models import Ticket
from apps.customers.models import Customer
from apps.projects.models import Project, Task


@login_required
def dashboard(request):
    # ── Change 1: SOC-only access ─────────────────────────────────────────── #
    # System admins and users with no profile are redirected to the ticket list.
    # They should not see org-wide aggregates — they only have visibility into
    # tickets assigned to them, which the ticket list already enforces via
    # Ticket.objects.visible_to().
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        return redirect('ticket_list')

    today = timezone.now()
    terminal = list(Ticket.TERMINAL_STATUSES)

    # ── Base querysets ────────────────────────────────────────────────────── #
    # We confirmed is_soc above, so SOC sees all tickets — work on the full
    # table directly (same result as visible_to(), but no extra filter/join).
    all_tickets = Ticket.objects
    active_qs   = all_tickets.exclude(status__in=terminal)
    closed_qs   = all_tickets.filter(status__in=terminal)

    # ── Change 2: SLA-breach counting — pure DB ───────────────────────────── #
    # A breached ticket has sla_deadline in the past AND is not terminal.
    sla_breached_qs = active_qs.filter(sla_deadline__lt=today)

    # ── Change 3: status distribution (one query, dict keyed by status) ──── #
    status_counts: dict = dict(
        all_tickets.values('status')
                   .annotate(n=Count('id'))
                   .values_list('status', 'n')
    )

    # ── Actionable backlog — who must act next ────────────────────────────── #
    awaiting_admin   = status_counts.get(Ticket.STATUS_AWAITING_CONTAINMENT, 0)
    awaiting_soc     = (
        status_counts.get(Ticket.STATUS_CONTAINMENT_REPORTED, 0)
        + status_counts.get(Ticket.STATUS_UNDER_REVIEW, 0)
    )
    awaiting_manager = status_counts.get(Ticket.STATUS_VERIFIED, 0)

    # ── FP/TP ratio ───────────────────────────────────────────────────────── #
    tp_count   = all_tickets.filter(disposition=Ticket.DISP_TRUE_POSITIVE).count()
    fp_count   = all_tickets.filter(disposition=Ticket.DISP_FALSE_POSITIVE).count()
    disp_total = tp_count + fp_count
    tp_pct     = round(tp_count * 100 / disp_total) if disp_total else 0
    fp_pct     = round(fp_count * 100 / disp_total) if disp_total else 0

    # ── Stat block ────────────────────────────────────────────────────────── #
    stats = {
        'total':          all_tickets.count(),
        'active':         active_qs.count(),
        'closed':         closed_qs.count(),
        # legacy keys kept so template partial logic still resolves
        'open':           status_counts.get(Ticket.STATUS_NEW, 0),
        'in_progress':    active_qs.exclude(status=Ticket.STATUS_NEW).count(),
        'resolved_month': closed_qs.filter(
            updated_at__month=today.month,
            updated_at__year=today.year,
        ).count(),
        'sla_breaches':     sla_breached_qs.count(),
        'total_customers':  Customer.objects.count(),
        'active_projects':  Project.objects.filter(status='Active').count(),
        # actionable backlog
        'awaiting_admin':   awaiting_admin,
        'awaiting_soc':     awaiting_soc,
        'awaiting_manager': awaiting_manager,
        # FP/TP
        'tp_count': tp_count,
        'fp_count': fp_count,
        'tp_pct':   tp_pct,
        'fp_pct':   fp_pct,
    }

    # ── Status distribution chart (pipeline view — all 7 states) ─────────── #
    status_labels = json.dumps([label for _, label in Ticket.STATUS_CHOICES])
    status_data   = json.dumps([
        status_counts.get(code, 0) for code, _ in Ticket.STATUS_CHOICES
    ])

    # ── FP/TP doughnut chart data ─────────────────────────────────────────── #
    fp_tp_labels = json.dumps(['True Positive (TP)', 'False Positive (FP)'])
    fp_tp_data   = json.dumps([tp_count, fp_count])

    # ── Tickets by type ───────────────────────────────────────────────────── #
    by_type = list(
        all_tickets.values('issue_type').annotate(count=Count('id')).order_by('-count')
    )
    by_type_labels = json.dumps([b['issue_type'] for b in by_type])
    by_type_data   = json.dumps([b['count']      for b in by_type])

    # ── Tickets by category ───────────────────────────────────────────────── #
    by_category = list(
        all_tickets.values('category').annotate(count=Count('id')).order_by('-count')
    )
    by_category_labels = json.dumps([b['category'] for b in by_category])
    by_category_data   = json.dumps([b['count']    for b in by_category])

    # ── Tickets created per month (last 6 months) ─────────────────────────── #
    monthly = []
    for i in range(5, -1, -1):
        month = (today.month - i - 1) % 12 + 1
        year  = today.year if today.month - i > 0 else today.year - 1
        count = all_tickets.filter(
            created_at__month=month, created_at__year=year
        ).count()
        monthly.append({'month': f'{year}/{month:02d}', 'count': count})

    monthly_labels = json.dumps([m['month'] for m in monthly])
    monthly_data   = json.dumps([m['count'] for m in monthly])

    # ── Recent tickets & SLA breach list ─────────────────────────────────── #
    recent_tickets = active_qs.order_by('-created_at')[:8]
    breach_tickets = sla_breached_qs.order_by('sla_deadline')[:5]

    # ── Recent tasks ──────────────────────────────────────────────────────── #
    recent_tasks = Task.objects.select_related('project', 'assignee').order_by('-created_at')[:5]

    return render(request, 'dashboard/dashboard.html', {
        'stats':              stats,
        'status_labels':      status_labels,
        'status_data':        status_data,
        'fp_tp_labels':       fp_tp_labels,
        'fp_tp_data':         fp_tp_data,
        'by_type_labels':     by_type_labels,
        'by_type_data':       by_type_data,
        'by_category_labels': by_category_labels,
        'by_category_data':   by_category_data,
        'monthly_labels':     monthly_labels,
        'monthly_data':       monthly_data,
        'recent_tickets':     recent_tickets,
        'breach_tickets':     breach_tickets,
        'recent_tasks':       recent_tasks,
    })
