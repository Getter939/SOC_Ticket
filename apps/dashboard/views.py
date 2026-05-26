import json
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import render
from django.utils import timezone

from apps.incidents.models import Ticket
from apps.customers.models import Customer
from apps.projects.models import Project, Task


@login_required
def dashboard(request):
    today = timezone.now()

    # --- Ticket stats ---
    all_active = Ticket.objects.exclude(status__in=['Resolved', 'Closed'])
    sla_breached_qs = Ticket.objects.filter(
        sla_deadline__lt=today
    ).exclude(status__in=['Resolved', 'Closed'])

    stats = {
        'open': all_active.filter(status='Open').count(),
        'in_progress': all_active.filter(status='In Progress').count(),
        'resolved_month': Ticket.objects.filter(
            status__in=['Resolved', 'Closed'],
            updated_at__month=today.month,
            updated_at__year=today.year,
        ).count(),
        'sla_breaches': sla_breached_qs.count(),
        'total_customers': Customer.objects.count(),
        'active_projects': Project.objects.filter(status='Active').count(),
    }

    # --- Chart data: tickets by type ---
    by_type = list(
        Ticket.objects.values('issue_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    by_type_labels = json.dumps([b['issue_type'] for b in by_type])
    by_type_data   = json.dumps([b['count']      for b in by_type])

    # --- Chart data: tickets by category ---
    by_category = list(
        Ticket.objects.values('category')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    by_category_labels = json.dumps([b['category'] for b in by_category])
    by_category_data   = json.dumps([b['count']    for b in by_category])

    # --- Chart data: tickets created per month (last 6 months) ---
    monthly = []
    for i in range(5, -1, -1):
        month = (today.month - i - 1) % 12 + 1
        year  = today.year if today.month - i > 0 else today.year - 1
        count = Ticket.objects.filter(created_at__month=month, created_at__year=year).count()
        monthly.append({'month': f"{year}/{month:02d}", 'count': count})

    monthly_labels = json.dumps([m['month'] for m in monthly])
    monthly_data   = json.dumps([m['count'] for m in monthly])

    # --- Recent tickets & SLA breach list ---
    recent_tickets = Ticket.objects.exclude(status__in=['Resolved', 'Closed']).order_by('-created_at')[:8]
    breach_tickets = sla_breached_qs.order_by('sla_deadline')[:5]

    # --- Recent tasks ---
    recent_tasks = Task.objects.select_related('project', 'assignee').order_by('-created_at')[:5]

    return render(request, 'dashboard/dashboard.html', {
        'stats': stats,
        'by_type_labels': by_type_labels,
        'by_type_data': by_type_data,
        'by_category_labels': by_category_labels,
        'by_category_data': by_category_data,
        'monthly_labels': monthly_labels,
        'monthly_data': monthly_data,
        'recent_tickets': recent_tickets,
        'breach_tickets': breach_tickets,
        'recent_tasks': recent_tasks,
    })
