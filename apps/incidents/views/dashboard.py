import logging

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.utils import timezone

from ..models import (
    Ticket,
)

logger = logging.getLogger('apps.incidents.views')



# ── System Owner dashboard ────────────────────────────────────────────── #

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
    now = timezone.now()
    stats = {
        'total':          my_tickets.count(),
        'active':         active_qs.count(),
        'closed':         closed_qs.count(),
        'ola_breaches':   active_qs.filter(ola_contain_deadline__lt=now).count(),
    }

    emergency_filter = request.GET.get('emergency', '').strip()
    sort = request.GET.get('sort', 'newest').strip()
    if emergency_filter in ('1', '0'):
        emergency_value = emergency_filter == '1'
        active_qs = active_qs.filter(is_emergency=emergency_value)
        closed_qs = closed_qs.filter(is_emergency=emergency_value)
    else:
        emergency_filter = ''
    if sort not in ('newest', 'emergency'):
        sort = 'newest'
    active_order = ('-is_emergency', '-created_at') if sort == 'emergency' else ('-created_at',)
    closed_order = ('-is_emergency', '-updated_at') if sort == 'emergency' else ('-updated_at',)

    recent_tickets = active_qs.order_by(*active_order)[:10]
    closed_tickets = closed_qs.order_by(*closed_order)[:10]

    return render(request, 'incidents/system_owner_dashboard.html', {
        'stats':          stats,
        'recent_tickets': recent_tickets,
        'closed_tickets': closed_tickets,
        'profile':        profile,
        'is_superuser_view': request.user.is_superuser,
        'emergency_filter': emergency_filter,
        'sort': sort,
    })
