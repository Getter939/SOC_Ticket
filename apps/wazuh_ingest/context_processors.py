from .models import WazuhAlert
from apps.incidents.models import Ticket


def pending_triage_count(request):
    """Expose Tier 1 intake and Tier 2 ticket queue counts to the navigation."""
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {}

    profile = getattr(user, 'profile', None)
    if not user.is_superuser and (profile is None or not profile.is_soc):
        return {}

    context = {
        'pending_triage_count': WazuhAlert.objects.filter(
            triage_status=WazuhAlert.TRIAGE_PENDING,
        ).count(),
    }

    if user.is_superuser or (profile and profile.is_tier2):
        # Everything waiting on Tier 2: escalation triage + both verification
        # stages (admin containment / owner remediation).
        context['escalation_queue_count'] = Ticket.objects.filter(
            status__in=Ticket.TIER2_QUEUE_STATUSES,
        ).count()

    return context
