from .models import WazuhAlert
from .views import _user_tier


def pending_triage_count(request):
    """Expose pending/escalated Wazuh alert counts to SOC staff/manager nav badges."""
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {}

    profile = getattr(user, 'profile', None)
    if profile is None or not profile.is_soc:
        return {}

    context = {
        'pending_triage_count': WazuhAlert.objects.filter(
            triage_status=WazuhAlert.TRIAGE_PENDING,
        ).count(),
    }

    tier = _user_tier(profile)
    if tier:
        context['escalation_queue_count'] = WazuhAlert.objects.filter(
            triage_status=WazuhAlert.TRIAGE_ESCALATED, escalated_to_tier=tier,
        ).count()

    return context
