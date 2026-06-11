from .models import WazuhAlert


def pending_triage_count(request):
    """Expose the pending Wazuh alert count to SOC staff/manager nav badges."""
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {}

    profile = getattr(user, 'profile', None)
    if profile is None or not profile.is_soc:
        return {}

    return {
        'pending_triage_count': WazuhAlert.objects.filter(
            triage_status=WazuhAlert.TRIAGE_PENDING,
        ).count(),
    }
