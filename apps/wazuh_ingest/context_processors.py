from django.db.models import Q

from .models import WazuhAlert
from apps.incidents.models import Ticket, TicketSubtask, TriageRecord


def pending_triage_count(request):
    """Expose Tier 1 intake and Tier 2 ticket queue counts to the navigation."""
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {}

    profile = getattr(user, 'profile', None)

    # Response-team members are not SOC — surface their own "My Requests" badge
    # before the SOC-only gate below and return.
    if profile is not None and profile.is_response_team:
        return {
            'response_request_queue_count': TicketSubtask.objects.filter(
                subtask_type__in=TicketSubtask.RESPONSE_TYPES,
                assigned_to=user,
            ).exclude(status=TicketSubtask.STATUS_DONE).count(),
        }

    if not user.is_superuser and (profile is None or not profile.is_soc):
        return {}

    context = {
        'pending_triage_count': WazuhAlert.objects.filter(
            triage_status=WazuhAlert.TRIAGE_PENDING,
        ).count(),
    }

    if user.is_superuser or (profile and profile.is_tier1):
        # My Queue badge: manual reports this analyst can pick up or already
        # holds, plus their own-court tickets — above all cases Tier 2
        # returned (T1_REVIEW), which previously surfaced nowhere.
        context['my_queue_count'] = (
            TriageRecord.objects.filter(
                decision='', ticket__isnull=True,
            ).filter(
                Q(claimed_by__isnull=True) | Q(claimed_by=user)
            ).count()
            + Ticket.objects.filter(
                created_by=user, status__in=Ticket.TIER1_QUEUE_STATUSES,
            ).count()
        )

    if user.is_superuser or (profile and profile.is_tier2):
        # Everything waiting on Tier 2: escalation triage + both verification
        # stages (admin containment / owner remediation).
        context['escalation_queue_count'] = Ticket.objects.filter(
            status__in=Ticket.TIER2_QUEUE_STATUSES,
        ).count()

    if user.is_superuser or (profile and profile.is_soc_manager):
        # Everything waiting on the SOC Manager: the pre-containment review
        # plus the emergency approval gate.
        context['manager_queue_count'] = Ticket.objects.filter(
            status__in=Ticket.MANAGER_QUEUE_STATUSES,
        ).count()

    return context
