"""Shared actor predicates that do not depend on incident model imports."""


def is_creator_analyst(ticket, user):
    """Whether ``user`` is the Tier 1/Tier 2 analyst who opened ``ticket``."""
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return bool(
        profile
        and (profile.is_tier1 or profile.is_tier2)
        and user.pk == ticket.created_by_id
    )

