"""
Shared, role-based actor resolution for every seed command.

Seeders run against environments that hold REAL staff accounts — the UAT VM
runs entirely on them. So no seeder may create, modify or delete a user, and
none may touch a password. Instead each one *discovers* who currently holds
each role and attributes its synthetic tickets to those people.

This module is the single source of truth for that lookup so every seeder
produces data in the same shape and fails the same way. It replaced the old
per-command synthetic accounts (``seed_*``, ``uat_*`` and the dashboard-mockup
name accounts), which duplicated real staff and, on a shared box, risked
clobbering them.

Typical use::

    from apps.incidents.management import seed_actors

    actors = seed_actors.resolve()
    seed_actors.require(actors, 'T1', 'MANAGER', 'ADMIN')   # raises CommandError
    t1s = seed_actors.cycler(actors, 'T1')      # round-robin over real analysts
    owner = seed_actors.first(actors, 'OWNER')  # None when the role is unfilled

``cycler`` yields ``None`` forever for an unfilled role, so an optional actor
(a System Owner, say) degrades to a null FK instead of crashing the seed.
"""

from itertools import cycle, repeat

from django.contrib.auth.models import User
from django.core.management.base import CommandError

from apps.accounts.models import UserProfile

# key → (role, tier or None, human label used in error messages)
KEY_SPECS = {
    'T1':       (UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T1,
                 'SOC Staff at Tier 1 (role SOC_STAFF + tier T1)'),
    'T2':       (UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T2,
                 'SOC Staff at Tier 2 (role SOC_STAFF + tier T2)'),
    'STAFF':    (UserProfile.ROLE_SOC_STAFF, None, 'SOC Staff (role SOC_STAFF)'),
    'MANAGER':  (UserProfile.ROLE_SOC_MANAGER, None, 'SOC Manager (role SOC_MANAGER)'),
    'ADMIN':    (UserProfile.ROLE_SYSTEM_ADMIN, None, 'System Admin (role SYSTEM_ADMIN)'),
    'OWNER':    (UserProfile.ROLE_SYSTEM_OWNER, None, 'System Owner (role SYSTEM_OWNER)'),
    'FORENSIC': (UserProfile.ROLE_FORENSIC, None, 'Forensic Analyst (role FORENSIC)'),
    'REDTEAM':  (UserProfile.ROLE_REDTEAM_MANAGER, None,
                 'Red Team Manager (role REDTEAM_MANAGER)'),
}

# Tier-specific keys fall back to any SOC staff, so an environment that has not
# split its analysts into tiers still seeds instead of refusing to run.
_TIER_FALLBACK = {'T1': 'STAFF', 'T2': 'STAFF'}


def resolve():
    """Map every actor key to the list of active users holding that role.

    Never creates or modifies anything. Ordering is by username so repeated
    runs attribute data consistently.
    """
    actors = {}
    for key, (role, tier, _label) in KEY_SPECS.items():
        qs = User.objects.filter(is_active=True, profile__role=role)
        if tier is not None:
            qs = qs.filter(profile__tier=tier)
        actors[key] = list(qs.select_related('profile').order_by('username'))

    for key, fallback in _TIER_FALLBACK.items():
        if not actors[key]:
            actors[key] = list(actors[fallback])
    return actors


def require(actors, *keys):
    """Raise CommandError naming every requested role that has no active user.

    Deliberately refuses rather than inventing an account: on a real box a
    missing role is a configuration gap for a human to fix in admin.
    """
    missing = [KEY_SPECS[k][2] for k in keys if not actors.get(k)]
    if missing:
        raise CommandError(
            'Cannot seed - no active user holds these role(s):\n  - '
            + '\n  - '.join(missing)
            + '\n\nAssign them in Django admin (Accounts > User profiles), then '
              're-run.\nSeed commands never create user accounts.'
        )


def first(actors, key):
    """The first user holding ``key``, or None when the role is unfilled."""
    users = actors.get(key) or []
    return users[0] if users else None


def cycler(actors, key):
    """Round-robin iterator over the holders of ``key``.

    Yields None forever when the role is unfilled, so optional actors degrade
    to a null FK rather than raising.
    """
    users = actors.get(key) or []
    return cycle(users) if users else repeat(None)


def summary(actors, keys=None):
    """Multi-line 'role: usernames' report for a command's stdout.

    Usernames only — seeders must not print real people's names or emails.
    """
    lines = []
    for key in (keys or KEY_SPECS):
        users = actors.get(key) or []
        names = ', '.join(u.username for u in users) if users else '(none)'
        lines.append(f'  {key:<9}: {names}')
    return '\n'.join(lines)
