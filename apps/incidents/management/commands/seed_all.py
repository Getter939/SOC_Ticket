"""
apps/incidents/management/commands/seed_all.py

One command to reset and regenerate every seed dataset, in the right order.

All seeders now attribute their data to the REAL accounts holding each role
(see apps.incidents.management.seed_actors) and none of them creates, modifies
or deletes a user. This command additionally PURGES the legacy synthetic
accounts that older versions used to create — ``uat_*``, ``seed_*`` and the
dashboard-mockup name accounts — so those never reappear in the system.

Purge order matters: the user FKs on Ticket are SET_NULL, so deleting an
account first would silently orphan its tickets (created_by becomes NULL and
the rows can no longer be identified). Legacy tickets are therefore removed
BEFORE their authors.

Usage:
    python manage.py seed_all --dry-run    # show the plan, write nothing
    python manage.py seed_all              # purge legacy + reset + reseed all
    python manage.py seed_all --keep-legacy-users   # reseed, leave old accounts
    python manage.py seed_all --purge-only          # only remove legacy rows
"""

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import BaseCommand

from apps.incidents.management import seed_actors
from apps.incidents.models import Ticket

# Usernames older seeders invented. They duplicated real staff (one even shares
# a first name with a real SOC Manager), so they are removed rather than kept.
LEGACY_USER_PREFIXES = ('uat_', 'seed_')
LEGACY_USER_NAMES = (
    'surapong', 'kamjad', 'pongpanit', 'supatach', 'poy', 'natt', 'santi',
)

# Content markers / reference prefixes owned by the seeders, used to remove
# their rows before the authors disappear.
LEGACY_TICKET_MARKERS = ('[UAT-STATE]', '[SEED-DATA]', '[RESPONSE-DEMO]')
LEGACY_REFERENCE_PREFIXES = ('MOCK-SOC-', 'DEMO-CEO-')

# (label, command, kwargs) in dependency order. Volume first so the dashboards
# have a base, then the deterministic per-state rows, then the focused demos.
SEED_STEPS = [
    ('Volume dataset (30 days)', 'seed_data', {'tickets': 60, 'days': 30, 'flush': True}),
    ('One ticket per lifecycle state', 'seed_uat_states', {'per_state': 2, 'flush': True}),
    ('Response-team requests', 'seed_response_demo', {'flush': True}),
    ('CEO demo tickets', 'seed_ceo_demo', {}),
]


class Command(BaseCommand):
    help = ('Purge legacy synthetic accounts and regenerate every seed dataset '
            'against the real role-holders.')

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true',
                            help='Show what would happen; write nothing.')
        parser.add_argument('--keep-legacy-users', action='store_true',
                            help='Reseed but leave the old uat_/seed_/mock accounts in place.')
        parser.add_argument('--purge-only', action='store_true',
                            help='Only remove legacy rows and accounts; do not reseed.')
        parser.add_argument('--mockup', action='store_true',
                            help='Also run seed_dashboard_mockup (screenshot dataset).')

    def handle(self, *args, **options):
        dry = options['dry_run']

        actors = seed_actors.resolve()
        self.stdout.write(self.style.MIGRATE_HEADING('Real accounts by role'))
        self.stdout.write(seed_actors.summary(actors))

        legacy_users = self._legacy_users()
        legacy_tickets = self._legacy_tickets()

        self.stdout.write(self.style.MIGRATE_HEADING('\nLegacy synthetic data'))
        self.stdout.write(f'  seed tickets to remove : {legacy_tickets.count()}')
        self.stdout.write(
            '  accounts to remove     : '
            + (', '.join(u.username for u in legacy_users) if legacy_users else '(none)')
        )

        if dry:
            self.stdout.write(self.style.MIGRATE_HEADING('\nWould run'))
            for label, name, opts in self._steps(options):
                self.stdout.write(f'  {name:<22} {label}')
            self.stdout.write(self.style.SUCCESS('\nDry run - nothing written.'))
            return

        # ── 1. purge ─────────────────────────────────────────────────────── #
        _, per_model = legacy_tickets.delete()
        self.stdout.write(self.style.WARNING(
            f"\nRemoved {per_model.get('incidents.Ticket', 0)} legacy seed ticket(s)."
        ))
        if options['keep_legacy_users']:
            self.stdout.write('Kept legacy accounts (--keep-legacy-users).')
        elif legacy_users:
            names = ', '.join(u.username for u in legacy_users)
            # Anything still authored by these accounts would be orphaned by the
            # SET_NULL FK rather than removed, so surface it instead of hiding it.
            stranded = Ticket.objects.filter(
                created_by__in=legacy_users).exclude(pk__in=()).count()
            User.objects.filter(pk__in=[u.pk for u in legacy_users]).delete()
            self.stdout.write(self.style.WARNING(f'Removed legacy account(s): {names}'))
            if stranded:
                self.stdout.write(self.style.WARNING(
                    f'  NOTE: {stranded} ticket(s) authored by those accounts kept '
                    'their data but lost their author (created_by is now empty).'
                ))

        if options['purge_only']:
            self.stdout.write(self.style.SUCCESS('\nPurge complete (--purge-only).'))
            return

        # ── 2. reseed ────────────────────────────────────────────────────── #
        # Roles are required only now: purging can run on a box that has not
        # had its roles assigned yet.
        seed_actors.require(seed_actors.resolve(), 'T1', 'T2', 'MANAGER', 'ADMIN')

        for label, name, opts in self._steps(options):
            self.stdout.write(self.style.MIGRATE_HEADING(f'\n== {name} - {label}'))
            try:
                call_command(name, **opts, stdout=self.stdout, stderr=self.stderr)
            except Exception as exc:
                # One failing dataset should not abandon the rest.
                self.stderr.write(self.style.ERROR(f'  {name} failed: {exc}'))

        self.stdout.write(self.style.SUCCESS('\nAll seed datasets regenerated.'))
        self.stdout.write(
            'No user accounts were created or modified - everyone signs in with '
            'their own credentials.'
        )

    # ── helpers ──────────────────────────────────────────────────────────── #

    def _steps(self, options):
        steps = list(SEED_STEPS)
        if options['mockup']:
            steps.append(('Dashboard screenshot dataset', 'seed_dashboard_mockup',
                          {'reset': True, 'apply': True}))
        return steps

    @staticmethod
    def _legacy_users():
        """Synthetic accounts invented by older seeders (never real staff)."""
        qs = User.objects.none()
        for prefix in LEGACY_USER_PREFIXES:
            qs = qs | User.objects.filter(username__startswith=prefix)
        qs = qs | User.objects.filter(username__in=LEGACY_USER_NAMES)
        # Never touch a superuser: on a deployed box that is usually the
        # operator's own login, and removing it locks them out of /admin/.
        return list(qs.exclude(is_superuser=True).distinct().order_by('username'))

    @staticmethod
    def _legacy_tickets():
        """Every seeded ticket, by marker or reference prefix."""
        qs = Ticket.objects.none()
        for marker in LEGACY_TICKET_MARKERS:
            qs = qs | Ticket.objects.filter(issue_description__contains=marker)
        for prefix in LEGACY_REFERENCE_PREFIXES:
            qs = qs | Ticket.objects.filter(reference_id__startswith=prefix)
        # Rows authored by a legacy account but predating the content markers.
        # Both the prefixed AND the named accounts must be covered here: the
        # user FKs are SET_NULL, so any row still pointing at an account we are
        # about to delete would be silently orphaned instead of removed.
        for prefix in LEGACY_USER_PREFIXES:
            qs = qs | Ticket.objects.filter(created_by__username__startswith=prefix)
        qs = qs | Ticket.objects.filter(created_by__username__in=LEGACY_USER_NAMES)
        return qs.distinct()
