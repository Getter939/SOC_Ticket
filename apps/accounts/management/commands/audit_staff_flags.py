"""Report who can reach /admin/, and flag anyone who shouldn't.

``is_staff`` is what Django's AdminSite checks, and nothing in this codebase
ever sets it — every flag in the database was applied by hand through the admin
or a shell. The intended policy is "SOC Managers and superusers only", but a
policy nothing enforces is a policy that drifts silently.

Unit tests can't help here: they run against a throwaway database, so they pin
the RULE (a System Admin is bounced from /admin/) but can say nothing about the
live one. This command is the other half — it reads production data and says
whether the roster still matches.

Read-only by design. It reports; it never changes a flag. Fixing an unexpected
entry is a human decision made in the admin.
"""

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from apps.accounts.models import UserProfile


class Command(BaseCommand):
    help = 'Audit which accounts hold is_staff / is_superuser (read-only).'

    # Roles allowed to hold is_staff without being a superuser.
    ALLOWED_STAFF_ROLES = frozenset({UserProfile.ROLE_SOC_MANAGER})

    def add_arguments(self, parser):
        parser.add_argument(
            '--quiet', action='store_true',
            help='Print only violations, not the full roster.',
        )

    def handle(self, *args, **options):
        privileged = (
            User.objects
            .filter(is_staff=True)
            .union(User.objects.filter(is_superuser=True))
            .order_by('username')
        )

        violations = []
        rows = []
        for user in privileged:
            profile = getattr(user, 'profile', None)
            role = profile.role if profile else ''
            rows.append((user, role))
            # Superusers are exempt: the flag is the point of the account.
            if user.is_superuser:
                continue
            if role not in self.ALLOWED_STAFF_ROLES:
                violations.append((user, role))

        if not options['quiet']:
            self.stdout.write(self.style.MIGRATE_HEADING('Accounts that can reach /admin/:'))
            if not rows:
                self.stdout.write('  (none)')
            for user, role in rows:
                flags = []
                if user.is_superuser:
                    flags.append('superuser')
                if user.is_staff:
                    flags.append('staff')
                if not user.is_active:
                    flags.append('INACTIVE')
                self.stdout.write(
                    f'  {user.username:<20} role={role or "(none)":<18} [{", ".join(flags)}]'
                )
            self.stdout.write('')

        if violations:
            self.stderr.write(self.style.ERROR(
                f'{len(violations)} account(s) hold is_staff without being a superuser '
                f'or a {UserProfile.ROLE_SOC_MANAGER}:'
            ))
            for user, role in violations:
                self.stderr.write(f'  {user.username} (role={role or "(none)"})')
            self.stderr.write(
                'Review these in the Django admin. This command does not change flags.'
            )
            # Non-zero exit so a scheduled run or CI step can fail on drift.
            raise SystemExit(1)

        self.stdout.write(self.style.SUCCESS(
            'OK - is_staff is limited to superusers and SOC Managers.'
        ))
