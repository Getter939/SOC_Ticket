"""Audited, operator-assisted recovery. Requires trusted server-shell access."""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from apps.accounts.mfa import reset_authenticator


class Command(BaseCommand):
    help = 'Reset an authenticator after verifying the account owner’s identity. Existing MFA sessions are revoked.'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument(
            '--actor', required=True, help='Active superuser responsible for this recovery.'
        )
        parser.add_argument(
            '--reason',
            required=True,
            help='Ticket/reference and how identity was verified. Never include credentials.',
        )

    def handle(self, *args, **options):
        User = get_user_model()
        user = User.objects.filter(username=options['username']).first()
        actor = User.objects.filter(
            username=options['actor'], is_active=True, is_superuser=True
        ).first()
        if not user or not actor:
            raise CommandError('The target user and an active superuser actor must exist.')
        if not options['reason'].strip():
            raise CommandError('An identity-verification reason is required.')
        reset_authenticator(user, actor=actor, reason=options['reason'])
        self.stdout.write(
            self.style.SUCCESS(
                'Authenticator reset. The user must sign in and complete enrollment again.'
            )
        )
