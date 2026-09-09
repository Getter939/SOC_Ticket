"""Load the sample TI Platform inventory (docs/ti-platform-sample.csv).

One-time helper for testing IOC Search before real exports exist. Idempotent:
imports dedup on ID, so re-running skips rows already present. Attributes the
import to a Forensic Analyst if one exists, else leaves the uploader blank.
"""

from pathlib import Path

from django.conf import settings
from django.core.files import File
from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import UserProfile
from apps.incidents.ti_platform import import_inventory


class Command(BaseCommand):
    help = 'Import docs/ti-platform-sample.csv into the TI Platform inventory (test data).'

    def handle(self, *args, **options):
        path = Path(settings.BASE_DIR) / 'docs' / 'ti-platform-sample.csv'
        if not path.exists():
            raise CommandError(f'Sample file not found: {path}')

        uploader = (
            UserProfile.objects.filter(role=UserProfile.ROLE_FORENSIC)
            .select_related('user').values_list('user', flat=True).first()
        )
        user = None
        if uploader:
            from django.contrib.auth.models import User
            user = User.objects.filter(pk=uploader).first()

        with path.open('rb') as handle:
            upload = File(handle, name='ti-platform-sample.csv')
            batch = import_inventory(upload, user)

        self.stdout.write(self.style.SUCCESS(
            f'Imported {batch.row_count} rows: {batch.added_count} added, '
            f'{batch.skipped_count} duplicates skipped '
            f'(uploader: {user.username if user else "—"}).'
        ))
