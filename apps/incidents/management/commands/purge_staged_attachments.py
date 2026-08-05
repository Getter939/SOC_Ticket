"""Remove evidence staged for case forms that were never submitted.

StagedAttachment holds uploads between a failed submit and the retry. When an
analyst abandons the form instead, the rows and their files stay behind — this
command is what keeps that from growing without bound.

Production is Windows Server + native PostgreSQL + Waitress, not the Docker
stack in the repo docs, so schedule this through **Task Scheduler**, not cron:

    schtasks /create /tn "SOC purge staged attachments" /sc daily /st 03:00 ^
        /tr "C:\\path\\to\\venv\\Scripts\\python.exe C:\\path\\to\\manage.py purge_staged_attachments"

Safe to run at any time: it only ever touches StagedAttachment. Real evidence
(TicketAttachment / ProjectIncidentAttachment) is never in scope.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.incidents.staging import purge_expired, purge_orphan_files


class Command(BaseCommand):
    help = 'Delete abandoned staged case-form attachments older than --hours.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--hours', type=int, default=24,
            help='Age in hours past which staged files are removed '
                 '(default 24; 0 purges everything staged).',
        )
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Report what would be removed without deleting anything.',
        )

    def handle(self, *args, **options):
        hours = options['hours']
        cutoff = timezone.now() - timezone.timedelta(hours=hours)

        if options['dry_run']:
            from apps.incidents.models import StagedAttachment
            count = StagedAttachment.objects.filter(created_at__lt=cutoff).count()
            self.stdout.write(
                f'[dry-run] would remove {count} staged attachment(s) '
                f'older than {hours}h'
            )
            return

        removed = purge_expired(cutoff)
        orphans = purge_orphan_files(cutoff)
        self.stdout.write(self.style.SUCCESS(
            f'Removed {removed} staged attachment(s) and {orphans} orphaned '
            f'file(s) older than {hours}h'
        ))
