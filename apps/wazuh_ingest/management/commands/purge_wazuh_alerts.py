"""Apply a retention window to the raw Wazuh alert queue.

Ingestion adds every alert at or above the configured rule level, so WazuhAlert
grows without bound while only a fraction ever becomes a ticket. This trims the
remainder.

The age filter is the easy half. The exclusions are the point of this command:

    Ticket.wazuh_alert      OneToOne, on_delete=SET_NULL
    TicketAlertLink.alert   OneToOne, on_delete=CASCADE

A purge that filtered on timestamp alone would silently null the alert pointer
on any ticket raised from an alert older than the window, and cascade-delete
its link row — destroying the alert-to-incident provenance that incident
reports and the reporting mart depend on, with no error and no way back short
of a restore. So a linked alert is never in scope at any age.

PENDING and TRIAGING alerts are also never in scope. An old untriaged alert is
unfinished work, and deleting it hides a backlog rather than trimming history.
If those accumulate, the answer is triage capacity, not retention.

Production is Windows Server + native PostgreSQL + Waitress, so schedule this
through **Task Scheduler**, not cron, and after the nightly ingestion window
rather than overlapping it:

    schtasks /create /tn "SOC purge wazuh alerts" /sc daily /st 04:00 ^
        /tr "C:\\SOCTicket\\app\\venv\\Scripts\\python.exe C:\\SOCTicket\\app\\manage.py purge_wazuh_alerts"

Agree the retention period with compliance before the first production run.
"""

import logging

from decouple import config
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.wazuh_ingest.models import WazuhAlert

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = config('WAZUH_RETENTION_DAYS', default=90, cast=int)

# Open work. Never deleted, however old.
PROTECTED_TRIAGE_STATUSES = (
    WazuhAlert.TRIAGE_PENDING,
    WazuhAlert.TRIAGE_TRIAGING,
)


def delete_unlinked_batch(alert_ids):
    """Delete the given alerts, re-checking every exclusion at delete time.

    Gathering ids and then deleting by primary key alone leaves a window in
    which an analyst can attach one of those alerts to a ticket as a supporting
    alert. TicketAlertLink.alert cascades, so the delete would then destroy the
    link they had just made, with no error and nothing in the log.

    Re-applying the filters here puts the exclusions in the delete's own WHERE
    clause, so an alert that stopped being eligible between selection and
    deletion is skipped instead of removed. Returns the number of alerts
    actually deleted, which is what the caller must count — the batch size is
    an upper bound, not a result.
    """
    _, per_model = (
        WazuhAlert.objects
        .filter(pk__in=alert_ids)
        .filter(
            ticket__isnull=True,
            ticket_alert_link__isnull=True,
            project_incident__isnull=True,
        )
        .exclude(triage_status__in=PROTECTED_TRIAGE_STATUSES)
        .delete()
    )
    return per_model.get('wazuh_ingest.WazuhAlert', 0)


class Command(BaseCommand):
    help = (
        'Delete raw Wazuh alerts older than --days that were never linked to a '
        'ticket, bundle, or left pending triage.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--days', type=int, default=DEFAULT_RETENTION_DAYS,
            help=f'Retention window in days (default {DEFAULT_RETENTION_DAYS}, '
                 f'from WAZUH_RETENTION_DAYS).',
        )
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Report what would be deleted, and what is being kept and why, '
                 'without deleting anything.',
        )
        parser.add_argument(
            '--batch-size', type=int, default=1000,
            help='Rows deleted per transaction (default 1000). Keeps a purge '
                 'from holding a long lock against the live triage queue.',
        )

    def handle(self, *args, **options):
        days = options['days']
        batch_size = options['batch_size']

        if days < 1:
            raise CommandError('--days must be at least 1; refusing to purge the live queue.')
        if batch_size < 1:
            raise CommandError('--batch-size must be at least 1.')

        cutoff = timezone.now() - timezone.timedelta(days=days)
        aged = WazuhAlert.objects.filter(timestamp__lt=cutoff)

        deletable = aged.filter(
            ticket__isnull=True,
            ticket_alert_link__isnull=True,
            project_incident__isnull=True,
        ).exclude(triage_status__in=PROTECTED_TRIAGE_STATUSES)

        aged_total = aged.count()
        target_total = deletable.count()
        kept_total = aged_total - target_total

        if options['dry_run']:
            # The breakdown is what makes a first run reviewable: it shows which
            # exclusion is holding each alert back, so an unexpectedly small
            # delete count can be explained without querying by hand.
            kept_linked = aged.filter(ticket__isnull=False).count()
            kept_link_row = aged.filter(ticket_alert_link__isnull=False).count()
            kept_bundled = aged.filter(project_incident__isnull=False).count()
            kept_open = aged.filter(triage_status__in=PROTECTED_TRIAGE_STATUSES).count()

            self.stdout.write(
                f'[dry-run] cutoff {cutoff:%Y-%m-%d %H:%M %Z} (--days {days})\n'
                f'[dry-run] {aged_total} alert(s) older than the window\n'
                f'[dry-run] would delete {target_total}\n'
                f'[dry-run] would keep   {kept_total}\n'
                f'[dry-run]   linked to a ticket : {kept_linked}\n'
                f'[dry-run]   has an alert link  : {kept_link_row}\n'
                f'[dry-run]   in a bundle        : {kept_bundled}\n'
                f'[dry-run]   pending / triaging : {kept_open}\n'
                f'[dry-run]   (categories overlap; an alert may match several)'
            )
            return

        deleted_total = 0
        while True:
            # Re-evaluate the queryset each pass rather than paginating: rows
            # are disappearing underneath it, and a sliced queryset cannot be
            # used directly in delete().
            batch_ids = list(deletable.values_list('pk', flat=True)[:batch_size])
            if not batch_ids:
                break

            removed = delete_unlinked_batch(batch_ids)
            deleted_total += removed

            if removed == 0:
                # Every alert in this batch was linked or reopened between the
                # select and the delete. Stopping guarantees the loop always
                # terminates; whatever is still eligible is picked up by the
                # next scheduled run, and retention is not time-critical.
                logger.warning(
                    'wazuh retention: %d alert(s) became protected between '
                    'selection and deletion; stopping this run.',
                    len(batch_ids),
                )
                break

        message = (
            f'Purged {deleted_total} Wazuh alert(s) older than {days} day(s); '
            f'kept {kept_total} of {aged_total} aged alert(s) as linked or open.'
        )
        logger.info('wazuh retention: %s', message)
        self.stdout.write(self.style.SUCCESS(message))
