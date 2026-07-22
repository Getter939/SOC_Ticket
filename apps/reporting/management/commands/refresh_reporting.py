"""Refresh the reporting-layer (Layer ③).

Steps, each isolated so one failure never aborts the rest (same resilient shape
as ``ingest_wazuh_alerts``); the command reports a result dict:

  1. REFRESH the ``mart.agg_ticket_daily`` materialized view.
  2. Write today's ``mart.snapshot_queue_daily`` rows (point-in-time queue).
  3. Capture ``mart.agg_detection_daily`` from the Wazuh Indexer.

Scheduling: run nightly from the same OS scheduler as the Wazuh ingest, at a
consistent local time (the snapshot captures the queue "as of" the run).

CONCURRENTLY note: ``REFRESH MATERIALIZED VIEW CONCURRENTLY`` cannot run inside
a transaction and needs a unique index (migration 0001) plus an already-populated
view. Management commands run in autocommit by default, so the default path is
safe. Use ``--no-concurrently`` when running inside an outer transaction.
"""
import logging

from django.core.management.base import BaseCommand
from django.db import connection, transaction
from django.utils import timezone

from apps.reporting import detection, snapshot
from apps.reporting.models import AggDetectionDaily, SnapshotQueueDaily

logger = logging.getLogger(__name__)

MATERIALIZED_VIEWS = ['mart.agg_ticket_daily']


class Command(BaseCommand):
    help = 'Refresh the reporting-layer views, queue snapshot, and detection capture.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--no-concurrently', action='store_true',
            help='Use a plain (locking) REFRESH instead of CONCURRENTLY.',
        )
        parser.add_argument(
            '--skip-snapshot', action='store_true',
            help='Skip writing the daily queue snapshot.',
        )
        parser.add_argument(
            '--skip-detection', action='store_true',
            help='Skip the Wazuh Indexer detection capture.',
        )
        parser.add_argument(
            '--detection-days', type=int, default=2,
            help='Days of Indexer history to (re)capture per run (default: 2).',
        )

    def handle(self, *args, **options):
        result = {
            'mv_refreshed': [], 'snapshot_rows': None,
            'detection_rows': None, 'errors': [],
        }

        # ── Step 1: materialized views ───────────────────────────────────── #
        concurrently = not options['no_concurrently']
        for mv in MATERIALIZED_VIEWS:
            keyword = 'CONCURRENTLY ' if concurrently else ''
            try:
                with connection.cursor() as cursor:
                    cursor.execute(f'REFRESH MATERIALIZED VIEW {keyword}{mv}')
                result['mv_refreshed'].append(mv)
            except Exception as exc:
                msg = f'Failed to refresh {mv}: {exc}'
                logger.error(msg)
                result['errors'].append(msg)
                self.stderr.write(msg)

        # ── Step 2: daily queue snapshot (point-in-time; idempotent) ─────── #
        if not options['skip_snapshot']:
            try:
                now = timezone.now()
                snap_date = timezone.localdate(now)
                rows = snapshot.compute_snapshot_rows(now=now, snapshot_date=snap_date)
                # Delete-then-insert for this date so a same-day re-run reflects
                # the current queue exactly (no stale grains left behind).
                with transaction.atomic():
                    SnapshotQueueDaily.objects.filter(snapshot_date=snap_date).delete()
                    SnapshotQueueDaily.objects.bulk_create(rows)
                result['snapshot_rows'] = len(rows)
            except Exception as exc:
                msg = f'Failed to write queue snapshot: {exc}'
                logger.error(msg)
                result['errors'].append(msg)
                self.stderr.write(msg)

        # ── Step 3: detection capture from the Wazuh Indexer ─────────────── #
        if not options['skip_detection']:
            try:
                rows = detection.fetch_detection_daily(days=options['detection_days'])
                objs = [
                    AggDetectionDaily(
                        day=r['day'], rule_level=r['rule_level'],
                        alert_count=r['alert_count'], agent_count=r['agent_count'],
                    )
                    for r in rows
                ]
                AggDetectionDaily.objects.bulk_create(
                    objs, update_conflicts=True,
                    unique_fields=['day', 'rule_level'],
                    update_fields=['alert_count', 'agent_count'],
                )
                result['detection_rows'] = len(objs)
            except Exception as exc:
                msg = f'Detection capture failed (non-fatal): {exc}'
                logger.error(msg)
                result['errors'].append(msg)
                self.stderr.write(msg)

        self.stdout.write(str(result))
        return None
