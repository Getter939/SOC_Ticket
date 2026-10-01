"""Refresh the reporting-layer (Layer ③).

Steps, each isolated so one failure never aborts the rest (same resilient shape
as ``ingest_wazuh_alerts``); the command reports a result dict:

  1. REFRESH the ``mart.agg_ticket_daily`` / ``mart.agg_alert_daily``
     materialized views.
  1b. Copy the alert funnel into ``mart.hist_alert_daily`` for days still inside
     the raw-alert retention window; older days are frozen (see below).
  2. Write tonight's point-in-time snapshots: ``snapshot_queue_daily``,
     ``snapshot_kpi_daily``, ``snapshot_workload_daily``,
     ``snapshot_response_daily``.
  3. Capture ``mart.agg_detection_daily`` from the Wazuh Indexer.

If any step reports an error, the command emails ``REPORTING_ALERT_EMAILS``
and exits non-zero (CommandError), so Task Scheduler's "Last Run Result" shows
the failure. A night it fails to capture cannot be captured later.

Frozen window (step 1b): ``purge_wazuh_alerts`` deletes raw alerts older than
``WAZUH_RETENTION_DAYS``. A day the purge has started on would recompute LOWER
counts, so only days newer than (retention - HIST_ALERT_MARGIN_DAYS) are
updated; older rows in ``hist_alert_daily`` are never touched again.

Scheduling: run nightly from the same OS scheduler as the Wazuh ingest, at a
consistent local time (the snapshot captures the queue "as of" the run).

CONCURRENTLY note: ``REFRESH MATERIALIZED VIEW CONCURRENTLY`` cannot run inside
a transaction and needs a unique index (migration 0001) plus an already-populated
view. Management commands run in autocommit by default, so the default path is
safe. Use ``--no-concurrently`` when running inside an outer transaction.
"""
import logging
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.utils import timezone

from apps.reporting import detection, snapshot
from apps.reporting.alerts import send_reporting_alert
from apps.reporting.models import (
    AggAlertDaily, AggDetectionDaily, HistAlertDaily, SnapshotKpiDaily,
    SnapshotQueueDaily, SnapshotResponseDaily, SnapshotWorkloadDaily,
)
from apps.wazuh_ingest.management.commands.purge_wazuh_alerts import DEFAULT_RETENTION_DAYS

logger = logging.getLogger(__name__)

MATERIALIZED_VIEWS = ['mart.agg_ticket_daily', 'mart.agg_alert_daily']

# Days kept clear of the purge's edge before a day is frozen (step 1b).
HIST_ALERT_MARGIN_DAYS = 2

# Every table step 2 writes, cleared and rewritten together for the night.
SNAPSHOT_MODELS = [
    SnapshotQueueDaily, SnapshotKpiDaily, SnapshotWorkloadDaily, SnapshotResponseDaily,
]


def hist_alert_window_start(today, retention_days=DEFAULT_RETENTION_DAYS):
    """First day ``hist_alert_daily`` may still be updated; older days are frozen."""
    return today - timedelta(days=max(1, retention_days - HIST_ALERT_MARGIN_DAYS))


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
            'mv_refreshed': [], 'alert_history_rows': None, 'snapshot_rows': None,
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

        # ── Step 1b: keep the alert funnel past the raw-alert purge ──────── #
        # Only from a freshly refreshed view: copying a stale one would write
        # yesterday's numbers over today's.
        if 'mart.agg_alert_daily' in result['mv_refreshed']:
            try:
                now = timezone.now()
                source = AggAlertDaily.objects.all()
                # First run ever: take every day still present (backfill).
                # After that, only the unfrozen window.
                if HistAlertDaily.objects.exists():
                    source = source.filter(
                        day__gte=hist_alert_window_start(timezone.localdate(now)))
                objs = [
                    HistAlertDaily(
                        day=row.day, severity_band=row.severity_band, captured_at=now,
                        **{f: getattr(row, f) for f in HistAlertDaily.COUNT_FIELDS},
                    )
                    for row in source
                ]
                HistAlertDaily.objects.bulk_create(
                    objs, update_conflicts=True,
                    unique_fields=['day', 'severity_band'],
                    update_fields=HistAlertDaily.COUNT_FIELDS + ['captured_at'],
                )
                result['alert_history_rows'] = len(objs)
            except Exception as exc:
                msg = f'Failed to keep alert funnel history: {exc}'
                logger.error(msg)
                result['errors'].append(msg)
                self.stderr.write(msg)

        # ── Step 2: nightly snapshots (point-in-time; idempotent) ────────── #
        if not options['skip_snapshot']:
            try:
                now = timezone.now()
                snap_date = timezone.localdate(now)
                rows = snapshot.compute_snapshot_rows(now=now, snapshot_date=snap_date)
                workload = snapshot.compute_workload_rows(now=now, snapshot_date=snap_date)
                responses = snapshot.compute_response_rows(now=now, snapshot_date=snap_date)
                kpi = snapshot.compute_kpi_row(now=now, snapshot_date=snap_date)
                # Delete-then-insert for this date so a same-day re-run reflects
                # the current queue exactly (no stale grains left behind). One
                # transaction: the night's tables are all written or none are.
                with transaction.atomic():
                    for model in SNAPSHOT_MODELS:
                        model.objects.filter(snapshot_date=snap_date).delete()
                    SnapshotQueueDaily.objects.bulk_create(rows)
                    SnapshotWorkloadDaily.objects.bulk_create(workload)
                    SnapshotResponseDaily.objects.bulk_create(responses)
                    kpi.save()
                result['snapshot_rows'] = len(rows)
            except Exception as exc:
                msg = f'Failed to write nightly snapshots: {exc}'
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
        if result['errors']:
            send_reporting_alert('refresh_reporting failed', result['errors'])
            raise CommandError(
                f"refresh_reporting finished with {len(result['errors'])} error(s); "
                'see the lines above.')
        return None
