"""Refresh the reporting-layer (Layer ③) materialized views.

Phase 1 scope: refresh ``mart.agg_ticket_daily``. Phase 2 will add the daily
queue snapshot and the Indexer-fed detection capture as further guarded steps.

Structured like ``ingest_wazuh_alerts``: each step is isolated so one failure
never aborts the rest, and the command reports a result dict.

Scheduling: run nightly from the same OS scheduler as the Wazuh ingest.

Note on CONCURRENTLY: ``REFRESH MATERIALIZED VIEW CONCURRENTLY`` cannot run
inside a transaction block and needs a unique index (migration 0001 creates one)
plus an already-populated view (0001 builds it ``WITH DATA``). Management
commands run in autocommit by default, so the default path is safe. Use
``--no-concurrently`` for the rare case of running inside an outer transaction.
"""
import logging

from django.core.management.base import BaseCommand
from django.db import connection

logger = logging.getLogger(__name__)

# Materialized views refreshed by this command, in order.
MATERIALIZED_VIEWS = ['mart.agg_ticket_daily']


class Command(BaseCommand):
    help = 'Refresh the reporting-layer materialized views (Phase 1: agg_ticket_daily).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--no-concurrently', action='store_true',
            help=(
                'Use a plain (table-locking) REFRESH instead of CONCURRENTLY. '
                'Needed when running inside an outer transaction.'
            ),
        )

    def handle(self, *args, **options):
        concurrently = not options['no_concurrently']
        result = {'mv_refreshed': [], 'errors': []}

        for mv in MATERIALIZED_VIEWS:
            keyword = 'CONCURRENTLY ' if concurrently else ''
            sql = f'REFRESH MATERIALIZED VIEW {keyword}{mv}'
            try:
                with connection.cursor() as cursor:
                    cursor.execute(sql)
                result['mv_refreshed'].append(mv)
            except Exception as exc:
                msg = f'Failed to refresh {mv}: {exc}'
                logger.error(msg)
                result['errors'].append(msg)
                self.stderr.write(msg)

        self.stdout.write(str(result))
        return None
