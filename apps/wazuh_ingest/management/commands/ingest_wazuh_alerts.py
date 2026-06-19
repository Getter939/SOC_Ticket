import json
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.wazuh_ingest.ingest import fetch_and_store_alerts, store_alert_hits
from apps.wazuh_ingest.models import WazuhAlert


class Command(BaseCommand):
    help = 'Fetch new Wazuh alerts (rule.level >= --min-level) from OpenSearch and store them.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--min-level', type=int, default=10,
            help='Minimum rule.level to ingest (default: 10).',
        )
        parser.add_argument(
            '--batch-size', type=int, default=500,
            help='Maximum number of alerts to fetch per run (default: 500).',
        )
        parser.add_argument(
            '--fixture',
            nargs='?',
            const='bundled',
            help=(
                'Load alerts from an OpenSearch response JSON file without making an HTTP '
                'request. Omit the path to use the bundled demo fixture.'
            ),
        )
        parser.add_argument(
            '--fresh',
            action='store_true',
            help=(
                'Create a new test batch from the fixture by assigning unique synthetic '
                'OpenSearch IDs and current timestamps. Only valid with --fixture.'
            ),
        )

    def handle(self, *args, **options):
        fixture = options.get('fixture')
        fresh = options.get('fresh', False)
        if fresh and not fixture:
            raise CommandError('--fresh can only be used together with --fixture.')

        if fixture:
            fixture_path = self._fixture_path(fixture)
            try:
                payload = json.loads(fixture_path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError) as exc:
                raise CommandError(f'Could not load Wazuh fixture {fixture_path}: {exc}') from exc

            hits = payload if isinstance(payload, list) else payload.get('hits', {}).get('hits')
            if not isinstance(hits, list):
                raise CommandError(
                    'Fixture must be a list of OpenSearch hits or an OpenSearch response '
                    'containing hits.hits.'
                )

            if fresh:
                hits = self._fresh_fixture_hits(hits)

            result = store_alert_hits(
                hits,
                min_level=options['min_level'],
                advance_watermark=False,
            )
            result['source'] = str(fixture_path)
            result['fresh'] = fresh
            if not fresh and result['fetched'] and result['created'] == 0:
                result['hint'] = (
                    'Fixture alerts already exist. Use --fixture --fresh to create a new '
                    'test batch.'
                )
        else:
            result = fetch_and_store_alerts(
                min_level=options['min_level'],
                batch_size=options['batch_size'],
            )
        self.stdout.write(str(result))

    @staticmethod
    def _fixture_path(value):
        if value == 'bundled':
            return Path(__file__).resolve().parents[2] / 'fixtures' / 'wazuh_alerts.demo.json'
        return Path(value).expanduser().resolve()

    @staticmethod
    def _fresh_fixture_hits(hits):
        """Return fixture hits with unique IDs and timestamps suitable for a new test run."""
        run_id = uuid4().hex[:12]
        base_timestamp = timezone.now()
        max_id_length = WazuhAlert._meta.get_field('opensearch_id').max_length
        fresh_hits = []

        for index, hit in enumerate(hits, start=1):
            if not isinstance(hit, dict):
                fresh_hits.append(hit)
                continue

            fresh_hit = deepcopy(hit)
            original_id = str(hit.get('_id', 'alert'))
            prefix = f'fixture-{run_id}-{index:04d}-'
            fresh_hit['_id'] = f'{prefix}{original_id}'[:max_id_length]

            source = fresh_hit.get('_source')
            if isinstance(source, dict):
                source['@timestamp'] = (
                    base_timestamp + timedelta(milliseconds=index)
                ).isoformat()

            fresh_hits.append(fresh_hit)

        return fresh_hits
