import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from apps.wazuh_ingest.ingest import fetch_and_store_alerts, store_alert_hits


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

    def handle(self, *args, **options):
        fixture = options.get('fixture')
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

            result = store_alert_hits(
                hits,
                min_level=options['min_level'],
                advance_watermark=False,
            )
            result['source'] = str(fixture_path)
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
