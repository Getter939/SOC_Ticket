from django.core.management.base import BaseCommand

from apps.wazuh_ingest.ingest import fetch_and_store_alerts


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

    def handle(self, *args, **options):
        result = fetch_and_store_alerts(
            min_level=options['min_level'],
            batch_size=options['batch_size'],
        )
        self.stdout.write(str(result))
