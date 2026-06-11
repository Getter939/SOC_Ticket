from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from .ingest import fetch_and_store_alerts
from .models import IngestWatermark, WazuhAlert


def _make_hit(opensearch_id='6jTLMJkB07VbjNIu73jt', rule_level=12, timestamp='2025-09-09T23:25:29.409Z'):
    return {
        '_id': opensearch_id,
        '_source': {
            '@timestamp': timestamp,
            'agent': {'id': '001', 'name': 'DESKTOP-EP4F8C5', 'ip': '1.1.1.1'},
            'rule': {
                'id': '60106',
                'level': rule_level,
                'description': 'Windows Logon Success',
                'groups': ['windows', 'authentication_success'],
                'mitre': {
                    'technique': ['Valid Accounts'],
                    'tactic': ['Defense Evasion', 'Persistence'],
                    'id': ['T1078'],
                },
            },
            'data': {'win': {'eventdata': {}, 'system': {'eventID': '4624'}}},
            'decoder': {'name': 'windows_eventchannel'},
            'location': 'EventChannel',
            'id': '1757460329.5863487',
            'timestamp': '2025-09-09T23:25:29.409+0000',
        },
    }


def _mock_response(hits):
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {'hits': {'hits': hits}}
    return response


class FetchAndStoreAlertsTest(TestCase):
    @patch('apps.wazuh_ingest.ingest.requests.post')
    def test_valid_alert_is_parsed_and_stored(self, mock_post):
        mock_post.return_value = _mock_response([_make_hit()])

        result = fetch_and_store_alerts(min_level=10)

        self.assertEqual(result['fetched'], 1)
        self.assertEqual(result['created'], 1)
        self.assertEqual(result['skipped'], 0)
        self.assertEqual(result['errors'], [])

        alert = WazuhAlert.objects.get(opensearch_id='6jTLMJkB07VbjNIu73jt')
        self.assertEqual(alert.alert_id, '1757460329.5863487')
        self.assertEqual(alert.agent_id, '001')
        self.assertEqual(alert.agent_name, 'DESKTOP-EP4F8C5')
        self.assertEqual(alert.agent_ip, '1.1.1.1')
        self.assertEqual(alert.rule_id, '60106')
        self.assertEqual(alert.rule_level, 12)
        self.assertEqual(alert.rule_description, 'Windows Logon Success')
        self.assertEqual(alert.rule_groups, ['windows', 'authentication_success'])
        self.assertEqual(alert.mitre_techniques, ['Valid Accounts'])
        self.assertEqual(alert.mitre_tactics, ['Defense Evasion', 'Persistence'])
        self.assertEqual(alert.mitre_ids, ['T1078'])
        self.assertEqual(alert.decoder_name, 'windows_eventchannel')
        self.assertEqual(alert.raw_data, {'win': {'eventdata': {}, 'system': {'eventID': '4624'}}})

    @patch('apps.wazuh_ingest.ingest.requests.post')
    def test_duplicate_opensearch_id_is_skipped(self, mock_post):
        WazuhAlert.objects.create(
            opensearch_id='6jTLMJkB07VbjNIu73jt',
            timestamp=timezone.now(),
            rule_level=12,
        )

        mock_post.return_value = _mock_response([_make_hit()])

        result = fetch_and_store_alerts(min_level=10)

        self.assertEqual(result['fetched'], 1)
        self.assertEqual(result['created'], 0)
        self.assertEqual(result['skipped'], 1)
        self.assertEqual(WazuhAlert.objects.count(), 1)

    @patch('apps.wazuh_ingest.ingest.requests.post')
    def test_low_level_alert_not_stored_when_min_level_10(self, mock_post):
        # The query itself filters by rule.level >= min_level, so OpenSearch
        # would never return this hit for min_level=10 — simulate that by
        # returning no hits for the low-level query.
        mock_post.return_value = _mock_response([])

        result = fetch_and_store_alerts(min_level=10)

        self.assertEqual(result['fetched'], 0)
        self.assertEqual(result['created'], 0)
        self.assertEqual(WazuhAlert.objects.count(), 0)

        # Sanity check: the query sent to OpenSearch enforces rule.level >= 10.
        sent_query = mock_post.call_args.kwargs['json']
        level_filter = sent_query['query']['bool']['filter'][0]
        self.assertEqual(level_filter, {'range': {'rule.level': {'gte': 10}}})

    @patch('apps.wazuh_ingest.ingest.requests.post')
    def test_connection_failure_returns_error_dict_without_raising(self, mock_post):
        mock_post.side_effect = ConnectionError('connection refused')

        result = fetch_and_store_alerts(min_level=10)

        self.assertEqual(result['fetched'], 0)
        self.assertEqual(result['created'], 0)
        self.assertEqual(result['skipped'], 0)
        self.assertEqual(len(result['errors']), 1)
        self.assertIn('connection refused', result['errors'][0])

    @patch('apps.wazuh_ingest.ingest.requests.post')
    def test_watermark_advances_after_successful_batch(self, mock_post):
        mock_post.return_value = _mock_response([_make_hit()])

        self.assertFalse(IngestWatermark.objects.exists())

        fetch_and_store_alerts(min_level=10)

        watermark = IngestWatermark.objects.get(pk=1)
        self.assertIsNotNone(watermark.last_timestamp)
        self.assertEqual(watermark.last_timestamp.year, 2025)
        self.assertEqual(watermark.last_timestamp.month, 9)
        self.assertEqual(watermark.last_timestamp.day, 9)
