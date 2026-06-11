from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from .ingest import fetch_and_store_alerts
from .models import IngestWatermark, WazuhAlert


def _make_user(username, role, department='Test', phone='000'):
    user = User.objects.create_user(username=username, password='testpass123')
    UserProfile.objects.create(user=user, role=role, department=department, phone=phone)
    return user


def _make_alert(rule_level=12, opensearch_id='alert-1', **kwargs):
    return WazuhAlert.objects.create(
        opensearch_id=opensearch_id,
        timestamp=timezone.now(),
        rule_level=rule_level,
        rule_description='Suspicious PowerShell execution',
        agent_name='DESKTOP-EP4F8C5',
        mitre_tactics=['Defense Evasion'],
        **kwargs,
    )


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


class TriageQueueTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_user('triage_soc', UserProfile.ROLE_SOC_STAFF)
        cls.soc_manager = _make_user('triage_mgr', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('triage_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def setUp(self):
        self.alert = _make_alert(rule_level=12, opensearch_id='queue-alert-1')

    def test_soc_staff_can_view_queue(self):
        self.client.login(username='triage_soc', password='testpass123')
        response = self.client.get(reverse('triage_queue'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Suspicious PowerShell execution')

    def test_system_admin_redirected_away(self):
        self.client.login(username='triage_admin', password='testpass123')
        response = self.client.get(reverse('triage_queue'))

        self.assertRedirects(response, reverse('ticket_list'))

    def test_close_fp_sets_status_and_audit_fields(self):
        self.client.login(username='triage_soc', password='testpass123')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': 'Confirmed benign — known admin activity.',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_FALSE_POSITIVE)
        self.assertEqual(self.alert.triaged_by, self.soc_staff)
        self.assertIsNotNone(self.alert.triaged_at)
        self.assertEqual(self.alert.triage_note, 'Confirmed benign — known admin activity.')

    def test_create_ticket_redirects_with_prefill_params(self):
        self.client.login(username='triage_soc', password='testpass123')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'create_ticket',
            'note': 'Confirmed malicious — escalating to ticket.',
        })

        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_TRUE_POSITIVE)

        expected_url = reverse('create_ticket')
        self.assertTrue(response.url.startswith(expected_url + '?'))
        self.assertIn(f'wazuh_alert={self.alert.pk}', response.url)
        self.assertIn('severity=High', response.url)

    def test_escalate_sets_status_and_tier(self):
        self.client.login(username='triage_soc', password='testpass123')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'escalate',
            'escalate_to': WazuhAlert.TIER_T2,
            'note': 'Needs deeper investigation by T2.',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)
        self.assertEqual(self.alert.escalated_to_tier, WazuhAlert.TIER_T2)

    def test_action_on_already_triaged_alert_is_rejected(self):
        self.alert.triage_status = WazuhAlert.TRIAGE_FALSE_POSITIVE
        self.alert.save(update_fields=['triage_status'])

        self.client.login(username='triage_soc', password='testpass123')
        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': 'Trying again.',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        messages_list = list(get_messages(response.wsgi_request))
        self.assertTrue(any('ถูกดำเนินการ' in str(m) for m in messages_list))

        self.alert.refresh_from_db()
        # Status unchanged from the FALSE_POSITIVE set above.
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_FALSE_POSITIVE)

    def test_empty_note_is_rejected(self):
        self.client.login(username='triage_soc', password='testpass123')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': '',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_PENDING)
