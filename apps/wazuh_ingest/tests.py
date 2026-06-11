from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from .ingest import fetch_and_store_alerts
from .models import IngestWatermark, WazuhAlert


def _make_user(username, role, department='Test', phone='000', tier=''):
    user = User.objects.create_user(username=username, password='testpass123')
    UserProfile.objects.create(user=user, role=role, department=department, phone=phone, tier=tier)
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
        cls.soc_staff = _make_user('triage_soc', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.soc_staff2 = _make_user('triage_soc2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.soc_manager = _make_user('triage_mgr', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('triage_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def setUp(self):
        self.alert = _make_alert(rule_level=12, opensearch_id='queue-alert-1')

    def _claim(self, username='triage_soc'):
        self.client.login(username=username, password='testpass123')
        self.client.post(reverse('claim_alert'), {'alert_id': self.alert.pk})
        self.alert.refresh_from_db()

    def test_soc_staff_can_view_queue(self):
        self.client.login(username='triage_soc', password='testpass123')
        response = self.client.get(reverse('triage_queue'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Suspicious PowerShell execution')

    def test_system_admin_redirected_away(self):
        self.client.login(username='triage_admin', password='testpass123')
        response = self.client.get(reverse('triage_queue'))

        self.assertRedirects(response, reverse('ticket_list'))

    def test_claim_alert_sets_triaging_status(self):
        self.client.login(username='triage_soc', password='testpass123')

        response = self.client.post(reverse('claim_alert'), {'alert_id': self.alert.pk})

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)
        self.assertEqual(self.alert.claimed_by, self.soc_staff)
        self.assertIsNotNone(self.alert.claimed_at)

    def test_claim_already_triaging_alert_is_rejected(self):
        self._claim('triage_soc')

        self.client.login(username='triage_soc2', password='testpass123')
        response = self.client.post(reverse('claim_alert'), {'alert_id': self.alert.pk})

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.claimed_by, self.soc_staff)

    def test_release_alert_returns_to_pending(self):
        self._claim('triage_soc')

        response = self.client.post(reverse('release_alert'), {'alert_id': self.alert.pk})

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_PENDING)
        self.assertIsNone(self.alert.claimed_by)
        self.assertIsNone(self.alert.claimed_at)

    def test_action_without_claim_is_rejected(self):
        self.client.login(username='triage_soc', password='testpass123')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': 'Trying without claiming first.',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_PENDING)

    def test_action_by_non_claimer_is_rejected(self):
        self._claim('triage_soc')

        self.client.login(username='triage_soc2', password='testpass123')
        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': 'Trying to act on someone else\'s claim.',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)

    def test_close_fp_sets_status_and_audit_fields(self):
        self._claim('triage_soc')

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

    def test_create_ticket_requires_category(self):
        self._claim('triage_soc')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'create_ticket',
            'note': 'Confirmed malicious — escalating to ticket.',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)

    def test_create_ticket_redirects_with_prefill_params(self):
        self._claim('triage_soc')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'create_ticket',
            'category': WazuhAlert.CATEGORY_MALWARE,
            'note': 'Confirmed malicious — escalating to ticket.',
        })

        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)
        self.assertEqual(self.alert.claimed_by, self.soc_staff)
        self.assertEqual(self.alert.incident_category, WazuhAlert.CATEGORY_MALWARE)

        expected_url = reverse('create_ticket')
        self.assertTrue(response.url.startswith(expected_url + '?'))
        self.assertIn(f'wazuh_alert={self.alert.pk}', response.url)
        self.assertIn('severity=High', response.url)
        self.assertIn('detailed_issue2=Malware', response.url)

    def test_t1_cannot_escalate_to_same_tier(self):
        self._claim('triage_soc')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'escalate',
            'escalate_to': WazuhAlert.TIER_T1,
            'category': WazuhAlert.CATEGORY_OTHER,
            'note': 'Invalid same-tier escalation.',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)

    def test_escalate_sets_status_and_tier(self):
        self._claim('triage_soc')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'escalate',
            'escalate_to': WazuhAlert.TIER_T2,
            'category': WazuhAlert.CATEGORY_OTHER,
            'note': 'Needs deeper investigation by T2.',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)
        self.assertEqual(self.alert.escalated_to_tier, WazuhAlert.TIER_T2)
        self.assertEqual(self.alert.incident_category, WazuhAlert.CATEGORY_OTHER)

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
        self.assertTrue(any('ไม่ได้อยู่ในความรับผิดชอบ' in str(m) for m in messages_list))

        self.alert.refresh_from_db()
        # Status unchanged from the FALSE_POSITIVE set above.
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_FALSE_POSITIVE)

    def test_empty_note_is_rejected(self):
        self._claim('triage_soc')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': '',
        })

        self.assertRedirects(response, reverse('triage_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)


class EscalationQueueTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1_analyst = _make_user('esc_t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.t2_analyst = _make_user('esc_t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.t2_analyst2 = _make_user('esc_t2_other', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.manager = _make_user('esc_mgr', UserProfile.ROLE_SOC_MANAGER)

    def setUp(self):
        self.alert = _make_alert(rule_level=14, opensearch_id='escalated-alert-1')
        self.alert.triage_status = WazuhAlert.TRIAGE_ESCALATED
        self.alert.escalated_to_tier = WazuhAlert.TIER_T2
        self.alert.triage_note = 'Needs deeper investigation by T2.'
        self.alert.save(update_fields=['triage_status', 'escalated_to_tier', 'triage_note'])

    def _claim(self, username='esc_t2'):
        self.client.login(username=username, password='testpass123')
        self.client.post(reverse('claim_escalation'), {'alert_id': self.alert.pk})
        self.alert.refresh_from_db()

    def test_t2_sees_alert_escalated_to_t2(self):
        self.client.login(username='esc_t2', password='testpass123')
        response = self.client.get(reverse('escalation_queue'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Suspicious PowerShell execution')

    def test_t1_does_not_see_alert_escalated_to_t2(self):
        self.client.login(username='esc_t1', password='testpass123')
        response = self.client.get(reverse('escalation_queue'))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Suspicious PowerShell execution')

    def test_t2_can_close_escalated_alert_as_fp(self):
        self._claim()

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': 'T2 confirmed benign.',
            'source': 'escalation_queue',
        })

        self.assertRedirects(response, reverse('escalation_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_FALSE_POSITIVE)
        self.assertEqual(self.alert.triaged_by, self.t2_analyst)

    def test_t2_can_create_ticket_from_escalated_alert(self):
        self._claim()

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'create_ticket',
            'category': WazuhAlert.CATEGORY_DATA_EXFILTRATION,
            'note': 'T2 confirmed malicious.',
            'source': 'escalation_queue',
        })

        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)
        self.assertEqual(self.alert.claimed_by, self.t2_analyst)

        expected_url = reverse('create_ticket')
        self.assertTrue(response.url.startswith(expected_url + '?'))
        self.assertIn(f'wazuh_alert={self.alert.pk}', response.url)

    def test_t2_can_escalate_further_to_manager(self):
        self._claim()

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'escalate',
            'escalate_to': WazuhAlert.TIER_MANAGER,
            'category': WazuhAlert.CATEGORY_DATA_EXFILTRATION,
            'note': 'T2 needs Manager review.',
            'source': 'escalation_queue',
        })

        self.assertRedirects(response, reverse('escalation_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)
        self.assertEqual(self.alert.escalated_to_tier, WazuhAlert.TIER_MANAGER)

    def test_manager_sees_alert_escalated_to_manager(self):
        self.alert.escalated_to_tier = WazuhAlert.TIER_MANAGER
        self.alert.save(update_fields=['escalated_to_tier'])

        self.client.login(username='esc_mgr', password='testpass123')
        response = self.client.get(reverse('escalation_queue'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Suspicious PowerShell execution')

    def test_t1_cannot_act_on_alert_escalated_to_t2(self):
        self.client.login(username='esc_t1', password='testpass123')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': 'T1 trying to close.',
            'source': 'escalation_queue',
        })

        self.assertRedirects(response, reverse('escalation_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)

    def test_escalated_alert_must_be_claimed_before_action(self):
        self.client.login(username='esc_t2', password='testpass123')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': 'Attempt without claim.',
            'source': 'escalation_queue',
        })

        self.assertRedirects(response, reverse('escalation_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)
        self.assertIsNone(self.alert.claimed_by)

    def test_claim_and_release_escalated_alert(self):
        self._claim()
        self.assertEqual(self.alert.claimed_by, self.t2_analyst)
        self.assertIsNotNone(self.alert.claimed_at)

        response = self.client.post(
            reverse('release_escalation'),
            {'alert_id': self.alert.pk},
        )

        self.assertRedirects(response, reverse('escalation_queue'))
        self.alert.refresh_from_db()
        self.assertIsNone(self.alert.claimed_by)
        self.assertIsNone(self.alert.claimed_at)

    def test_other_t2_cannot_act_on_claimed_escalation(self):
        self._claim()
        self.client.login(username='esc_t2_other', password='testpass123')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'close_fp',
            'note': 'Attempt by another T2 analyst.',
            'source': 'escalation_queue',
        })

        self.assertRedirects(response, reverse('escalation_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)
        self.assertEqual(self.alert.claimed_by, self.t2_analyst)

    def test_manager_cannot_escalate_to_same_or_lower_tier(self):
        self.alert.escalated_to_tier = WazuhAlert.TIER_MANAGER
        self.alert.save(update_fields=['escalated_to_tier'])
        self._claim('esc_mgr')

        response = self.client.post(reverse('triage_action'), {
            'alert_id': self.alert.pk,
            'action': 'escalate',
            'escalate_to': WazuhAlert.TIER_T2,
            'category': WazuhAlert.CATEGORY_OTHER,
            'note': 'Invalid downward escalation.',
            'source': 'escalation_queue',
        })

        self.assertRedirects(response, reverse('escalation_queue'))
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.escalated_to_tier, WazuhAlert.TIER_MANAGER)


class SuperuserWazuhAccessTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.superuser = User.objects.create_superuser(
            username='wazuh_superuser',
            email='wazuh-super@example.com',
            password='testpass123',
        )

    def setUp(self):
        self.client.force_login(self.superuser)

    def test_superuser_without_profile_can_claim_and_triage_alert(self):
        alert = _make_alert(
            opensearch_id='superuser-pending-alert',
            rule_level=14,
        )

        queue_response = self.client.get(reverse('triage_queue'))
        self.assertEqual(queue_response.status_code, 200)
        self.assertContains(queue_response, alert.rule_description)

        claim_response = self.client.post(
            reverse('claim_alert'),
            {'alert_id': alert.pk},
        )
        self.assertRedirects(claim_response, reverse('triage_queue'))

        alert.refresh_from_db()
        self.assertEqual(alert.claimed_by, self.superuser)
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)

        action_response = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk,
            'action': 'close_fp',
            'note': 'Superuser confirmed benign.',
        })
        self.assertRedirects(action_response, reverse('triage_queue'))

        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_FALSE_POSITIVE)
        self.assertEqual(alert.triaged_by, self.superuser)

    def test_superuser_sees_and_can_claim_escalations_for_all_tiers(self):
        t1_alert = _make_alert(
            opensearch_id='superuser-t1-escalation',
            rule_level=11,
            triage_status=WazuhAlert.TRIAGE_ESCALATED,
            escalated_to_tier=WazuhAlert.TIER_T1,
        )
        t2_alert = _make_alert(
            opensearch_id='superuser-t2-escalation',
            rule_level=12,
            triage_status=WazuhAlert.TRIAGE_ESCALATED,
            escalated_to_tier=WazuhAlert.TIER_T2,
        )
        manager_alert = _make_alert(
            opensearch_id='superuser-manager-escalation',
            rule_level=15,
            triage_status=WazuhAlert.TRIAGE_ESCALATED,
            escalated_to_tier=WazuhAlert.TIER_MANAGER,
        )

        response = self.client.get(reverse('escalation_queue'))
        self.assertEqual(response.status_code, 200)
        visible_alerts = list(response.context['alerts'])
        for alert in (t1_alert, t2_alert, manager_alert):
            self.assertIn(alert, visible_alerts)

        claim_response = self.client.post(
            reverse('claim_escalation'),
            {'alert_id': t2_alert.pk},
        )
        self.assertRedirects(claim_response, reverse('escalation_queue'))
        t2_alert.refresh_from_db()
        self.assertEqual(t2_alert.claimed_by, self.superuser)

    def test_superuser_can_escalate_to_any_tier(self):
        alert = _make_alert(
            opensearch_id='superuser-reassign-escalation',
            rule_level=13,
            triage_status=WazuhAlert.TRIAGE_ESCALATED,
            escalated_to_tier=WazuhAlert.TIER_MANAGER,
            claimed_by=self.superuser,
            claimed_at=timezone.now(),
        )

        response = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk,
            'action': 'escalate',
            'escalate_to': WazuhAlert.TIER_T1,
            'category': WazuhAlert.CATEGORY_OTHER,
            'note': 'Superuser reassigned for operational review.',
            'source': 'escalation_queue',
        })

        self.assertRedirects(response, reverse('escalation_queue'))
        alert.refresh_from_db()
        self.assertEqual(alert.escalated_to_tier, WazuhAlert.TIER_T1)
        self.assertIsNone(alert.claimed_by)
