"""
Tests for modules the 2026-07 code audit flagged as uncovered:

1. IpLookupViewTest      — RDAP lookup endpoint: input validation, the
                           private/loopback SSRF guard (must make NO outbound
                           call), upstream success and failure handling.
2. GlobalSearchViewTest  — Postgres full-text search: visible_to scoping on
                           ticket results and the SOC-only triage-results gate.
3. TrendMicroParserTest  — pure date/score parsers in import_trendmicro.
4. TrendMicroImportTest  — end-to-end CSV import: field mapping, duplicate-row
                           merging, idempotent re-run, --dry-run rollback.

Run with:  py manage.py test apps.incidents.test_lookup_search_import --settings=config.settings_local
"""

import csv
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.management.commands.import_trendmicro import (
    parse_ack, parse_created, parse_stopped_at, parse_thai_report_date,
)
from apps.incidents.models import Ticket, TicketLog, TriageRecord


def _make_user(username, role, tier='', department='Test', phone='000'):
    user = User.objects.create_user(username=username, password='testpass123')
    UserProfile.objects.create(
        user=user, role=role, tier=tier, department=department, phone=phone,
    )
    return user


# ──────────────────────────────────────────────────────────────────────────── #
# 1. IP lookup (RDAP)                                                          #
# ──────────────────────────────────────────────────────────────────────────── #

class IpLookupViewTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_user('t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)

    def setUp(self):
        self.client.login(username='t1', password='testpass123')

    def test_requires_login(self):
        self.client.logout()
        resp = self.client.get(reverse('ip_lookup'), {'ip': '8.8.8.8'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('login', resp['Location'])

    def test_invalid_ip_returns_400(self):
        resp = self.client.get(reverse('ip_lookup'), {'ip': 'not-an-ip'})
        self.assertEqual(resp.status_code, 400)
        self.assertIn('error', resp.json())

    @patch('apps.incidents.views.requests.get')
    def test_private_ip_never_hits_rdap(self, mock_get):
        """The SSRF guard: private/loopback/link-local addresses must be
        answered locally without any outbound HTTP request."""
        for ip in ('192.168.1.10', '10.0.0.1', '127.0.0.1', '169.254.1.1', '::1'):
            resp = self.client.get(reverse('ip_lookup'), {'ip': ip})
            self.assertEqual(resp.status_code, 200, ip)
            self.assertIn('error', resp.json(), ip)
        mock_get.assert_not_called()

    @patch('apps.incidents.views.requests.get')
    def test_public_ip_success(self, mock_get):
        mock_get.return_value = Mock(
            json=Mock(return_value={
                'name': 'EXAMPLE-NET',
                'startAddress': '8.8.8.0',
                'endAddress': '8.8.8.255',
                'type': 'ALLOCATED',
                'country': 'US',
                'entities': [
                    {'vcardArray': ['vcard', [['fn', {}, 'text', 'Example Org']]]},
                ],
            }),
            raise_for_status=Mock(),
        )
        resp = self.client.get(reverse('ip_lookup'), {'ip': '8.8.8.8'})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['network_name'], 'EXAMPLE-NET')
        self.assertEqual(data['org'], 'Example Org')
        self.assertEqual(data['country'], 'US')
        mock_get.assert_called_once()
        self.assertIn('8.8.8.8', mock_get.call_args[0][0])

    @patch('apps.incidents.views.requests.get')
    def test_rdap_failure_returns_502(self, mock_get):
        mock_get.side_effect = requests.RequestException('connection refused')
        resp = self.client.get(reverse('ip_lookup'), {'ip': '8.8.8.8'})
        self.assertEqual(resp.status_code, 502)
        self.assertIn('error', resp.json())


# ──────────────────────────────────────────────────────────────────────────── #
# 2. Global full-text search                                                   #
# ──────────────────────────────────────────────────────────────────────────── #

class GlobalSearchViewTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_user('t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.sysadm = _make_user('sysadm', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.ticket = Ticket.objects.create(
            device_name='malwarebox',
            issue_description='suspicious beaconing to known C2',
            ip_address='10.0.0.5',
            created_by=cls.t1,
        )
        cls.triage = TriageRecord.objects.create(
            alert_description='malwarebox unusual outbound traffic',
            analyst=cls.t1,
        )

    def test_soc_user_sees_ticket_and_triage_results(self):
        self.client.login(username='t1', password='testpass123')
        resp = self.client.get(reverse('global_search'), {'q': 'malwarebox'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(self.ticket, list(resp.context['ticket_results']))
        self.assertIn(self.triage, list(resp.context['triage_results']))

    def test_system_admin_sees_neither_unassigned_ticket_nor_triage(self):
        """Ticket results honour visible_to (admin sees only assigned tickets)
        and triage results are gated to SOC roles entirely."""
        self.client.login(username='sysadm', password='testpass123')
        resp = self.client.get(reverse('global_search'), {'q': 'malwarebox'})
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(self.ticket, list(resp.context['ticket_results']))
        self.assertEqual(list(resp.context['triage_results']), [])

    def test_assigned_ticket_visible_to_system_admin(self):
        self.ticket.assigned_admin = self.sysadm
        self.ticket.save()
        self.client.login(username='sysadm', password='testpass123')
        resp = self.client.get(reverse('global_search'), {'q': 'malwarebox'})
        self.assertIn(self.ticket, list(resp.context['ticket_results']))

    def test_empty_query_returns_no_results(self):
        self.client.login(username='t1', password='testpass123')
        resp = self.client.get(reverse('global_search'), {'q': '   '})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(list(resp.context['ticket_results']), [])
        self.assertEqual(list(resp.context['triage_results']), [])


# ──────────────────────────────────────────────────────────────────────────── #
# 3. TrendMicro import — pure parsers                                          #
# ──────────────────────────────────────────────────────────────────────────── #

class TrendMicroParserTest(TestCase):
    def test_parse_created_day_first_with_time(self):
        dt = parse_created('10/4/2026, 11:14:00')
        self.assertEqual(
            (dt.year, dt.month, dt.day, dt.hour, dt.minute),
            (2026, 4, 10, 11, 14),
        )
        self.assertTrue(timezone.is_aware(dt))

    def test_parse_created_bad_input_returns_none(self):
        self.assertIsNone(parse_created(''))
        self.assertIsNone(parse_created(None))
        self.assertIsNone(parse_created('yesterday'))
        self.assertIsNone(parse_created('2026-04-10'))  # ISO not a tracker format

    def test_parse_ack_bare_date(self):
        dt = parse_ack('11/4/2026')
        self.assertEqual((dt.year, dt.month, dt.day, dt.hour), (2026, 4, 11, 0))

    def test_parse_thai_report_date_buddhist_two_digit_year(self):
        dt = parse_thai_report_date('ปปกก./45  ลว.14 พ.ค. 69')
        # พ.ศ. 69 → 2569 → ค.ศ. 2026; day from ลว.14; month from พ.ค (May).
        self.assertEqual((dt.year, dt.month, dt.day), (2026, 5, 14))

    def test_parse_thai_report_date_missing_parts_returns_none(self):
        self.assertIsNone(parse_thai_report_date(''))
        self.assertIsNone(parse_thai_report_date('ส่งรายงานแล้ว'))

    def test_parse_stopped_at(self):
        dt = parse_stopped_at('ปิดงาน *หยุดการเคลื่อนไหว 2026-05-19 14:18:11')
        self.assertEqual(
            (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second),
            (2026, 5, 19, 14, 18, 11),
        )
        self.assertIsNone(parse_stopped_at('ไม่มีข้อมูล'))


# ──────────────────────────────────────────────────────────────────────────── #
# 4. TrendMicro import — end-to-end command                                    #
# ──────────────────────────────────────────────────────────────────────────── #

CSV_FIELDS = [
    'no', 'รหัส Incident', 'รหัส INC', 'Created Date', 'วันที่รับเคส',
    'วันที่ออกรายงาน', 'หมายเหตุ', 'Validation Result', 'Status', 'Category',
    'ผู้รับผิดชอบ', 'Detail', 'Case Note', 'Current Score', 'Severity',
    'Case Key', 'Critical Level',
]


def _write_csv(directory, rows, name='tracker.csv'):
    path = Path(directory) / name
    with open(path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({**{k: '' for k in CSV_FIELDS}, **row})
    return str(path)


class TrendMicroImportTest(TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _rows(self):
        return [
            {   # primary row of the WB-0001 duplicate group (most complete)
                'no': '1', 'รหัส Incident': 'WB-0001',
                'Created Date': '10/4/2026, 11:14:00',
                'วันที่รับเคส': '11/4/2026',
                'หมายเหตุ': '*หยุดการเคลื่อนไหว 2026-04-12 10:00:00',
                'Validation Result': 'TP', 'Status': 'เสร็จเรียบร้อย',
                'Category': 'Malicious Logic', 'ผู้รับผิดชอบ': 'Alice',
                'Detail': 'EDR flagged trojan', 'Case Note': 'confirmed malware',
                'Current Score': '87.5', 'Severity': 'High',
                'Case Key': 'HOST-01', 'Critical Level': 'Emergency',
            },
            {   # duplicate row for the same incident — must merge into a log
                'no': '2', 'รหัส Incident': 'WB-0001',
                'Created Date': '10/4/2026, 11:14:00',
                'Status': 'อยู่ระหว่างการจ่ายงาน',
                'Case Note': 'first-pass note',
            },
            {   # separate benign incident
                'no': '3', 'รหัส Incident': 'WB-0002',
                'Created Date': '11/4/2026, 09:00:00',
                'Validation Result': 'FP', 'Status': 'เสร็จเรียบร้อย',
                'Category': 'Explained Anomaly',
                'Case Note': 'VPN login, benign',
            },
        ]

    def test_import_maps_fields_and_merges_duplicates(self):
        path = _write_csv(self._tmp.name, self._rows())
        call_command('import_trendmicro', path, create_missing_users=True)

        self.assertEqual(Ticket.objects.count(), 2)

        t1 = Ticket.objects.get(reference_id='WB-0001')
        self.assertEqual(t1.classification, Ticket.CLASSIFICATION_INCIDENT)
        self.assertEqual(t1.status, Ticket.STATUS_APPROVED)
        self.assertTrue(t1.is_emergency)
        self.assertEqual(t1.severity, 'High')
        self.assertEqual(t1.alert_score, 87)
        self.assertEqual(t1.detailed_issue, 'Malicious Logic')
        self.assertEqual(t1.detailed_issue2, 'Malicious Other')
        self.assertEqual(t1.device_name, 'HOST-01')
        self.assertIn('[TrendMicro Detail] EDR flagged trojan', t1.issue_description)
        self.assertIsNotNone(t1.closed_at)
        self.assertIsNotNone(t1.acknowledged_at)
        # ack (11/4 midnight) is after the alert (10/4 11:14) → no clamping
        self.assertGreater(t1.acknowledged_at, t1.incident_datetime)
        # placeholder assignee created with an unusable password
        self.assertEqual(t1.created_by.username, 'alice')
        self.assertFalse(t1.created_by.has_usable_password())
        # created_at backdated to the ack date, not import day
        t1.refresh_from_db()
        self.assertEqual(timezone.localtime(t1.created_at).day, 11)
        # import log + merged duplicate row log
        notes = list(t1.logs.values_list('note', flat=True))
        self.assertEqual(len(notes), 2)
        self.assertTrue(any('แถวซ้ำ' in n and 'first-pass note' in n for n in notes))

        t2 = Ticket.objects.get(reference_id='WB-0002')
        self.assertEqual(t2.classification, Ticket.CLASSIFICATION_EVENT)
        self.assertEqual(t2.status, Ticket.STATUS_CLOSED_EVENT)
        self.assertEqual(t2.severity, 'Unknown')  # blank Severity in sheet

    def test_rerun_is_idempotent(self):
        path = _write_csv(self._tmp.name, self._rows())
        call_command('import_trendmicro', path, create_missing_users=True)
        call_command('import_trendmicro', path, create_missing_users=True)
        self.assertEqual(Ticket.objects.count(), 2)
        self.assertEqual(
            TicketLog.objects.filter(ticket__reference_id='WB-0001').count(), 2,
        )

    def test_dry_run_rolls_back(self):
        path = _write_csv(self._tmp.name, self._rows())
        call_command('import_trendmicro', path, dry_run=True,
                     create_missing_users=True)
        self.assertEqual(Ticket.objects.count(), 0)
        self.assertFalse(User.objects.filter(username='alice').exists())

    def test_missing_assignee_without_flag_warns_and_leaves_empty(self):
        path = _write_csv(self._tmp.name, self._rows())
        call_command('import_trendmicro', path)  # no --create-missing-users
        t1 = Ticket.objects.get(reference_id='WB-0001')
        self.assertIsNone(t1.created_by)
        self.assertFalse(User.objects.filter(username='alice').exists())
