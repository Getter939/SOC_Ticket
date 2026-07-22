"""Tests for the reporting layer (Layer ③) — Phase 1.

Covers the ``mart.fact_ticket`` view logic (detection clock, durations, OLA
flags, Asia/Bangkok date bucketing) and the ``mart.agg_ticket_daily``
materialized view refreshed by ``refresh_reporting``.
"""
from datetime import datetime, timedelta, timezone as py_tz
from io import StringIO

from django.core.management import call_command
from django.test import TestCase, TransactionTestCase

from apps.incidents.models import Ticket
from apps.wazuh_ingest.models import WazuhAlert
from apps.reporting.models import AggTicketDaily, FactTicket

UTC = py_tz.utc


def _make_ticket(**controlled):
    """Create a minimal ticket, then force ``controlled`` fields via UPDATE so
    save()-time logic (ticket_id, OLA deadlines, auto_now_add) can't override the
    values a test wants to assert on."""
    ticket = Ticket.objects.create(
        device_name='dev', issue_description='desc',
        wazuh_alert=controlled.pop('wazuh_alert', None),
    )
    if controlled:
        Ticket.objects.filter(pk=ticket.pk).update(**controlled)
    return ticket


def _fact(ticket):
    return FactTicket.objects.get(pk=ticket.pk)


class DetectionClockTests(TestCase):
    """D3: detected_at = COALESCE(wazuh_alert.timestamp, incident_datetime,
    created_at), tagged by source precision."""

    def test_source_siem_uses_alert_timestamp(self):
        alert_ts = datetime(2026, 6, 10, 3, 0, tzinfo=UTC)
        alert = WazuhAlert.objects.create(
            opensearch_id='os-siem-1', timestamp=alert_ts, rule_level=12)
        # incident_datetime is deliberately different — SIEM timestamp must win.
        t = _make_ticket(
            wazuh_alert=alert,
            incident_datetime=datetime(2026, 6, 9, 0, 0, tzinfo=UTC))
        fact = _fact(t)
        self.assertEqual(fact.mttr_clock_source, 'siem')
        self.assertEqual(fact.detected_at, alert_ts)

    def test_source_analyst_uses_incident_datetime(self):
        det = datetime(2026, 6, 11, 8, 30, tzinfo=UTC)
        t = _make_ticket(incident_datetime=det)   # no wazuh_alert
        fact = _fact(t)
        self.assertEqual(fact.mttr_clock_source, 'analyst')
        self.assertEqual(fact.detected_at, det)

    def test_source_created_falls_back(self):
        t = _make_ticket()   # no alert, no incident_datetime
        fact = _fact(t)
        self.assertEqual(fact.mttr_clock_source, 'created')
        self.assertEqual(fact.detected_at, t.created_at)


class DurationTests(TestCase):
    def test_mttr_measured_from_detection(self):
        det = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)
        closed = det + timedelta(hours=6)
        t = _make_ticket(
            incident_datetime=det, status=Ticket.STATUS_APPROVED, closed_at=closed)
        fact = _fact(t)
        self.assertTrue(fact.is_closed)
        self.assertEqual(fact.time_to_resolve, timedelta(hours=6))

    def test_durations_null_when_unclosed(self):
        t = _make_ticket(incident_datetime=datetime(2026, 6, 1, tzinfo=UTC))
        fact = _fact(t)
        self.assertIsNone(fact.time_to_resolve)
        self.assertFalse(fact.is_closed)


class ContainOlaTests(TestCase):
    def test_met_when_closed_before_deadline(self):
        deadline = datetime(2026, 6, 2, 12, 0, tzinfo=UTC)
        t = _make_ticket(
            status=Ticket.STATUS_APPROVED,
            ola_contain_deadline=deadline,
            closed_at=deadline - timedelta(hours=1))
        fact = _fact(t)
        self.assertTrue(fact.contain_ola_applicable)
        self.assertTrue(fact.contain_ola_met)

    def test_missed_when_closed_after_deadline(self):
        deadline = datetime(2026, 6, 2, 12, 0, tzinfo=UTC)
        t = _make_ticket(
            status=Ticket.STATUS_APPROVED,
            ola_contain_deadline=deadline,
            closed_at=deadline + timedelta(hours=1))
        fact = _fact(t)
        self.assertTrue(fact.contain_ola_applicable)
        self.assertFalse(fact.contain_ola_met)

    def test_not_applicable_without_deadline(self):
        # Notification-only ticket (Medium/Low): Ticket.save() sets no contain
        # deadline. Force it null to model that (save() auto-sets one for High).
        t = _make_ticket(status=Ticket.STATUS_APPROVED,
                         ola_contain_deadline=None,
                         closed_at=datetime(2026, 6, 2, tzinfo=UTC))
        fact = _fact(t)
        self.assertFalse(fact.contain_ola_applicable)
        self.assertFalse(fact.contain_ola_met)


class LocalDateBucketingTests(TestCase):
    """Bucketing must use Asia/Bangkok (UTC+7), not UTC — or counts split on the
    wrong midnight."""

    def test_created_after_utc_midnight_is_next_local_day(self):
        # 2026-06-15 17:30 UTC == 2026-06-16 00:30 Asia/Bangkok
        t = _make_ticket(created_at=datetime(2026, 6, 15, 17, 30, tzinfo=UTC))
        fact = _fact(t)
        self.assertEqual(str(fact.opened_date_local), '2026-06-16')

    def test_created_before_utc_midnight_is_same_local_day(self):
        # 2026-06-15 16:00 UTC == 2026-06-15 23:00 Asia/Bangkok
        t = _make_ticket(created_at=datetime(2026, 6, 15, 16, 0, tzinfo=UTC))
        fact = _fact(t)
        self.assertEqual(str(fact.opened_date_local), '2026-06-15')


class AggTicketDailyTests(TestCase):
    def test_counts_and_grain(self):
        det = datetime(2026, 6, 1, 2, 0, tzinfo=UTC)
        # 3 closed High/INCIDENT/SIEM tickets closed on the same local day.
        for i in range(3):
            _make_ticket(
                severity='High', classification=Ticket.CLASSIFICATION_INCIDENT,
                issue_type='SIEM', status=Ticket.STATUS_APPROVED,
                incident_datetime=det,
                closed_at=datetime(2026, 6, 1, 5, 0, tzinfo=UTC))
        # One EVENT closed same day (must not count as incident).
        _make_ticket(
            severity='High', classification=Ticket.CLASSIFICATION_EVENT,
            issue_type='SIEM', status=Ticket.STATUS_CLOSED_EVENT,
            closed_at=datetime(2026, 6, 1, 6, 0, tzinfo=UTC))
        # An OPEN ticket must be excluded entirely.
        _make_ticket(severity='High', classification=Ticket.CLASSIFICATION_INCIDENT)

        # Non-concurrent refresh runs inside the test transaction, seeing the
        # rows above.
        call_command('refresh_reporting', '--no-concurrently')

        rows = {(r.severity, r.classification): r
                for r in AggTicketDaily.objects.filter(day='2026-06-01')}
        inc = rows[('High', 'INCIDENT')]
        self.assertEqual(inc.closed_count, 3)
        self.assertEqual(inc.incident_count, 3)
        self.assertEqual(inc.event_count, 0)
        evt = rows[('High', 'EVENT')]
        self.assertEqual(evt.closed_count, 1)
        self.assertEqual(evt.event_count, 1)


class RefreshConcurrentlyTests(TransactionTestCase):
    """The default CONCURRENTLY path needs committed data and no surrounding
    transaction — exercised here with TransactionTestCase."""

    def test_concurrent_refresh_succeeds(self):
        _make_ticket(
            severity='Critical', classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_APPROVED,
            incident_datetime=datetime(2026, 6, 3, 2, 0, tzinfo=UTC),
            closed_at=datetime(2026, 6, 3, 3, 0, tzinfo=UTC))
        out = StringIO()
        call_command('refresh_reporting', stdout=out)          # default: CONCURRENTLY
        self.assertIn("'errors': []", out.getvalue())
        self.assertTrue(
            AggTicketDaily.objects.filter(day='2026-06-03', severity='Critical').exists())
