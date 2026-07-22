"""Tests for the reporting layer (Layer ③) — Phase 1.

Covers the ``mart.fact_ticket`` view logic (detection clock, durations, OLA
flags, Asia/Bangkok date bucketing) and the ``mart.agg_ticket_daily``
materialized view refreshed by ``refresh_reporting``.
"""
from datetime import datetime, timedelta, timezone as py_tz
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.incidents import ola
from apps.incidents.models import Ticket
from apps.wazuh_ingest.models import WazuhAlert
from apps.reporting import detection, snapshot
from apps.reporting.models import (
    AggAlertDaily, AggDetectionDaily, AggTicketDaily, DimSeverityMap,
    FactAlert, FactTicket, SnapshotQueueDaily,
)

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
        # rows above. Skip snapshot/detection — this test only checks the agg.
        call_command('refresh_reporting', '--no-concurrently',
                     '--skip-snapshot', '--skip-detection')

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
        call_command('refresh_reporting', '--skip-detection', stdout=out)   # default: CONCURRENTLY
        self.assertIn("'errors': []", out.getvalue())
        self.assertTrue(
            AggTicketDaily.objects.filter(day='2026-06-03', severity='Critical').exists())


# ── Phase 2 ────────────────────────────────────────────────────────────── #

class OlaBucketParityTests(TestCase):
    """The snapshot's OLA buckets must match apps.incidents.ola exactly."""

    def test_buckets_match_ola_thresholds(self):
        now = timezone.now()
        cases = {
            'Critical': (now - timedelta(hours=1), ola.OVERDUE),
            'High':     (now + timedelta(minutes=30), ola.DUE_1H),
            'Medium':   (now + timedelta(hours=2), ola.DUE_4H),
            'Low':      (now + timedelta(hours=10), ola.ON_TRACK),
            'Unknown':  (None, snapshot.OLA_NONE),
        }
        for sev, (deadline, _) in cases.items():
            _make_ticket(severity=sev, ola_contain_deadline=deadline)

        rows = {r.severity: r for r in snapshot.compute_snapshot_rows(now=now)}
        for sev, (_, expected_bucket) in cases.items():
            self.assertEqual(rows[sev].ola_bucket, expected_bucket, f'severity={sev}')

        # Cross-check the non-null buckets against ola.bucket_filter itself.
        for sev, (deadline, _) in cases.items():
            if deadline is None:
                continue
            bucket = rows[sev].ola_bucket
            matched = Ticket.objects.filter(
                ola.bucket_filter(bucket, now), severity=sev).exists()
            self.assertTrue(matched, f'{sev} not in ola.bucket_filter({bucket})')


class AgeBucketTests(TestCase):
    def test_age_buckets(self):
        now = timezone.now()
        expected = {
            'Critical': (now, snapshot.AGE_0_1D),
            'High':     (now - timedelta(days=2), snapshot.AGE_1_3D),
            'Medium':   (now - timedelta(days=5), snapshot.AGE_3_7D),
            'Low':      (now - timedelta(days=10), snapshot.AGE_7D_PLUS),
        }
        for sev, (created, _) in expected.items():
            _make_ticket(severity=sev, created_at=created)
        rows = {r.severity: r for r in snapshot.compute_snapshot_rows(now=now)}
        for sev, (_, bucket) in expected.items():
            self.assertEqual(rows[sev].age_bucket, bucket, f'severity={sev}')


class SnapshotIdempotencyTests(TestCase):
    def test_rerun_same_day_does_not_duplicate(self):
        for _ in range(3):
            _make_ticket(severity='High')   # open (status NEW), same grain
        today = timezone.localdate()

        call_command('refresh_reporting', '--skip-detection', '--no-concurrently')
        first = list(SnapshotQueueDaily.objects.filter(snapshot_date=today))
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].open_count, 3)

        # Re-run: still exactly one row-set for the day, not doubled.
        call_command('refresh_reporting', '--skip-detection', '--no-concurrently')
        second = SnapshotQueueDaily.objects.filter(snapshot_date=today)
        self.assertEqual(second.count(), 1)
        self.assertEqual(second.first().open_count, 3)

    def test_terminal_tickets_excluded(self):
        _make_ticket(severity='High')                                  # open
        _make_ticket(severity='High', status=Ticket.STATUS_APPROVED)   # closed
        rows = snapshot.compute_snapshot_rows()
        self.assertEqual(sum(r.open_count for r in rows), 1)


class DetectionParseTests(TestCase):
    def test_parse_response_flattens_buckets(self):
        payload = {'aggregations': {'per_day': {'buckets': [
            {'key_as_string': '2026-06-15T00:00:00.000+07:00', 'per_level': {'buckets': [
                {'key': 12, 'doc_count': 40, 'agents': {'value': 3}},
                {'key': 10, 'doc_count': 100, 'agents': {'value': 7}},
            ]}},
        ]}}}
        rows = detection.parse_response(payload)
        self.assertEqual(rows, [
            {'day': '2026-06-15', 'rule_level': 12, 'alert_count': 40, 'agent_count': 3},
            {'day': '2026-06-15', 'rule_level': 10, 'alert_count': 100, 'agent_count': 7},
        ])


class DetectionCaptureTests(TestCase):
    def test_capture_upserts_and_is_idempotent(self):
        first = [{'day': '2026-06-15', 'rule_level': 12, 'alert_count': 40, 'agent_count': 3}]
        with patch('apps.reporting.detection.fetch_detection_daily', return_value=first):
            call_command('refresh_reporting', '--skip-snapshot', '--no-concurrently')
        row = AggDetectionDaily.objects.get(day='2026-06-15', rule_level=12)
        self.assertEqual(row.alert_count, 40)

        # Re-capture same grain with a new count → updated in place, not doubled.
        second = [{'day': '2026-06-15', 'rule_level': 12, 'alert_count': 55, 'agent_count': 4}]
        with patch('apps.reporting.detection.fetch_detection_daily', return_value=second):
            call_command('refresh_reporting', '--skip-snapshot', '--no-concurrently')
        self.assertEqual(AggDetectionDaily.objects.filter(day='2026-06-15', rule_level=12).count(), 1)
        self.assertEqual(AggDetectionDaily.objects.get(day='2026-06-15', rule_level=12).alert_count, 55)

    def test_detection_failure_is_non_fatal(self):
        _make_ticket(severity='High')
        out = StringIO()
        with patch('apps.reporting.detection.fetch_detection_daily',
                   side_effect=RuntimeError('indexer down')):
            call_command('refresh_reporting', '--no-concurrently', stdout=out)
        # Detection failed but the snapshot still ran.
        self.assertIn('Detection capture failed', out.getvalue())
        self.assertEqual(AggDetectionDaily.objects.count(), 0)
        self.assertTrue(SnapshotQueueDaily.objects.exists())


# ── Phase 3 ────────────────────────────────────────────────────────────── #

def _make_alert(rule_level=12, **fields):
    ts = fields.pop('timestamp', datetime(2026, 6, 20, 2, 0, tzinfo=UTC))
    return WazuhAlert.objects.create(
        opensearch_id=fields.pop('opensearch_id', f'os-{WazuhAlert.objects.count()}'),
        timestamp=ts, rule_level=rule_level, **fields)


class SeverityMapSeedTests(TestCase):
    def test_wazuh_bands_seeded(self):
        bands = {(m.min_value, m.max_value): m.canonical_band
                 for m in DimSeverityMap.objects.filter(source_system='WAZUH')}
        self.assertEqual(bands[(14, 999)], 'Critical')
        self.assertEqual(bands[(12, 13)], 'High')
        self.assertEqual(bands[(7, 11)], 'Medium')
        self.assertEqual(bands[(0, 6)], 'Low')


class FactAlertBandingTests(TestCase):
    def test_rule_level_maps_to_canonical_band(self):
        for level, expected in [(15, 'Critical'), (13, 'High'), (10, 'Medium'), (3, 'Low')]:
            a = _make_alert(rule_level=level)
            self.assertEqual(FactAlert.objects.get(pk=a.pk).severity_band, expected,
                             f'rule_level={level}')

    def test_unmapped_level_falls_back_to_unknown(self):
        # Remove the map → nothing matches → Unknown (never silently Low).
        DimSeverityMap.objects.all().delete()
        a = _make_alert(rule_level=12)
        self.assertEqual(FactAlert.objects.get(pk=a.pk).severity_band, 'Unknown')

    def test_native_rule_level_preserved(self):
        a = _make_alert(rule_level=13)
        self.assertEqual(FactAlert.objects.get(pk=a.pk).rule_level, 13)


class FactAlertFunnelTests(TestCase):
    def test_triage_status_flags(self):
        cases = {
            WazuhAlert.TRIAGE_TRUE_POSITIVE: 'is_true_positive',
            WazuhAlert.TRIAGE_FALSE_POSITIVE: 'is_false_positive',
            WazuhAlert.TRIAGE_ESCALATED: 'is_escalated',
        }
        for status, flag in cases.items():
            a = _make_alert(triage_status=status)
            fact = FactAlert.objects.get(pk=a.pk)
            self.assertTrue(getattr(fact, flag))
            self.assertTrue(fact.is_triaged)

    def test_pending_is_not_triaged(self):
        a = _make_alert(triage_status=WazuhAlert.TRIAGE_PENDING)
        self.assertFalse(FactAlert.objects.get(pk=a.pk).is_triaged)

    def test_became_ticket(self):
        linked = _make_alert(opensearch_id='os-linked')
        Ticket.objects.create(device_name='d', issue_description='i', wazuh_alert=linked)
        unlinked = _make_alert(opensearch_id='os-unlinked')
        self.assertTrue(FactAlert.objects.get(pk=linked.pk).became_ticket)
        self.assertFalse(FactAlert.objects.get(pk=unlinked.pk).became_ticket)

    def test_triage_ola(self):
        ts = datetime(2026, 6, 20, 0, 0, tzinfo=UTC)
        within = _make_alert(opensearch_id='os-in', timestamp=ts,
                             triage_status=WazuhAlert.TRIAGE_TRUE_POSITIVE,
                             triaged_at=ts + timedelta(hours=3))
        breach = _make_alert(opensearch_id='os-br', timestamp=ts,
                             triage_status=WazuhAlert.TRIAGE_TRUE_POSITIVE,
                             triaged_at=ts + timedelta(hours=5))
        pending = _make_alert(opensearch_id='os-pd', timestamp=ts)
        self.assertTrue(FactAlert.objects.get(pk=within.pk).triage_ola_met)
        self.assertFalse(FactAlert.objects.get(pk=breach.pk).triage_ola_met)
        self.assertTrue(FactAlert.objects.get(pk=breach.pk).triage_ola_applicable)
        self.assertFalse(FactAlert.objects.get(pk=pending.pk).triage_ola_applicable)


class AggAlertDailyTests(TestCase):
    def test_funnel_counts(self):
        ts = datetime(2026, 6, 20, 2, 0, tzinfo=UTC)   # → 2026-06-20 local
        _make_alert(opensearch_id='a1', rule_level=13, timestamp=ts,
                    triage_status=WazuhAlert.TRIAGE_TRUE_POSITIVE, triaged_at=ts + timedelta(hours=1))
        _make_alert(opensearch_id='a2', rule_level=13, timestamp=ts,
                    triage_status=WazuhAlert.TRIAGE_FALSE_POSITIVE, triaged_at=ts + timedelta(hours=2))
        _make_alert(opensearch_id='a3', rule_level=13, timestamp=ts)   # High, pending

        call_command('refresh_reporting', '--no-concurrently',
                     '--skip-snapshot', '--skip-detection')

        row = AggAlertDaily.objects.get(day='2026-06-20', severity_band='High')
        self.assertEqual(row.ingested_count, 3)
        self.assertEqual(row.triaged_count, 2)
        self.assertEqual(row.true_positive_count, 1)
        self.assertEqual(row.false_positive_count, 1)
        self.assertEqual(row.triage_ola_applicable, 2)
        self.assertEqual(row.triage_ola_met, 2)
