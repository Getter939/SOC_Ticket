from collections import Counter
from datetime import timedelta
from io import StringIO

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketLog, TriageRecord
from apps.incidents.tests import _make_user, _make_t1, _make_t2
from apps.wazuh_ingest.models import WazuhAlert


class DashboardMockupSeedTest(TestCase):
    """The mockup seeder used to invent its own accounts and, on --reset, delete
    every non-superuser user plus every ticket. It now attributes tickets to the
    real role-holders and only removes its own MOCK-SOC- rows."""

    @classmethod
    def setUpTestData(cls):
        # Real role-holders the seeder will discover.
        cls.t1a = _make_t1('mock_t1a')
        cls.t1b = _make_t1('mock_t1b')
        cls.t2 = _make_t2('mock_t2')
        cls.manager = _make_user('mock_mgr', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('mock_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _call(self, *args):
        output = StringIO()
        call_command('seed_dashboard_mockup', *args, stdout=output)
        return output.getvalue()

    def _seed(self):
        return self._call('--reset', '--apply')

    def test_dry_run_does_not_mutate_database(self):
        bystander = User.objects.create_user(username='bystander', password='keep')
        output = self._call()

        self.assertIn('DRY RUN', output)
        self.assertIn('No database changes written', output)
        self.assertEqual(Ticket.objects.count(), 0)
        self.assertTrue(User.objects.filter(pk=bystander.pk).exists())

    def test_apply_requires_reset(self):
        with self.assertRaises(CommandError):
            self._call('--apply')

    def test_creates_no_accounts_and_deletes_none(self):
        """Regression: --reset used to wipe every non-superuser account."""
        bystander = User.objects.create_user(username='bystander', password='keep')
        before = {u.pk: u.password for u in User.objects.all()}

        output = self._seed()

        self.assertIn('Dashboard mockup dataset is ready', output)
        self.assertTrue(User.objects.filter(pk=bystander.pk).exists())
        self.assertEqual({u.pk: u.password for u in User.objects.all()}, before)

    def test_tickets_are_attributed_to_real_role_holders(self):
        self._seed()
        authors = set(Ticket.objects.values_list('created_by__username', flat=True))
        self.assertTrue(authors <= {self.t1a.username, self.t1b.username,
                                    self.t2.username})
        self.assertTrue(
            Ticket.objects.filter(assigned_admin=self.admin).exists()
        )

    def test_reset_leaves_foreign_tickets_alone(self):
        """Only MOCK-SOC- rows are removed — a tester's ticket must survive."""
        # Explicit id so it does not consume the auto sequence the seeder uses.
        keeper = Ticket.objects.create(
            ticket_id='REAL-KEEPER-1',
            device_name='REAL-HOST', ip_address='10.0.0.9',
            issue_description='A real tester ticket', created_by=self.t1a,
        )
        self._seed()
        self.assertTrue(Ticket.objects.filter(pk=keeper.pk).exists())

    def test_refuses_without_role_holders(self):
        User.objects.filter(pk=self.manager.pk).update(is_active=False)
        with self.assertRaises(CommandError):
            self._seed()

    def test_ticket_volume_daily_pattern_and_active_distribution(self):
        self._seed()
        tickets = Ticket.objects.all()
        self.assertGreaterEqual(tickets.count(), 120)

        day_counts = Counter(t.created_at.date() for t in tickets)
        self.assertEqual(len(day_counts), 30)
        self.assertGreaterEqual(min(day_counts.values()), 3)
        self.assertLessEqual(max(day_counts.values()), 8)

        weekday_counts = [
            count for day, count in day_counts.items() if day.weekday() < 5
        ]
        weekend_counts = [
            count for day, count in day_counts.items() if day.weekday() >= 5
        ]
        self.assertGreater(min(weekday_counts), max(weekend_counts))

        active = tickets.exclude(status__in=Ticket.TERMINAL_STATUSES)
        active_counts = Counter(active.values_list('status', flat=True))
        self.assertEqual(active_counts[Ticket.STATUS_NEW], 2)
        for status in [
            Ticket.STATUS_ESCALATED_T2,
            Ticket.STATUS_T1_REVIEW,
            Ticket.STATUS_AWAITING_CONTAINMENT,
            Ticket.STATUS_CONTAINMENT_REPORTED,
            Ticket.STATUS_PENDING_MANAGER,
        ]:
            self.assertGreaterEqual(active_counts[status], 3)

    def test_most_cases_are_critical_or_high_and_no_active_overdue(self):
        self._seed()
        tickets = Ticket.objects.all()
        high_pressure = tickets.filter(severity__in=['Critical', 'High']).count()
        self.assertGreater(high_pressure / tickets.count(), 0.7)

        now = timezone.now()
        active = tickets.exclude(status__in=Ticket.TERMINAL_STATUSES)
        self.assertFalse(active.filter(ola_contain_deadline__lt=now).exists())

    def test_terminal_tickets_close_within_targets_and_ola_contain_deadline(self):
        self._seed()
        terminal_tickets = Ticket.objects.filter(status__in=Ticket.TERMINAL_STATUSES)
        self.assertTrue(terminal_tickets.exists())

        for ticket in terminal_tickets:
            resolved = ticket.logs.filter(
                status_at_time__in=Ticket.TERMINAL_STATUSES,
            ).order_by('created_at').values_list('created_at', flat=True).first()
            self.assertIsNotNone(resolved)
            self.assertLessEqual(resolved - ticket.created_at, timedelta(days=1))
            self.assertLessEqual(resolved, ticket.ola_contain_deadline)
            if ticket.severity == 'Critical':
                self.assertLessEqual(ticket.created_at - ticket.incident_datetime, timedelta(minutes=30))
                self.assertLessEqual(resolved - ticket.created_at, timedelta(hours=4))

    def test_ticket_details_and_phase_feedback_are_rich(self):
        self._seed()
        sample = Ticket.objects.filter(
            status=Ticket.STATUS_APPROVED,
            severity='Critical',
        ).first()
        self.assertIsNotNone(sample)
        self.assertGreater(len(sample.issue_description), 500)
        self.assertGreater(len(sample.ioc_details), 150)
        self.assertGreater(len(sample.action_required), 150)
        self.assertGreater(len(sample.containment_report), 150)
        self.assertGreater(sample.logs.count(), 5)
        self.assertTrue(sample.logs.filter(note__contains='Tier 2 completed review').exists())
        self.assertTrue(sample.logs.filter(note__contains='containment evidence').exists())

    def test_operational_sources_are_seeded(self):
        self._seed()
        self.assertGreater(WazuhAlert.objects.count(), 0)
        self.assertGreater(TriageRecord.objects.count(), 0)
        self.assertTrue(Ticket.objects.filter(wazuh_alert__isnull=False).exists())
        self.assertTrue(TriageRecord.objects.filter(ticket__isnull=False).exists())
