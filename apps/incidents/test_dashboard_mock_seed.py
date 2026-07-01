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
from apps.wazuh_ingest.models import WazuhAlert


class DashboardMockupSeedTest(TestCase):
    keep_users = ['superadmin', 'admin1', 'admin2', 'analyst1', 'analyst2', 'manager1']
    mock_users = ['surapong', 'kamjad', 'pongpanit', 'supatach', 'poy', 'natt', 'santi']

    def _call(self, *args):
        output = StringIO()
        call_command('seed_dashboard_mockup', *args, stdout=output)
        return output.getvalue()

    def _seed(self):
        for username in self.keep_users:
            User.objects.create_user(username=username, password='keep')
        User.objects.create_user(username='old_demo_user', password='delete-me')
        return self._call('--reset', '--apply', '--password', 'MockPass123!')

    def test_dry_run_does_not_mutate_database(self):
        User.objects.create_user(username='old_demo_user', password='delete-me')
        output = self._call()

        self.assertIn('DRY RUN', output)
        self.assertIn('No database changes written', output)
        self.assertEqual(Ticket.objects.count(), 0)
        self.assertTrue(User.objects.filter(username='old_demo_user').exists())

    def test_apply_requires_reset(self):
        with self.assertRaises(CommandError):
            self._call('--apply')

    def test_reset_keeps_default_users_and_creates_requested_roles(self):
        output = self._seed()

        self.assertIn('Dashboard mockup dataset is ready', output)
        self.assertFalse(User.objects.filter(username='old_demo_user').exists())
        for username in self.keep_users + self.mock_users:
            self.assertTrue(User.objects.filter(username=username).exists(), username)

        self.assertEqual(
            User.objects.get(username='surapong').profile.role,
            UserProfile.ROLE_SOC_MANAGER,
        )
        self.assertEqual(User.objects.get(username='kamjad').profile.tier, UserProfile.TIER_T2)
        self.assertEqual(User.objects.get(username='pongpanit').profile.tier, UserProfile.TIER_T2)
        for username in ['supatach', 'poy', 'natt']:
            self.assertEqual(User.objects.get(username=username).profile.tier, UserProfile.TIER_T1)
        self.assertEqual(
            User.objects.get(username='santi').profile.role,
            UserProfile.ROLE_SYSTEM_ADMIN,
        )

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
