from datetime import timedelta
from io import StringIO

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents import sla as sla_buckets
from apps.incidents.models import Ticket, TicketSubtask, TriageRecord
from apps.wazuh_ingest.models import WazuhAlert


class ProductionDemoSeedTest(TestCase):
    def seed(self):
        output = StringIO()
        call_command(
            'seed_production_demo',
            '--reset',
            '--password',
            'TestDemo123!',
            stdout=output,
        )
        return output.getvalue()

    def test_seed_builds_three_week_workload_and_showcase(self):
        output = self.seed()
        demo_tickets = Ticket.objects.filter(reference_id__startswith='DEMO-3W-')

        self.assertEqual(demo_tickets.count(), 69)
        self.assertEqual(
            demo_tickets.exclude(status__in=Ticket.TERMINAL_STATUSES).count(),
            24,
        )
        self.assertEqual(
            demo_tickets.filter(status__in=Ticket.TERMINAL_STATUSES).count(),
            45,
        )
        self.assertEqual(WazuhAlert.objects.filter(opensearch_id__startswith='demo-3w-alert-').count(), 36)
        self.assertEqual(TriageRecord.objects.filter(source_reference__startswith='DEMO-3W-').count(), 18)

        self.assertEqual(
            User.objects.filter(profile__role=UserProfile.ROLE_SOC_STAFF, profile__tier=UserProfile.TIER_T1).count(),
            4,
        )
        self.assertEqual(
            User.objects.filter(profile__role=UserProfile.ROLE_SOC_STAFF, profile__tier=UserProfile.TIER_T2).count(),
            3,
        )

        showcase = demo_tickets.get(reference_id='DEMO-3W-EMERGENCY-001')
        self.assertTrue(showcase.is_emergency)
        self.assertEqual(showcase.status, Ticket.STATUS_APPROVED)
        self.assertEqual(showcase.classification, Ticket.CLASSIFICATION_INCIDENT)
        self.assertIsNotNone(showcase.escalated_to_t2_at)
        self.assertIsNotNone(showcase.verified_by)
        self.assertIsNotNone(showcase.approved_by)
        self.assertGreaterEqual(len(showcase.issue_description), 500)
        self.assertGreaterEqual(len(showcase.containment_report), 500)
        self.assertEqual(showcase.subtasks.count(), 5)
        self.assertTrue(all(
            status == TicketSubtask.STATUS_DONE
            for status in showcase.subtasks.values_list('status', flat=True)
        ))
        self.assertEqual(
            list(showcase.logs.order_by('created_at').values_list('status_at_time', flat=True)),
            [
                Ticket.STATUS_NEW,
                Ticket.STATUS_ESCALATED_T2,
                Ticket.STATUS_ESCALATED_T2,
                Ticket.STATUS_T1_REVIEW,
                Ticket.STATUS_AWAITING_CONTAINMENT,
                Ticket.STATUS_CONTAINMENT_REPORTED,
                Ticket.STATUS_AWAITING_CONTAINMENT,
                Ticket.STATUS_CONTAINMENT_REPORTED,
                Ticket.STATUS_PENDING_MANAGER,
                Ticket.STATUS_APPROVED,
            ],
        )
        self.assertIn(f'/incidents/ticket/{showcase.pk}/', output)
        self.assertEqual(reverse('ticket_detail', args=[showcase.pk]), f'/incidents/ticket/{showcase.pk}/')

        thai_showcase = demo_tickets.get(reference_id='DEMO-3W-THAI-EMERGENCY-001')
        self.assertTrue(thai_showcase.is_emergency)
        self.assertEqual(thai_showcase.status, Ticket.STATUS_APPROVED)
        self.assertEqual(
            timezone.localtime(thai_showcase.incident_datetime).date(),
            timezone.localdate() - timedelta(days=1),
        )
        self.assertIn('ระบบบริหารคลังสินค้า', thai_showcase.device_name)
        self.assertIn('ศูนย์เฝ้าระวัง', thai_showcase.issue_description)
        self.assertIn('มาตรการควบคุม', thai_showcase.containment_report)
        self.assertTrue(thai_showcase.logs.filter(note__contains='ผู้จัดการ SOC').exists())
        self.assertIn(f'/incidents/ticket/{thai_showcase.pk}/', output)

    def test_reset_replaces_only_one_copy_of_demo_dataset(self):
        self.seed()
        self.seed()

        self.assertEqual(Ticket.objects.filter(reference_id__startswith='DEMO-3W-').count(), 69)
        self.assertEqual(User.objects.filter(username__startswith='demo.').count(), 16)
        self.assertEqual(WazuhAlert.objects.filter(opensearch_id__startswith='demo-3w-alert-').count(), 36)


class SlaDemoBucketSeedTest(TestCase):
    def _make_ticket(self, status=Ticket.STATUS_NEW, reference_id='DEMO-SLA-'):
        return Ticket.objects.create(
            device_name='demo-host',
            ip_address='10.0.0.10',
            issue_description='Demo SLA bucket ticket',
            status=status,
            reference_id=reference_id,
            sla_deadline=timezone.now() + timedelta(days=2),
        )

    def _call(self, *args):
        output = StringIO()
        call_command('seed_sla_demo_buckets', *args, stdout=output)
        return output.getvalue()

    def test_dry_run_prints_plan_without_changing_deadlines(self):
        tickets = [self._make_ticket() for _ in range(4)]
        original_deadlines = {
            ticket.pk: ticket.sla_deadline for ticket in tickets
        }

        output = self._call('--due-1h', '1', '--due-4h', '1', '--on-track', '1')

        self.assertIn('DRY RUN', output)
        self.assertIn('No database changes written', output)
        for ticket in tickets:
            ticket.refresh_from_db()
            self.assertEqual(ticket.sla_deadline, original_deadlines[ticket.pk])

    def test_apply_spreads_active_tickets_across_shared_sla_buckets(self):
        for _ in range(8):
            self._make_ticket()
        terminal = self._make_ticket(status=Ticket.STATUS_APPROVED)
        original_terminal_deadline = terminal.sla_deadline

        output = self._call(
            '--apply',
            '--due-1h', '2',
            '--due-4h', '2',
            '--on-track', '2',
        )

        self.assertIn('APPLY', output)
        self.assertIn('SLA demo bucket spread applied', output)
        now = timezone.now()
        active = Ticket.objects.exclude(status__in=Ticket.TERMINAL_STATUSES)
        self.assertEqual(
            active.filter(sla_buckets.bucket_filter(sla_buckets.DUE_1H, now)).count(),
            2,
        )
        self.assertEqual(
            active.filter(sla_buckets.bucket_filter(sla_buckets.DUE_4H, now)).count(),
            2,
        )
        self.assertEqual(
            active.filter(sla_buckets.bucket_filter(sla_buckets.ON_TRACK, now)).count(),
            2,
        )
        self.assertEqual(
            active.filter(sla_buckets.bucket_filter(sla_buckets.OVERDUE, now)).count(),
            2,
        )
        terminal.refresh_from_db()
        self.assertEqual(terminal.sla_deadline, original_terminal_deadline)

    def test_reference_prefix_limits_the_updated_active_tickets(self):
        selected = [self._make_ticket(reference_id='DEMO-SLA-A') for _ in range(3)]
        untouched = self._make_ticket(reference_id='OTHER-SLA-A')
        untouched_deadline = untouched.sla_deadline

        self._call(
            '--apply',
            '--reference-prefix', 'DEMO-SLA-',
            '--due-1h', '1',
            '--due-4h', '1',
            '--on-track', '1',
        )

        now = timezone.now()
        selected_qs = Ticket.objects.filter(pk__in=[ticket.pk for ticket in selected])
        self.assertEqual(
            selected_qs.filter(sla_buckets.bucket_filter(sla_buckets.DUE_1H, now)).count(),
            1,
        )
        self.assertEqual(
            selected_qs.filter(sla_buckets.bucket_filter(sla_buckets.DUE_4H, now)).count(),
            1,
        )
        self.assertEqual(
            selected_qs.filter(sla_buckets.bucket_filter(sla_buckets.ON_TRACK, now)).count(),
            1,
        )
        untouched.refresh_from_db()
        self.assertEqual(untouched.sla_deadline, untouched_deadline)

    def test_negative_counts_are_rejected(self):
        with self.assertRaises(CommandError):
            self._call('--due-1h', '-1')
