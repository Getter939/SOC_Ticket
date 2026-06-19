from io import StringIO

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from apps.accounts.models import UserProfile
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

        self.assertEqual(demo_tickets.count(), 68)
        self.assertEqual(
            demo_tickets.exclude(status__in=Ticket.TERMINAL_STATUSES).count(),
            24,
        )
        self.assertEqual(
            demo_tickets.filter(status__in=Ticket.TERMINAL_STATUSES).count(),
            44,
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

    def test_reset_replaces_only_one_copy_of_demo_dataset(self):
        self.seed()
        self.seed()

        self.assertEqual(Ticket.objects.filter(reference_id__startswith='DEMO-3W-').count(), 68)
        self.assertEqual(User.objects.filter(username__startswith='demo.').count(), 16)
        self.assertEqual(WazuhAlert.objects.filter(opensearch_id__startswith='demo-3w-alert-').count(), 36)
