from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase

from .forms import TicketForm
from .models import Ticket, TicketAttachment, TicketLog
from .tests import _make_t1, _make_t2, _make_ticket, _make_user, _ticket_post_data


class TicketPreparationWorkflowTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_t1('prep_t1')
        cls.t2 = _make_t2('prep_t2')
        cls.manager = _make_user('prep_manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('prep_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def test_save_preparation_issues_id_without_routing(self):
        self.client.force_login(self.t2)
        data = _ticket_post_data(
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ASSIGN_ADMIN,
            assigned_admin=self.admin.pk,
        )
        data['submission_intent'] = 'save_preparation'

        response = self.client.post(reverse('create_ticket'), data)

        ticket = Ticket.objects.latest('pk')
        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        self.assertTrue(ticket.ticket_id)
        self.assertEqual(ticket.status, Ticket.STATUS_NEW)
        self.assertEqual(ticket.t1_route, Ticket.T1_ROUTE_ADMIN)
        self.assertEqual(ticket.created_by, self.t2)

    def test_creator_submits_saved_preparation_to_selected_lane(self):
        ticket = _make_ticket(
            created_by=self.t2,
            assigned_to=self.t2,
            assigned_admin=self.admin,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_NEW,
            t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.t2)

        response = self.client.post(
            reverse('ticket_detail', args=[ticket.pk]),
            {'action': 'submit_preparation'},
        )

        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertTrue(TicketLog.objects.filter(
            ticket=ticket, author=self.t2, note__contains='จัดเตรียมแล้ว',
        ).exists())

    def test_tier2_creator_can_append_evidence_after_submission(self):
        ticket = _make_ticket(
            created_by=self.t2,
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.t2)

        response = self.client.post(
            reverse('upload_attachment', args=[ticket.pk]),
            {'file': SimpleUploadedFile('follow-up.log', b'follow-up evidence')},
        )

        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        attachment = TicketAttachment.objects.get(ticket=ticket)
        self.assertEqual(attachment.uploaded_by, self.t2)

    def test_manager_returns_for_completion_with_required_reason(self):
        ticket = _make_ticket(
            created_by=self.t2,
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.manager)

        response = self.client.post(
            reverse('ticket_detail', args=[ticket.pk]),
            {'action': 'return_for_completion', 'return_reason': 'Attach the firewall export.'},
        )

        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        ticket.refresh_from_db()
        # Routed straight from preparation (never escalated) → back to it.
        self.assertEqual(ticket.status, Ticket.STATUS_NEW)
        log = TicketLog.objects.filter(ticket=ticket).latest('pk')
        self.assertEqual(log.author, self.manager)
        self.assertIn('Attach the firewall export.', log.note)

    def test_manager_cannot_return_without_reason(self):
        ticket = _make_ticket(
            created_by=self.t1,
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.manager)

        self.client.post(
            reverse('ticket_detail', args=[ticket.pk]),
            {'action': 'return_for_completion', 'return_reason': '   '},
        )

        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)

    def test_tier2_creator_can_resubmit_manager_return(self):
        ticket = _make_ticket(
            created_by=self.t2,
            status=Ticket.STATUS_NEW,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=Ticket.T1_ROUTE_ADMIN,
            assigned_admin=self.admin,
            first_submitted_at=timezone.now(),
        )
        self.client.force_login(self.t2)

        response = self.client.post(
            reverse('ticket_detail', args=[ticket.pk]),
            {'action': 'submit_preparation'},
        )

        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)

