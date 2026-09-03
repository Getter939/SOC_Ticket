from unittest.mock import patch

from django.contrib.auth.models import User
from apps.accounts.testing import MFATestCase as TestCase

from apps.accounts.models import UserProfile

from .models import Ticket
from .ticket_workflow import (
    assign_admin_or_owner_route,
    claim_tier2_ticket,
    complete_t2_review,
    manager_forward,
    reassess_emergency,
    reclassify_as_event,
    step_back,
    submit_containment,
    transition_ticket,
)


def _user(username, role, *, tier='', email=''):
    user = User.objects.create_user(username=username, password='testpass123', email=email)
    UserProfile.objects.create(
        user=user,
        role=role,
        tier=tier,
        department='Test',
        phone='000',
    )
    return user


def _ticket(**overrides):
    values = {
        'device_name': 'workflow-host',
        'ip_address': '192.0.2.99',
        'issue_description': 'Workflow service contract',
        'classification': Ticket.CLASSIFICATION_INCIDENT,
    }
    values.update(overrides)
    return Ticket.objects.create(**values)


class _ReviewForm:
    """A minimal form double: form validation remains the view's responsibility."""

    def __init__(self, ticket):
        self.ticket = ticket

    def save(self):
        self.ticket.device_name = 'workflow-host-corrected'
        self.ticket.save()
        return self.ticket


class TicketWorkflowServiceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user(
            'workflow-t1',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.t2 = _user(
            'workflow-t2',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T2,
        )
        cls.manager = _user('workflow-manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _user(
            'workflow-admin',
            UserProfile.ROLE_SYSTEM_ADMIN,
            email='admin@example.com',
        )
        cls.owner = _user(
            'workflow-owner',
            UserProfile.ROLE_SYSTEM_OWNER,
            email='owner@example.com',
        )

    def test_reassess_and_step_back_delegate_to_model_workflow(self):
        ticket = _ticket(
            created_by=self.t1,
            assigned_admin=self.admin,
            status=Ticket.STATUS_AWAITING_CONTAINMENT,
        )

        reassess_emergency(
            ticket=ticket,
            actor=self.manager,
            value=True,
            reason='New intelligence raises the risk.',
        )
        result = step_back(
            ticket=ticket,
            actor=self.manager,
            reason='Return the case to manager review.',
        )

        ticket.refresh_from_db()
        self.assertTrue(ticket.is_emergency)
        self.assertEqual(result.target_status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)

    def test_t2_review_saves_field_history_and_transitions(self):
        ticket = _ticket(
            created_by=self.t1,
            status=Ticket.STATUS_ESCALATED_T2,
            device_name='workflow-host-original',
        )

        result = complete_t2_review(
            ticket=ticket,
            actor=self.t2,
            review_form=_ReviewForm(ticket),
            next_status=Ticket.STATUS_T1_REVIEW,
            decision_note='Return the corrected ticket to Tier 1.',
            fallback_label='Return to Tier 1',
        )

        ticket.refresh_from_db()
        self.assertEqual(result.target_status, Ticket.STATUS_T1_REVIEW)
        self.assertEqual(ticket.status, Ticket.STATUS_T1_REVIEW)
        self.assertEqual(ticket.device_name, 'workflow-host-corrected')
        self.assertEqual(
            ticket.field_changes.get(field_name='device_name').source,
            't2_review',
        )

    @patch('apps.incidents.ticket_workflow.notify_manager_triage_pending')
    def test_assignment_service_supports_the_owner_lane(self, notify_manager):
        ticket = _ticket(
            created_by=self.t1,
            status=Ticket.STATUS_T1_REVIEW,
        )

        result = assign_admin_or_owner_route(
            ticket=ticket,
            actor=self.t1,
            route=Ticket.T1_ROUTE_OWNER,
            note='Owner can remediate this case.',
        )

        ticket.refresh_from_db()
        self.assertEqual(ticket.t1_route, Ticket.T1_ROUTE_OWNER)
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(result.target_status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        notify_manager.assert_called_once_with(ticket)

    @patch('apps.incidents.ticket_workflow.notify_containment_alert', return_value=False)
    def test_manager_forward_returns_notification_warning(self, notify_containment):
        ticket = _ticket(
            created_by=self.t1,
            assigned_admin=self.admin,
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            t1_route=Ticket.T1_ROUTE_ADMIN,
        )

        result = manager_forward(
            ticket=ticket,
            actor=self.manager,
            want_emergency=False,
            target_status=Ticket.STATUS_AWAITING_CONTAINMENT,
            note='Forward to the assigned admin.',
        )

        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertFalse(ticket.is_emergency)
        self.assertEqual(len(result.warnings), 1)
        notify_containment.assert_called_once_with(ticket, reason=None)

    @patch('apps.incidents.ticket_workflow.notify_system_owner_closed', return_value=False)
    def test_reclassification_closes_as_event_and_returns_owner_warning(self, notify_owner):
        ticket = _ticket(
            created_by=self.t1,
            system_owner=self.owner,
            status=Ticket.STATUS_PENDING_T2_REVIEW,
        )

        result = reclassify_as_event(
            ticket=ticket,
            actor=self.t2,
            note='Verified as benign activity.',
        )

        ticket.refresh_from_db()
        self.assertEqual(ticket.classification, Ticket.CLASSIFICATION_EVENT)
        self.assertEqual(ticket.status, Ticket.STATUS_CLOSED_EVENT)
        self.assertEqual(len(result.warnings), 1)
        notify_owner.assert_called_once()

    @patch('apps.incidents.ticket_workflow.notify_containment_submitted', return_value=False)
    def test_containment_submission_records_checklist_and_notification_warning(self, notify_submitted):
        ticket = _ticket(
            created_by=self.t1,
            assigned_admin=self.admin,
            status=Ticket.STATUS_AWAITING_CONTAINMENT,
            action_required='- Block the command-and-control address\n- Preserve endpoint evidence',
        )

        result = submit_containment(
            ticket=ticket,
            actor=self.admin,
            report='Host isolated and traffic blocked.',
            remediation='Endpoint will be rebuilt.',
            note='Containment complete.',
            checked_indexes={'0'},
        )

        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_CONTAINMENT_REPORTED)
        self.assertTrue(ticket.containment_checklist[0]['done'])
        self.assertFalse(ticket.containment_checklist[1]['done'])
        self.assertTrue(ticket.field_changes.filter(source='containment').exists())
        self.assertEqual(len(result.warnings), 1)
        notify_submitted.assert_called_once_with(ticket)

    @patch('apps.incidents.ticket_workflow.notify_containment_alert', return_value=True)
    def test_standard_transition_notifies_admin_on_rework(self, notify_containment):
        ticket = _ticket(
            created_by=self.t1,
            assigned_admin=self.admin,
            status=Ticket.STATUS_CONTAINMENT_REPORTED,
        )

        result = transition_ticket(
            ticket=ticket,
            actor=self.t2,
            next_status=Ticket.STATUS_AWAITING_CONTAINMENT,
            note='Please include the firewall-rule evidence.',
        )

        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertEqual(result.warnings, ())
        notify_containment.assert_called_once_with(
            ticket,
            reason='Please include the firewall-rule evidence.',
        )

    def test_tier2_claim_is_atomic_and_idempotent(self):
        ticket = _ticket(created_by=self.t1, status=Ticket.STATUS_ESCALATED_T2)

        first = claim_tier2_ticket(ticket=ticket, actor=self.t2)
        second = claim_tier2_ticket(ticket=ticket, actor=self.t2)

        ticket.refresh_from_db()
        self.assertTrue(first.claimed)
        self.assertFalse(second.claimed)
        self.assertEqual(ticket.t2_claimed_by, self.t2)
