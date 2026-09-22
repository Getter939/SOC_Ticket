from unittest.mock import patch

from django.contrib.auth.models import User
from apps.accounts.testing import MFATestCase as TestCase

from apps.accounts.models import UserProfile

from django.core.exceptions import ValidationError

from .cancellation import can_cancel_directly
from .models import Ticket
from .ticket_workflow import (
    claim_tier2_ticket,
    complete_t2_review,
    conclude_monitoring,
    manager_forward,
    reassess_emergency,
    reclassify_as_event,
    return_for_completion,
    start_monitoring,
    step_back,
    submit_containment,
    submit_preparation,
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

    def __init__(self, ticket, **cleaned):
        self.ticket = ticket
        self.cleaned_data = cleaned

    def save(self, commit=True):
        self.ticket.device_name = 'workflow-host-corrected'
        if commit:
            self.ticket.save()
        return self.ticket

    def save_m2m(self):
        pass


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

    @patch('apps.incidents.ticket_workflow.notify_manager_triage_pending')
    def test_t2_incident_review_records_lane_history_and_routes_to_manager(self, notify_manager):
        ticket = _ticket(
            created_by=self.t1,
            status=Ticket.STATUS_ESCALATED_T2,
            device_name='workflow-host-original',
        )

        result = complete_t2_review(
            ticket=ticket,
            actor=self.t2,
            review_form=_ReviewForm(
                ticket, t1_route=Ticket.T1_ROUTE_ADMIN, assigned_admin=self.admin,
            ),
            next_status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            decision_note='Confirmed Incident; admin lane.',
            fallback_label='Mark as Incident -> SOC Manager review',
        )

        ticket.refresh_from_db()
        self.assertEqual(result.target_status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(ticket.t1_route, Ticket.T1_ROUTE_ADMIN)
        self.assertEqual(ticket.assigned_admin, self.admin)
        self.assertEqual(ticket.device_name, 'workflow-host-corrected')
        self.assertEqual(
            ticket.field_changes.get(field_name='device_name').source,
            't2_review',
        )
        # The lane is part of the audited content change.
        self.assertTrue(ticket.field_changes.filter(field_name='t1_route').exists())
        notify_manager.assert_called_once_with(ticket)

    @patch('apps.incidents.ticket_workflow.notify_manager_triage_pending')
    def test_t2_incident_review_supports_the_owner_lane(self, notify_manager):
        ticket = _ticket(created_by=self.t1, status=Ticket.STATUS_ESCALATED_T2)

        complete_t2_review(
            ticket=ticket,
            actor=self.t2,
            review_form=_ReviewForm(ticket, t1_route=Ticket.T1_ROUTE_OWNER),
            next_status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            decision_note='Owner can remediate this case.',
            fallback_label='x',
        )

        ticket.refresh_from_db()
        self.assertEqual(ticket.t1_route, Ticket.T1_ROUTE_OWNER)
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)

    def test_t2_incident_review_without_a_lane_is_refused(self):
        ticket = _ticket(created_by=self.t1, status=Ticket.STATUS_ESCALATED_T2)

        with self.assertRaises(ValidationError):
            complete_t2_review(
                ticket=ticket,
                actor=self.t2,
                review_form=_ReviewForm(ticket),
                next_status=Ticket.STATUS_PENDING_MGR_TRIAGE,
                decision_note='No lane chosen.',
                fallback_label='x',
            )
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_ESCALATED_T2)

    def test_admin_lane_without_an_admin_is_refused_by_the_model(self):
        ticket = _ticket(
            created_by=self.t1, status=Ticket.STATUS_ESCALATED_T2,
            t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.assertFalse(ticket.can_transition_to(Ticket.STATUS_PENDING_MGR_TRIAGE))
        with self.assertRaises(ValidationError):
            ticket.transition_to(Ticket.STATUS_PENDING_MGR_TRIAGE, self.t2, 'no admin')

    @patch('apps.incidents.ticket_workflow.notify_manager_triage_pending')
    def test_manager_return_goes_to_tier2_when_tier2_routed_it(self, notify_manager):
        ticket = _ticket(created_by=self.t1, status=Ticket.STATUS_ESCALATED_T2)
        complete_t2_review(
            ticket=ticket, actor=self.t2,
            review_form=_ReviewForm(ticket, t1_route=Ticket.T1_ROUTE_OWNER),
            next_status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            decision_note='Incident.', fallback_label='x',
        )

        result = return_for_completion(
            ticket=ticket, actor=self.manager, reason='Scope unclear.',
        )

        ticket.refresh_from_db()
        self.assertEqual(result.target_status, Ticket.STATUS_ESCALATED_T2)
        self.assertEqual(ticket.status, Ticket.STATUS_ESCALATED_T2)
        # Back on Tier 2's desk as an Incident: a later Event call is a
        # downgrade and still needs the SOC Manager's verification.
        self.assertEqual(ticket.classification_at_escalation, Ticket.CLASSIFICATION_INCIDENT)
        ticket.classification = Ticket.CLASSIFICATION_EVENT
        self.assertTrue(ticket.can_transition_to(Ticket.STATUS_PENDING_MGR_EVENT_REVIEW))
        self.assertFalse(ticket.can_transition_to(Ticket.STATUS_CLOSED_EVENT))

    @patch('apps.incidents.ticket_workflow.notify_manager_triage_pending')
    @patch('apps.incidents.ticket_workflow.notify_system_owner_created')
    def test_manager_return_reopens_preparation_when_tier1_routed_it(self, notify_owner, _mgr):
        ticket = _ticket(
            created_by=self.t1, system_owner=self.owner,
            t1_route=Ticket.T1_ROUTE_ADMIN, assigned_admin=self.admin,
        )
        submit_preparation(ticket=ticket, actor=self.t1)
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertIsNotNone(ticket.first_submitted_at)
        self.assertEqual(notify_owner.call_count, 1)

        result = return_for_completion(
            ticket=ticket, actor=self.manager, reason='Attach the firewall log.',
        )
        ticket.refresh_from_db()
        self.assertEqual(result.target_status, Ticket.STATUS_NEW)
        self.assertEqual(ticket.status, Ticket.STATUS_NEW)
        # Already reviewed, so the creator can no longer cancel it outright.
        self.assertFalse(can_cancel_directly(ticket, self.t1))

        # Resubmitting routes it again without re-sending the owner email.
        submit_preparation(ticket=ticket, actor=self.t1)
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(notify_owner.call_count, 1)

    def test_manager_cannot_return_to_the_wrong_party(self):
        direct = _ticket(
            created_by=self.t1, status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            t1_route=Ticket.T1_ROUTE_OWNER,
        )
        self.assertFalse(direct.can_transition_to(Ticket.STATUS_ESCALATED_T2))
        with self.assertRaises(ValidationError):
            direct.transition_to(Ticket.STATUS_ESCALATED_T2, self.manager, 'wrong party')

    def test_tier1_cannot_route_an_escalated_incident(self):
        ticket = _ticket(
            created_by=self.t1, status=Ticket.STATUS_ESCALATED_T2,
            t1_route=Ticket.T1_ROUTE_OWNER,
        )
        with self.assertRaises(ValidationError):
            ticket.transition_to(Ticket.STATUS_PENDING_MGR_TRIAGE, self.t1, 'not mine')

    @patch('apps.incidents.ticket_workflow.notify_manager_triage_pending')
    def test_monitoring_incident_carries_the_lane_and_can_be_forwarded(self, _mgr):
        ticket = _ticket(created_by=self.t1, status=Ticket.STATUS_ESCALATED_T2)
        start_monitoring(ticket=ticket, actor=self.t2, note='Watch it.')

        with self.assertRaises(ValidationError):
            conclude_monitoring(
                ticket=ticket, actor=self.t2, outcome='incident', note='No lane.',
            )
        ticket.refresh_from_db()
        conclude_monitoring(
            ticket=ticket, actor=self.t2, outcome='incident', note='Beacon seen.',
            route=Ticket.T1_ROUTE_OWNER,
        )
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(ticket.t1_route, Ticket.T1_ROUTE_OWNER)
        self.assertTrue(ticket.can_transition_to(Ticket.STATUS_AWAITING_OWNER))

    def test_purge_migration_hands_t1_review_tickets_back_to_tier2(self):
        import importlib

        from django.apps import apps as global_apps

        from .models import TicketLog

        migration = importlib.import_module('apps.incidents.migrations.0083_purge_t1_review')
        stuck = _ticket(created_by=self.t1, status='T1_REVIEW', t2_claimed_by=self.t2)
        old_log = TicketLog.objects.create(
            ticket=stuck, note='returned', status_at_time='T1_REVIEW', author=self.t2,
        )
        submitted = _ticket(created_by=self.t1, status=Ticket.STATUS_APPROVED)
        untouched = _ticket(created_by=self.t1)

        migration.forwards(global_apps, None)

        stuck.refresh_from_db()
        self.assertEqual(stuck.status, Ticket.STATUS_ESCALATED_T2)
        self.assertEqual(stuck.classification_at_escalation, Ticket.CLASSIFICATION_INCIDENT)
        self.assertIsNone(stuck.t2_claimed_by)
        self.assertIsNotNone(stuck.escalated_to_t2_at)
        self.assertTrue(stuck.logs.filter(status_at_time=Ticket.STATUS_ESCALATED_T2).exists())
        # The old audit row is kept as-is and still renders a readable label.
        old_log.refresh_from_db()
        self.assertEqual(old_log.status_at_time, 'T1_REVIEW')
        self.assertEqual(old_log.status_display, Ticket.LEGACY_STATUS_LABELS['T1_REVIEW'])
        # first_submitted_at backfilled for submitted tickets only.
        submitted.refresh_from_db()
        untouched.refresh_from_db()
        self.assertIsNotNone(submitted.first_submitted_at)
        self.assertIsNone(untouched.first_submitted_at)

    def test_t2_content_edit_marks_the_ticket_for_its_creator(self):
        from . import history

        ticket = _ticket(created_by=self.t1, status=Ticket.STATUS_ESCALATED_T2)
        self.assertFalse(ticket.has_unseen_t2_changes)

        # A status move alone never marks it.
        ticket.transition_to(Ticket.STATUS_ESCALATED_T2, self.t2, 'note only')
        ticket.refresh_from_db()
        self.assertFalse(ticket.has_unseen_t2_changes)

        # The creator's own edit does not mark it either.
        before = history.snapshot(ticket)
        ticket.device_name = 'renamed-by-creator'
        ticket.save()
        history.record_changes(ticket, before, self.t1, source='edit')
        ticket.refresh_from_db()
        self.assertFalse(ticket.has_unseen_t2_changes)

        # A Tier 2 content edit does.
        before = history.snapshot(ticket)
        ticket.device_name = 'renamed-by-t2'
        ticket.save()
        history.record_changes(ticket, before, self.t2, source='edit')
        ticket.refresh_from_db()
        self.assertTrue(ticket.has_unseen_t2_changes)

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
