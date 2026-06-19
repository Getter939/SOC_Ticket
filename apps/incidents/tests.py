"""
Tests for the redesigned SOC ticketing workflow.

Test classes
────────────
1.  TicketVisibilityQuerysetTest  — Ticket.objects.visible_to() queryset scoping
2.  TicketVisibilityViewTest      — HTTP-level visibility enforcement
3.  WorkflowTransitionTest        — Every legal state-machine edge, every illegal edge
4.  WorkflowPermissionTest        — Per-transition role/tier permissions (positive + negative)
5.  T1ClassificationCreateTest    — Tier 1 Event/Incident disposition at creation
6.  Tier2EscalationTest           — Tier 2 return-only constraint (never assign / never create)
7.  ManagerRoutingTest            — requires_manager_verification (Critical floor + emergency)
8.  EmergencyFlagTest             — emergency-flag permissions + audit
9.  AdminFieldAccessTest          — System Admin write access to containment/remediation fields
10. SignOffFieldsTest             — verified_by/at and approved_by/at are write-once
11. NotificationEmailTest         — Email notifications on AWAITING_CONTAINMENT transitions
12. WazuhTriageActionTest         — 2-action Tier 1 triage + required release reason
13. TriageWorkflowIntegrityTest   — manual-triage + wazuh-alert ticket creation
14. SuperuserAccessTest           — superuser bypass across the redesigned flow
15. AttachmentDownloadSecurityTest / AttachmentUploadLimitTest

Run with:  py manage.py test apps.incidents --settings=config.settings_local
"""

import shutil
import tempfile
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.forms import AttachmentForm, TicketForm, TriageForm
from apps.incidents.models import Ticket, TicketAttachment, TicketLog, TriageRecord
from apps.incidents.notifications import notify_containment_required
from apps.wazuh_ingest.models import WazuhAlert


# ──────────────────────────────────────────────────────────────────────────── #
# Shared helpers                                                               #
# ──────────────────────────────────────────────────────────────────────────── #

def _make_user(username, role, department='Test', phone='000', **kwargs):
    """Create a User + UserProfile in one call. Pass tier='T1'/'T2' via kwargs."""
    user = User.objects.create_user(username=username, password='testpass123')
    UserProfile.objects.create(
        user=user, role=role, department=department, phone=phone, **kwargs
    )
    return user


def _make_t1(username='t1', **kwargs):
    return _make_user(username, UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1, **kwargs)


def _make_t2(username='t2', **kwargs):
    return _make_user(username, UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2, **kwargs)


def _make_ticket(**kwargs):
    """Create a Ticket with sensible defaults (bypasses the state machine)."""
    defaults = dict(
        device_name='10.0.0.1',
        ip_address='192.168.0.1',
        issue_description='Test ticket',
    )
    defaults.update(kwargs)
    return Ticket.objects.create(**defaults)


def _ticket_post_data(**overrides):
    """A valid create_ticket POST payload."""
    data = {
        'classification': Ticket.CLASSIFICATION_INCIDENT,
        't1_route': TicketForm.ROUTE_ESCALATE_T2,
        'severity': 'High',
        'category': 'Cyber Event',
        'issue_type': 'SIEM',
        'detailed_issue': 'Investigating',
        'detailed_issue2': 'Investigating Other',
        'device_name': 'TEST-ENDPOINT-01',
        'issue_description': 'Confirmed suspicious activity.',
        'ip_address': '192.0.2.10',
    }
    data.update(overrides)
    return data


def _advance_to(ticket, target_status, t1, admin=None, mgr=None):
    """
    Drive a ticket from its current status to target_status along the
    Incident → assign-admin happy path. Chooses the manager step automatically
    based on requires_manager_verification (severity / emergency).
    """
    if ticket.created_by_id is None:
        ticket.created_by = t1
    if ticket.classification != Ticket.CLASSIFICATION_INCIDENT:
        ticket.classification = Ticket.CLASSIFICATION_INCIDENT
    ticket.save(update_fields=['created_by', 'classification'])

    path = [
        Ticket.STATUS_NEW,
        Ticket.STATUS_AWAITING_CONTAINMENT,
        Ticket.STATUS_CONTAINMENT_REPORTED,
    ]
    if ticket.requires_manager_verification:
        path += [Ticket.STATUS_PENDING_MANAGER, Ticket.STATUS_APPROVED]
    else:
        path += [Ticket.STATUS_APPROVED]

    i = path.index(ticket.status)
    j = path.index(target_status)
    for step in path[i + 1: j + 1]:
        if step == Ticket.STATUS_CONTAINMENT_REPORTED:
            ticket.containment_report = 'Contained.'
            ticket.transition_to(step, admin, 'containment note')
        elif step == Ticket.STATUS_PENDING_MANAGER:
            ticket.transition_to(step, t1, 'verified — route to manager')
        elif step == Ticket.STATUS_APPROVED:
            actor = mgr if ticket.requires_manager_verification else t1
            ticket.transition_to(step, actor, 'close')
        else:  # AWAITING_CONTAINMENT
            ticket.transition_to(step, t1, 'assign admin')


# ──────────────────────────────────────────────────────────────────────────── #
# 1. Visibility queryset tests                                                 #
# ──────────────────────────────────────────────────────────────────────────── #

class TicketVisibilityQuerysetTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff   = _make_t1('soc_staff')
        cls.soc_manager = _make_user('soc_manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin_a     = _make_user('admin_a',     UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b     = _make_user('admin_b',     UserProfile.ROLE_SYSTEM_ADMIN)
        cls.no_profile  = User.objects.create_user(username='noprofile', password='testpass123')

        cls.ticket_a = _make_ticket(assigned_admin=cls.admin_a)
        cls.ticket_b = _make_ticket(assigned_admin=cls.admin_b)
        cls.ticket_unassigned = _make_ticket()

    def test_soc_staff_sees_all_tickets(self):
        self.assertEqual(Ticket.objects.visible_to(self.soc_staff).count(), 3)

    def test_soc_manager_sees_all_tickets(self):
        self.assertEqual(Ticket.objects.visible_to(self.soc_manager).count(), 3)

    def test_system_admin_sees_only_own_ticket(self):
        qs = Ticket.objects.visible_to(self.admin_a)
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), self.ticket_a)

    def test_system_admin_cannot_see_other_admins_ticket(self):
        self.assertNotIn(self.ticket_b, Ticket.objects.visible_to(self.admin_a))

    def test_no_profile_sees_no_tickets(self):
        self.assertEqual(Ticket.objects.visible_to(self.no_profile).count(), 0)


# ──────────────────────────────────────────────────────────────────────────── #
# 2. Visibility view tests                                                     #
# ──────────────────────────────────────────────────────────────────────────── #

class TicketVisibilityViewTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_t1('v_soc_staff')
        cls.admin_a   = _make_user('v_admin_a', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b   = _make_user('v_admin_b', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.ticket_a = _make_ticket(assigned_admin=cls.admin_a)
        cls.ticket_b = _make_ticket(assigned_admin=cls.admin_b)

    def test_admin_a_can_view_own_ticket(self):
        self.client.login(username='v_admin_a', password='testpass123')
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_a.pk})
        self.assertEqual(self.client.get(url).status_code, 200)

    def test_admin_a_gets_404_on_admin_b_ticket(self):
        self.client.login(username='v_admin_a', password='testpass123')
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_b.pk})
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_unauthenticated_user_redirected(self):
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_a.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])


# ──────────────────────────────────────────────────────────────────────────── #
# 3. Workflow transition tests                                                  #
# ──────────────────────────────────────────────────────────────────────────── #

class WorkflowTransitionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('wf_t1')
        cls.t2    = _make_t2('wf_t2')
        cls.mgr   = _make_user('wf_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('wf_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _incident(self, severity='High'):
        return _make_ticket(
            assigned_admin=self.admin, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT, severity=severity,
        )

    # ── Happy path ──────────────────────────────────────────────────────── #

    def test_new_incident_to_awaiting_containment(self):
        t = self._incident()
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'assign')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_new_incident_to_escalated_t2_stamps_escalation(self):
        t = self._incident()
        t.transition_to(Ticket.STATUS_ESCALATED_T2, self.t1, 'escalate')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_ESCALATED_T2)
        self.assertIsNotNone(t.escalated_to_t2_at)
        self.assertTrue(t.was_escalated_to_t2)

    def test_new_event_to_closed_event(self):
        t = _make_ticket(created_by=self.t1, classification=Ticket.CLASSIFICATION_EVENT)
        t.transition_to(Ticket.STATUS_CLOSED_EVENT, self.t1, 'benign')
        self.assertEqual(t.status, Ticket.STATUS_CLOSED_EVENT)

    def test_escalated_incident_returns_to_t1_review(self):
        t = self._incident()
        t.transition_to(Ticket.STATUS_ESCALATED_T2, self.t1, 'escalate')
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'confirm incident')
        self.assertEqual(t.status, Ticket.STATUS_T1_REVIEW)

    def test_t1_review_to_awaiting_containment(self):
        t = self._incident()
        t.transition_to(Ticket.STATUS_ESCALATED_T2, self.t1, 'escalate')
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'confirm')
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'assign admin')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_full_happy_path_high_severity_no_manager(self):
        t = self._incident(severity='High')
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin)
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_full_happy_path_critical_via_manager(self):
        t = self._incident(severity='Critical')
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin, mgr=self.mgr)
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_containment_rejection_loop(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_CONTAINMENT_REPORTED, self.t1, self.admin)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'not contained')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    # ── Illegal transitions ─────────────────────────────────────────────── #

    def test_cannot_skip_states(self):
        t = self._incident()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.t1, 'skip')

    def test_approved_is_terminal(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'reopen')

    def test_closed_event_is_terminal(self):
        t = _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_EVENT,
            status=Ticket.STATUS_CLOSED_EVENT,
        )
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'reopen')

    def test_event_cannot_take_incident_path(self):
        """A ticket classified EVENT cannot be assigned to an admin."""
        t = _make_ticket(
            created_by=self.t1, assigned_admin=self.admin,
            classification=Ticket.CLASSIFICATION_EVENT,
        )
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'mismatch')

    def test_incident_cannot_be_closed_as_event(self):
        t = self._incident()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CLOSED_EVENT, self.t1, 'mismatch')

    def test_invalid_status_code_raises(self):
        t = self._incident()
        with self.assertRaises(ValidationError):
            t.transition_to('BOGUS', self.t1, 'bad')


# ──────────────────────────────────────────────────────────────────────────── #
# 4. Permission matrix tests                                                   #
# ──────────────────────────────────────────────────────────────────────────── #

class WorkflowPermissionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1       = _make_t1('pm_t1')
        cls.other_t1 = _make_t1('pm_t1_other')
        cls.t2       = _make_t2('pm_t2')
        cls.mgr      = _make_user('pm_mgr',     UserProfile.ROLE_SOC_MANAGER)
        cls.admin_a  = _make_user('pm_admin_a', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b  = _make_user('pm_admin_b', UserProfile.ROLE_SYSTEM_ADMIN)

    def _ticket_at(self, status, severity='High',
                   classification=Ticket.CLASSIFICATION_INCIDENT, **kwargs):
        opts = dict(
            status=status, severity=severity, classification=classification,
            assigned_admin=self.admin_a, created_by=self.t1,
        )
        opts.update(kwargs)
        return _make_ticket(**opts)

    # NEW → AWAITING_CONTAINMENT  requires TIER1_CREATOR ───────────────────

    def test_creator_t1_can_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_non_creator_t1_cannot_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.other_t1, 'denied')

    def test_t2_cannot_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t2, 'denied')

    def test_manager_cannot_dispatch(self):
        """Managers are not Tier 1 and never open/route a fresh ticket."""
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.mgr, 'denied')

    # ESCALATED_T2 → T1_REVIEW  requires TIER2 ─────────────────────────────

    def test_t2_can_return_to_t1(self):
        t = self._ticket_at(Ticket.STATUS_ESCALATED_T2)
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_T1_REVIEW)

    def test_t1_cannot_return_to_t1(self):
        t = self._ticket_at(Ticket.STATUS_ESCALATED_T2)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_T1_REVIEW, self.t1, 'denied')

    # AWAITING_CONTAINMENT → CONTAINMENT_REPORTED  requires ASSIGNED_ADMIN ─

    def test_assigned_admin_can_report(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=self.admin_a)
        t.containment_report = 'contained'
        t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin_a, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_CONTAINMENT_REPORTED)

    def test_other_admin_cannot_report(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=self.admin_a)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin_b, 'denied')

    def test_t1_cannot_report_containment(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.t1, 'denied')

    # CONTAINMENT_REPORTED close  requires TIER1_CREATOR ──────────────────

    def test_creator_t1_can_close_when_no_manager(self):
        t = self._ticket_at(Ticket.STATUS_CONTAINMENT_REPORTED, severity='High')
        t.transition_to(Ticket.STATUS_APPROVED, self.t1, 'close')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_non_creator_t1_cannot_close(self):
        t = self._ticket_at(Ticket.STATUS_CONTAINMENT_REPORTED, severity='High')
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.other_t1, 'denied')

    # PENDING_MANAGER → APPROVED  requires MANAGER ────────────────────────

    def test_manager_can_approve(self):
        t = self._ticket_at(Ticket.STATUS_PENDING_MANAGER, severity='Critical')
        t.transition_to(Ticket.STATUS_APPROVED, self.mgr, 'approved')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_t1_cannot_approve_pending_manager(self):
        t = self._ticket_at(Ticket.STATUS_PENDING_MANAGER, severity='Critical')
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t1, 'denied')


# ──────────────────────────────────────────────────────────────────────────── #
# 5. Tier 1 Event/Incident disposition at creation                             #
# ──────────────────────────────────────────────────────────────────────────── #

class T1ClassificationCreateTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('cc_t1')
        cls.t2    = _make_t2('cc_t2')
        cls.admin = _make_user('cc_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def test_event_creation_closes_ticket(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification=Ticket.CLASSIFICATION_EVENT, t1_route='',
        ))
        self.assertEqual(resp.status_code, 302)
        ticket = Ticket.objects.latest('id')
        self.assertEqual(ticket.classification, Ticket.CLASSIFICATION_EVENT)
        self.assertEqual(ticket.status, Ticket.STATUS_CLOSED_EVENT)

    def test_incident_assign_admin_routes_to_containment(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ASSIGN_ADMIN,
            assigned_admin=self.admin.pk,
        ))
        self.assertEqual(resp.status_code, 302)
        ticket = Ticket.objects.latest('id')
        self.assertEqual(ticket.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertEqual(ticket.assigned_admin, self.admin)

    def test_incident_escalate_routes_to_t2(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ESCALATE_T2,
        ))
        self.assertEqual(resp.status_code, 302)
        ticket = Ticket.objects.latest('id')
        self.assertEqual(ticket.status, Ticket.STATUS_ESCALATED_T2)
        self.assertIsNotNone(ticket.escalated_to_t2_at)

    def test_incident_assign_admin_without_admin_is_invalid(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ASSIGN_ADMIN,
        ))
        self.assertEqual(resp.status_code, 200)  # form re-rendered with errors
        self.assertFalse(Ticket.objects.exists())

    def test_missing_classification_is_invalid(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification='', t1_route='',
        ))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Ticket.objects.exists())

    def test_t2_cannot_open_create_ticket_page(self):
        self.client.login(username='cc_t2', password='testpass123')
        resp = self.client.get(reverse('create_ticket'))
        self.assertEqual(resp.status_code, 302)  # redirected — Tier 1 only

    def test_admin_cannot_open_create_ticket_page(self):
        self.client.login(username='cc_admin', password='testpass123')
        resp = self.client.get(reverse('create_ticket'))
        self.assertEqual(resp.status_code, 302)


# ──────────────────────────────────────────────────────────────────────────── #
# 6. Tier 2 return-only constraint                                             #
# ──────────────────────────────────────────────────────────────────────────── #

class Tier2EscalationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('t2t_t1')
        cls.t2    = _make_t2('t2t_t2')
        cls.admin = _make_user('t2t_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _escalated(self):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_ESCALATED_T2, assigned_admin=self.admin,
            escalated_to_t2_at=timezone.now(),
        )

    def test_t2_confirms_incident_returns_to_t1(self):
        t = self._escalated()
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'confirmed incident')
        self.assertEqual(t.status, Ticket.STATUS_T1_REVIEW)

    def test_t2_reclassifies_event_and_closes(self):
        t = self._escalated()
        t.classification = Ticket.CLASSIFICATION_EVENT  # T2 may revise classification
        t.transition_to(Ticket.STATUS_CLOSED_EVENT, self.t2, 'benign on review')
        self.assertEqual(t.status, Ticket.STATUS_CLOSED_EVENT)

    def test_t2_cannot_assign_to_admin(self):
        """No ESCALATED_T2 → AWAITING_CONTAINMENT edge exists at all."""
        t = self._escalated()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t2, 'forbidden')

    def test_t2_cannot_create_ticket(self):
        self.client.login(username='t2t_t2', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data())
        self.assertEqual(resp.status_code, 302)  # redirected away, Tier 1 only
        self.assertFalse(Ticket.objects.filter(device_name='TEST-ENDPOINT-01').exists())

    def test_t1_review_then_assign_admin(self):
        t = self._escalated()
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'confirm')
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'assign admin')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)


# ──────────────────────────────────────────────────────────────────────────── #
# 7. Manager routing (requires_manager_verification)                           #
# ──────────────────────────────────────────────────────────────────────────── #

class ManagerRoutingTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('mr_t1')
        cls.mgr   = _make_user('mr_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('mr_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _contained(self, severity='High', is_emergency=False):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            assigned_admin=self.admin, status=Ticket.STATUS_CONTAINMENT_REPORTED,
            severity=severity, is_emergency=is_emergency, containment_report='done',
        )

    def test_critical_requires_manager(self):
        t = self._contained(severity='Critical')
        self.assertTrue(t.requires_manager_verification)

    def test_high_does_not_require_manager(self):
        t = self._contained(severity='High')
        self.assertFalse(t.requires_manager_verification)

    def test_emergency_forces_manager_even_on_high(self):
        t = self._contained(severity='High', is_emergency=True)
        self.assertTrue(t.requires_manager_verification)

    def test_high_ticket_t1_closes_directly(self):
        t = self._contained(severity='High')
        t.transition_to(Ticket.STATUS_APPROVED, self.t1, 'closed')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_high_ticket_cannot_route_to_manager(self):
        t = self._contained(severity='High')
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t1, 'no need')

    def test_critical_ticket_t1_cannot_close_directly(self):
        t = self._contained(severity='Critical')
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t1, 'must go to manager')

    def test_critical_ticket_routes_to_manager_then_closes(self):
        t = self._contained(severity='Critical')
        t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t1, 'verified')
        t.transition_to(Ticket.STATUS_APPROVED, self.mgr, 'approved')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_emergency_high_must_route_to_manager(self):
        t = self._contained(severity='High', is_emergency=True)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t1, 'blocked by emergency')
        t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t1, 'route')
        self.assertEqual(t.status, Ticket.STATUS_PENDING_MANAGER)

    @override_settings(SOC_SEVERITY_FLOOR='High')
    def test_severity_floor_is_tunable(self):
        t = self._contained(severity='High')
        self.assertTrue(t.requires_manager_verification)


# ──────────────────────────────────────────────────────────────────────────── #
# 8. Emergency flag permissions + audit                                        #
# ──────────────────────────────────────────────────────────────────────────── #

class EmergencyFlagTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('em_t1')
        cls.t2    = _make_t2('em_t2')
        cls.mgr   = _make_user('em_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('em_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.owner = _make_user('em_owner', UserProfile.ROLE_SYSTEM_OWNER)
        cls.superuser = User.objects.create_superuser('em_super', 'em@x.com', 'testpass123')

    def _direct_admin_ticket(self):
        """Incident handed directly to admin — never escalated to T2."""
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            assigned_admin=self.admin, status=Ticket.STATUS_AWAITING_CONTAINMENT,
        )

    def _escalated_ticket(self):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_ESCALATED_T2, escalated_to_t2_at=timezone.now(),
        )

    # ── Tier 1 gating ───────────────────────────────────────────────────── #

    def test_t1_cannot_set_emergency_on_direct_admin_ticket(self):
        t = self._direct_admin_ticket()
        self.assertFalse(t.can_set_emergency(self.t1))
        with self.assertRaises(ValidationError):
            t.set_emergency(True, self.t1)

    def test_t1_can_set_emergency_on_escalated_ticket(self):
        t = self._escalated_ticket()
        self.assertTrue(t.can_set_emergency(self.t1))
        t.set_emergency(True, self.t1)
        t.refresh_from_db()
        self.assertTrue(t.is_emergency)

    def test_t1_can_set_emergency_after_t2_returned_ticket(self):
        """escalated_to_t2_at survives the return to T1, so the gate stays open."""
        t = self._escalated_ticket()
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'returned')
        self.assertTrue(t.can_set_emergency(self.t1))

    # ── Other roles ungated ─────────────────────────────────────────────── #

    def test_t2_can_set_emergency_on_any_ticket(self):
        t = self._direct_admin_ticket()
        self.assertTrue(t.can_set_emergency(self.t2))

    def test_manager_can_set_emergency(self):
        self.assertTrue(self._direct_admin_ticket().can_set_emergency(self.mgr))

    def test_system_admin_can_set_emergency(self):
        self.assertTrue(self._direct_admin_ticket().can_set_emergency(self.admin))

    def test_superuser_can_set_emergency(self):
        t = self._direct_admin_ticket()
        self.assertTrue(t.can_set_emergency(self.superuser))

    # ── Mutable at any stage + audit ────────────────────────────────────── #

    def test_emergency_toggleable_at_terminal_stage(self):
        t = _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_APPROVED,
        )
        t.set_emergency(True, self.mgr)
        t.refresh_from_db()
        self.assertTrue(t.is_emergency)

    def test_setting_emergency_writes_audit_log(self):
        t = self._escalated_ticket()
        before = t.logs.count()
        t.set_emergency(True, self.t1, 'urgent')
        self.assertEqual(t.logs.count(), before + 1)
        log = t.logs.first()
        self.assertEqual(log.author, self.t1)
        self.assertIn('Emergency', log.note)

    def test_no_op_toggle_does_not_log(self):
        t = self._escalated_ticket()
        before = t.logs.count()
        t.set_emergency(False, self.t1)  # already False
        self.assertEqual(t.logs.count(), before)

    def test_clear_emergency_logs(self):
        t = self._escalated_ticket()
        t.set_emergency(True, self.t2)
        t.set_emergency(False, self.t2)
        t.refresh_from_db()
        self.assertFalse(t.is_emergency)


# ──────────────────────────────────────────────────────────────────────────── #
# 9. System Admin field access                                                 #
# ──────────────────────────────────────────────────────────────────────────── #

class AdminFieldAccessTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('af_t1')
        cls.admin = _make_user('af_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _awaiting(self):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            assigned_admin=self.admin, status=Ticket.STATUS_AWAITING_CONTAINMENT,
        )

    def test_admin_writes_containment_and_remediation(self):
        t = self._awaiting()
        self.client.login(username='af_admin', password='testpass123')
        resp = self.client.post(reverse('ticket_detail', args=[t.pk]), {
            'action': 'containment',
            'containment_report': 'Isolated the host and blocked the C2 IP.',
            'remediation_summary': 'Root cause: phishing. Reimaged endpoint.',
            'note': 'done',
        })
        self.assertRedirects(resp, reverse('ticket_detail', args=[t.pk]))
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_CONTAINMENT_REPORTED)
        self.assertIn('blocked the C2 IP', t.containment_report)
        self.assertIn('Reimaged endpoint', t.remediation_summary)

    def test_admin_containment_does_not_set_classification(self):
        t = self._awaiting()
        self.client.login(username='af_admin', password='testpass123')
        self.client.post(reverse('ticket_detail', args=[t.pk]), {
            'action': 'containment',
            'containment_report': 'Contained.',
            'note': 'done',
        })
        t.refresh_from_db()
        # classification stays whatever T1 set — admin never touches it.
        self.assertEqual(t.classification, Ticket.CLASSIFICATION_INCIDENT)


# ──────────────────────────────────────────────────────────────────────────── #
# 10. Sign-off field tests                                                     #
# ──────────────────────────────────────────────────────────────────────────── #

class SignOffFieldsTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('sf_t1')
        cls.mgr   = _make_user('sf_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('sf_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _incident(self, severity='Critical'):
        return _make_ticket(
            assigned_admin=self.admin, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT, severity=severity,
        )

    def test_verified_by_set_when_t1_marks_contained(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_PENDING_MANAGER, self.t1, self.admin, mgr=self.mgr)
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.t1)
        self.assertIsNotNone(t.verified_at)

    def test_approved_by_set_to_manager(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin, mgr=self.mgr)
        t.refresh_from_db()
        self.assertEqual(t.approved_by, self.mgr)

    def test_direct_close_sets_both_signoffs_to_t1(self):
        t = self._incident(severity='High')  # no manager needed
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin)
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.t1)
        self.assertEqual(t.approved_by, self.t1)

    def test_verified_by_write_once(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_PENDING_MANAGER, self.t1, self.admin, mgr=self.mgr)
        t.refresh_from_db()
        # Force back to CONTAINMENT_REPORTED with a different creator; verified_by must hold.
        Ticket.objects.filter(pk=t.pk).update(
            status=Ticket.STATUS_CONTAINMENT_REPORTED, created_by=self.t1.pk,
        )
        t.refresh_from_db()
        t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t1, 'again')
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.t1)


# ──────────────────────────────────────────────────────────────────────────── #
# 11. Email notification tests                                                  #
# ──────────────────────────────────────────────────────────────────────────── #

class NotificationEmailTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1  = _make_t1('ne_t1')
        cls.admin = _make_user('ne_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin.email = 'sysadmin@example.com'
        cls.admin.save()
        cls.admin_no_email = _make_user('ne_admin_noemail', UserProfile.ROLE_SYSTEM_ADMIN)

    def setUp(self):
        mail.outbox = []

    def _routed_ticket(self):
        t = _make_ticket(
            assigned_admin=self.admin, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'routing')
        return t

    def test_routing_sends_one_email_to_admin(self):
        t = self._routed_ticket()
        self.assertTrue(notify_containment_required(t))
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(self.admin.email, mail.outbox[0].to)

    def test_routing_subject_contains_ticket_id(self):
        t = self._routed_ticket()
        notify_containment_required(t)
        self.assertIn(t.ticket_id, mail.outbox[0].subject)

    def test_rejection_loop_body_contains_reason(self):
        t = self._routed_ticket()
        reason = 'Patch description is missing — include the CVE reference.'
        notify_containment_required(t, reason=reason)
        self.assertIn(reason, mail.outbox[0].body)

    def test_no_email_when_admin_has_no_email(self):
        t = _make_ticket(
            assigned_admin=self.admin_no_email, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        self.assertFalse(notify_containment_required(t))
        self.assertEqual(len(mail.outbox), 0)

    def test_transition_succeeds_without_email(self):
        t = _make_ticket(
            assigned_admin=self.admin_no_email, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'routing')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)


# ──────────────────────────────────────────────────────────────────────────── #
# 12. Wazuh triage: 2-action + required release reason                          #
# ──────────────────────────────────────────────────────────────────────────── #

class WazuhTriageActionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_t1('wz_t1')
        cls.t2 = _make_t2('wz_t2')

    def _claimed_alert(self, claimer):
        return WazuhAlert.objects.create(
            opensearch_id=f'os-{claimer.username}-{timezone.now().timestamp()}',
            timestamp=timezone.now(), rule_level=12,
            rule_description='Suspicious activity',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=claimer, claimed_at=timezone.now(),
        )

    def test_create_ticket_action_redirects_to_create_form(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk, 'action': 'create_ticket',
            'note': 'looks real', 'category': WazuhAlert.CATEGORY_MALWARE,
        })
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse('create_ticket'), resp.url)

    def test_close_fp_action_is_rejected(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk, 'action': 'close_fp', 'note': 'fp',
        })
        self.assertEqual(resp.status_code, 302)
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)  # unchanged

    def test_escalate_action_is_rejected(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk, 'action': 'escalate',
            'note': 'unsure', 'escalate_to': WazuhAlert.TIER_T2,
        })
        self.assertEqual(resp.status_code, 302)
        alert.refresh_from_db()
        self.assertNotEqual(alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)

    def test_release_requires_reason(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('release_alert'), {'alert_id': alert.pk})
        self.assertEqual(resp.status_code, 302)
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)  # not released
        self.assertEqual(alert.release_reason, '')

    def test_release_with_reason_returns_to_pending(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('release_alert'), {
            'alert_id': alert.pk, 'release_reason': 'Need more context from the host owner.',
        })
        self.assertEqual(resp.status_code, 302)
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_PENDING)
        self.assertIsNone(alert.claimed_by)
        self.assertIn('more context', alert.release_reason)

    def test_tier2_cannot_claim(self):
        alert = WazuhAlert.objects.create(
            opensearch_id='os-pending', timestamp=timezone.now(), rule_level=10,
            triage_status=WazuhAlert.TRIAGE_PENDING,
        )
        self.client.login(username='wz_t2', password='testpass123')
        self.client.post(reverse('claim_alert'), {'alert_id': alert.pk})
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_PENDING)
        self.assertIsNone(alert.claimed_by)


# ──────────────────────────────────────────────────────────────────────────── #
# 13. Triage / wazuh-alert ticket creation integrity                           #
# ──────────────────────────────────────────────────────────────────────────── #

class TriageWorkflowIntegrityTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1       = _make_t1('manual_t1')
        cls.other_t1 = _make_t1('manual_t1_other')
        cls.t2       = _make_t2('manual_t2')

    def test_manual_triage_form_only_lists_active_t2_staff(self):
        form = TriageForm(user=self.t1)
        self.assertQuerySetEqual(form.fields['escalated_to'].queryset, [self.t2])

    def test_non_owner_cannot_create_ticket_from_manual_triage(self):
        triage = TriageRecord.objects.create(
            source=TriageRecord.SOURCE_PHONE, analyst=self.t1,
            alert_description='Reported suspicious login.',
            decision=TriageRecord.DECISION_TP, notes='Confirmed by T1.',
        )
        self.client.login(username='manual_t1_other', password='testpass123')
        response = self.client.get(reverse('create_ticket'), {'triage_id': triage.pk})
        self.assertRedirects(response, reverse('triage_list'))
        self.assertFalse(Ticket.objects.exists())

    def test_wazuh_alert_becomes_true_positive_after_ticket_save(self):
        alert = WazuhAlert.objects.create(
            opensearch_id='ticket-finalize-alert', timestamp=timezone.now(),
            rule_level=14, rule_description='Confirmed ransomware behavior',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=self.t1, claimed_at=timezone.now(),
            triage_note='Confirmed malicious.', incident_category=WazuhAlert.CATEGORY_MALWARE,
        )
        self.client.login(username='manual_t1', password='testpass123')
        response = self.client.post(reverse('create_ticket'), _ticket_post_data(
            wazuh_alert=alert.pk,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ESCALATE_T2,
        ))
        self.assertEqual(response.status_code, 302)
        ticket = Ticket.objects.get(wazuh_alert=alert)
        alert.refresh_from_db()
        self.assertEqual(ticket.created_by, self.t1)
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRUE_POSITIVE)
        self.assertIsNone(alert.claimed_by)

    def test_invalid_ticket_form_keeps_wazuh_alert_in_progress(self):
        alert = WazuhAlert.objects.create(
            opensearch_id='invalid-ticket-alert', timestamp=timezone.now(),
            rule_level=12, rule_description='Suspicious command execution',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=self.t1, claimed_at=timezone.now(),
        )
        self.client.login(username='manual_t1', password='testpass123')
        response = self.client.post(reverse('create_ticket'), {'wazuh_alert': alert.pk})
        self.assertEqual(response.status_code, 200)
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)
        self.assertFalse(Ticket.objects.filter(wazuh_alert=alert).exists())


# ──────────────────────────────────────────────────────────────────────────── #
# 14. Superuser bypass                                                          #
# ──────────────────────────────────────────────────────────────────────────── #

class SuperuserAccessTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.superuser = User.objects.create_superuser(
            username='all_access_superuser', email='superuser@example.com',
            password='testpass123',
        )
        cls.system_admin = _make_user('superuser_target_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.t1 = _make_t1('superuser_t1')
        cls.t2 = _make_t2('superuser_t2')

    def setUp(self):
        self.client.force_login(self.superuser)

    def test_superuser_without_profile_sees_all_tickets(self):
        first = _make_ticket(issue_description='First ticket')
        second = _make_ticket(issue_description='Second ticket', assigned_admin=self.system_admin)
        self.assertFalse(hasattr(self.superuser, 'profile'))
        self.assertQuerySetEqual(
            Ticket.objects.visible_to(self.superuser).order_by('pk'), [first, second],
        )

    def test_superuser_can_access_core_pages(self):
        ticket = _make_ticket()
        urls = [
            reverse('home'), reverse('ticket_list'), reverse('create_ticket'),
            reverse('ticket_detail', args=[ticket.pk]), reverse('ticket_history'),
            reverse('triage_list'), reverse('create_triage'),
            reverse('system_owner_dashboard'),
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_superuser_can_perform_every_ticket_role_transition(self):
        ticket = _make_ticket(
            assigned_admin=self.system_admin, severity='Critical',
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        ticket.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.superuser, 'as t1')
        ticket.containment_report = 'Contained by superuser.'
        ticket.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.superuser, 'as admin')
        ticket.transition_to(Ticket.STATUS_PENDING_MANAGER, self.superuser, 'verify')
        ticket.transition_to(Ticket.STATUS_APPROVED, self.superuser, 'as manager')
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_APPROVED)
        self.assertEqual(ticket.verified_by, self.superuser)
        self.assertEqual(ticket.approved_by, self.superuser)

    def test_superuser_can_submit_containment_for_any_ticket(self):
        ticket = _make_ticket(
            assigned_admin=self.system_admin, status=Ticket.STATUS_AWAITING_CONTAINMENT,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        response = self.client.post(reverse('ticket_detail', args=[ticket.pk]), {
            'action': 'containment',
            'containment_report': 'Superuser containment report.',
            'note': 'Completed with all-role access.',
        })
        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_CONTAINMENT_REPORTED)


# ──────────────────────────────────────────────────────────────────────────── #
# 15. Attachment download authorization                                         #
# ──────────────────────────────────────────────────────────────────────────── #

@override_settings(MEDIA_ROOT=tempfile.mkdtemp(prefix='soc_test_media_'))
class AttachmentDownloadSecurityTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_t1('att_soc')
        cls.admin_a = _make_user('att_admin_a', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b = _make_user('att_admin_b', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.ticket_a = _make_ticket(assigned_admin=cls.admin_a)
        cls.attachment = TicketAttachment.objects.create(
            ticket=cls.ticket_a,
            file=SimpleUploadedFile(
                'evidence.html', b'<script>alert(document.cookie)</script>',
                content_type='text/html',
            ),
            original_name='evidence.html', uploaded_by=cls.soc_staff,
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(settings.MEDIA_ROOT, ignore_errors=True)

    def _url(self):
        return reverse('download_attachment', args=[self.attachment.pk])

    def test_unauthenticated_redirected_to_login(self):
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_authorized_user_downloads_with_safe_headers(self):
        self.client.force_login(self.soc_staff)
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response['Content-Disposition'].startswith('attachment'))
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

    def test_admin_cannot_download_attachment_on_unrelated_ticket(self):
        self.client.force_login(self.admin_b)
        self.assertEqual(self.client.get(self._url()).status_code, 404)


# ──────────────────────────────────────────────────────────────────────────── #
# 16. Attachment upload size limit                                              #
# ──────────────────────────────────────────────────────────────────────────── #

class AttachmentUploadLimitTest(TestCase):
    def test_oversize_file_rejected_by_form(self):
        with patch('apps.incidents.models.MAX_ATTACHMENT_SIZE', 10):
            form = AttachmentForm(
                data={'description': ''},
                files={'file': SimpleUploadedFile(
                    'big.bin', b'01234567890', content_type='application/octet-stream',
                )},
            )
            self.assertFalse(form.is_valid())
            self.assertIn('file', form.errors)

    def test_within_limit_file_accepted_by_form(self):
        form = AttachmentForm(
            data={'description': 'ok'},
            files={'file': SimpleUploadedFile('small.txt', b'hello', content_type='text/plain')},
        )
        self.assertTrue(form.is_valid(), msg=form.errors)
