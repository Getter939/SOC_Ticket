"""
Tests for the SOC ticketing system.

Test classes
────────────
1.  TicketVisibilityQuerysetTest  — Ticket.objects.visible_to() queryset scoping
2.  TicketVisibilityViewTest      — HTTP-level visibility enforcement
3.  WorkflowTransitionTest        — Every legal state-machine edge, every illegal edge
4.  WorkflowPermissionTest        — Per-transition role permissions (positive + negative)
5.  SignOffFieldsTest              — verified_by/at and approved_by/at are write-once
6.  NotificationEmailTest         — Email notifications on AWAITING_CONTAINMENT transitions

Notes
─────
• Run with:  py manage.py test apps.incidents --settings=config.settings_local
• Database:  SQLite (via settings_local)
• Email:     Django's test runner calls setup_test_environment() before tests,
             which replaces EMAIL_BACKEND with the in-memory locmem backend and
             initialises django.core.mail.outbox — no real SMTP is needed.
"""

from django.contrib.auth.models import User
from django.core import mail
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketLog
from apps.incidents.notifications import notify_containment_required


# ──────────────────────────────────────────────────────────────────────────── #
# Shared helpers                                                               #
# ──────────────────────────────────────────────────────────────────────────── #

def _make_user(username, role, department='Test', phone='000', **kwargs):
    """Create a User + UserProfile in one call."""
    user = User.objects.create_user(username=username, password='testpass123')
    UserProfile.objects.create(
        user=user, role=role, department=department, phone=phone, **kwargs
    )
    return user


def _make_ticket(**kwargs):
    """Create a Ticket with sensible defaults."""
    defaults = dict(
        device_name='10.0.0.1',
        ip_address='192.168.0.1',
        issue_description='Test ticket',
    )
    defaults.update(kwargs)
    return Ticket.objects.create(**defaults)


def _advance_to(ticket, target_status, soc_user, admin_user=None, mgr_user=None):
    """
    Drive a ticket from its current status to target_status by replaying
    each transition in the happy path.

    soc_user  — a user with SOC_STAFF or SOC_MANAGER role
    admin_user — the SYSTEM_ADMIN assigned to the ticket (required if target
                 is CONTAINMENT_REPORTED or later)
    mgr_user  — a user with SOC_MANAGER role (required if target is APPROVED).
                Falls back to soc_user when not supplied, which will raise
                ValidationError if soc_user is not a manager.
    """
    approver = mgr_user or soc_user
    path = [
        Ticket.STATUS_NEW,
        Ticket.STATUS_AWAITING_CONTAINMENT,
        Ticket.STATUS_CONTAINMENT_REPORTED,
        Ticket.STATUS_UNDER_REVIEW,
        Ticket.STATUS_VERIFIED,
        Ticket.STATUS_APPROVED,
    ]
    i = path.index(ticket.status)
    j = path.index(target_status)
    for step in path[i + 1: j + 1]:
        if step == Ticket.STATUS_CONTAINMENT_REPORTED:
            ticket.disposition = Ticket.DISP_TRUE_POSITIVE
            ticket.containment_report = 'Contained.'
            ticket.transition_to(step, admin_user, 'containment note')
        elif step == Ticket.STATUS_APPROVED:
            ticket.transition_to(step, approver, f'moving to {step}')
        else:
            ticket.transition_to(step, soc_user, f'moving to {step}')


# ──────────────────────────────────────────────────────────────────────────── #
# 1. Visibility queryset tests (unchanged from Session 4)                      #
# ──────────────────────────────────────────────────────────────────────────── #

class TicketVisibilityQuerysetTest(TestCase):
    """Unit-level: Ticket.objects.visible_to() returns the right rows."""

    @classmethod
    def setUpTestData(cls):
        cls.soc_staff   = _make_user('soc_staff',   UserProfile.ROLE_SOC_STAFF)
        cls.soc_manager = _make_user('soc_manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin_a     = _make_user('admin_a',     UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b     = _make_user('admin_b',     UserProfile.ROLE_SYSTEM_ADMIN)

        cls.no_profile = User.objects.create_user(username='noprofile', password='testpass123')

        cls.ticket_a = _make_ticket(
            device_name='10.0.0.1', ip_address='192.168.0.1',
            issue_description='Ticket routed to admin A',
            assigned_admin=cls.admin_a,
        )
        cls.ticket_b = _make_ticket(
            device_name='10.0.0.2', ip_address='192.168.0.2',
            issue_description='Ticket routed to admin B',
            assigned_admin=cls.admin_b,
        )
        cls.ticket_unassigned = _make_ticket(
            device_name='10.0.0.3', ip_address='192.168.0.3',
            issue_description='Unassigned ticket',
        )

    def test_soc_staff_sees_all_tickets(self):
        qs = Ticket.objects.visible_to(self.soc_staff)
        self.assertEqual(qs.count(), 3)

    def test_soc_staff_sees_admin_a_ticket(self):
        qs = Ticket.objects.visible_to(self.soc_staff)
        self.assertIn(self.ticket_a, qs)

    def test_soc_manager_sees_all_tickets(self):
        qs = Ticket.objects.visible_to(self.soc_manager)
        self.assertEqual(qs.count(), 3)

    def test_system_admin_sees_only_own_ticket(self):
        qs = Ticket.objects.visible_to(self.admin_a)
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), self.ticket_a)

    def test_system_admin_cannot_see_other_admins_ticket(self):
        qs = Ticket.objects.visible_to(self.admin_a)
        self.assertNotIn(self.ticket_b, qs)

    def test_system_admin_cannot_see_unassigned_ticket(self):
        qs = Ticket.objects.visible_to(self.admin_a)
        self.assertNotIn(self.ticket_unassigned, qs)

    def test_no_profile_sees_no_tickets(self):
        qs = Ticket.objects.visible_to(self.no_profile)
        self.assertEqual(qs.count(), 0)

    def test_no_profile_returns_empty_queryset_not_error(self):
        qs = Ticket.objects.visible_to(self.no_profile)
        self.assertFalse(qs.exists())


# ──────────────────────────────────────────────────────────────────────────── #
# 2. Visibility view tests (unchanged from Session 4)                          #
# ──────────────────────────────────────────────────────────────────────────── #

class TicketVisibilityViewTest(TestCase):
    """Integration-level: HTTP responses respect the visibility boundary."""

    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_user('v_soc_staff', UserProfile.ROLE_SOC_STAFF)
        cls.admin_a   = _make_user('v_admin_a',   UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b   = _make_user('v_admin_b',   UserProfile.ROLE_SYSTEM_ADMIN)

        cls.ticket_a = _make_ticket(
            device_name='10.1.0.1', ip_address='172.16.0.1',
            issue_description='View test — admin A ticket',
            assigned_admin=cls.admin_a,
        )
        cls.ticket_b = _make_ticket(
            device_name='10.1.0.2', ip_address='172.16.0.2',
            issue_description='View test — admin B ticket',
            assigned_admin=cls.admin_b,
        )

    def test_admin_a_can_view_own_ticket(self):
        self.client.login(username='v_admin_a', password='testpass123')
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_a.pk})
        self.assertEqual(self.client.get(url).status_code, 200)

    def test_admin_a_gets_404_on_admin_b_ticket(self):
        self.client.login(username='v_admin_a', password='testpass123')
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_b.pk})
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_soc_staff_can_view_any_ticket(self):
        self.client.login(username='v_soc_staff', password='testpass123')
        for ticket in (self.ticket_a, self.ticket_b):
            url = reverse('ticket_detail', kwargs={'pk': ticket.pk})
            response = self.client.get(url)
            self.assertEqual(
                response.status_code, 200,
                msg=f"SOC staff should see ticket {ticket.pk}, got {response.status_code}",
            )

    def test_admin_a_ticket_list_contains_only_own_ticket(self):
        self.client.login(username='v_admin_a', password='testpass123')
        url = reverse('ticket_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        tickets_in_context = list(response.context['tickets'])
        self.assertIn(self.ticket_a, tickets_in_context)
        self.assertNotIn(self.ticket_b, tickets_in_context)

    def test_unauthenticated_user_redirected(self):
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_a.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])


# ──────────────────────────────────────────────────────────────────────────── #
# 3. Workflow transition tests                                                  #
# ──────────────────────────────────────────────────────────────────────────── #

class WorkflowTransitionTest(TestCase):
    """
    Every legal edge fires without error.
    Every illegal edge raises ValidationError.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc   = _make_user('wf_soc',   UserProfile.ROLE_SOC_STAFF)
        cls.mgr   = _make_user('wf_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('wf_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    # ── Happy path: every legal transition ───────────────────────────────── #

    def _fresh_ticket(self):
        return _make_ticket(assigned_admin=self.admin)

    def test_new_to_awaiting_containment(self):
        t = self._fresh_ticket()
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc, 'dispatch')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_awaiting_containment_to_containment_reported(self):
        t = self._fresh_ticket()
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc, 'dispatch')
        t.disposition = Ticket.DISP_TRUE_POSITIVE
        t.containment_report = 'Contained.'
        t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin, 'reported')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_CONTAINMENT_REPORTED)

    def test_containment_reported_to_under_review(self):
        t = self._fresh_ticket()
        _advance_to(t, Ticket.STATUS_CONTAINMENT_REPORTED, self.soc, self.admin)
        t.transition_to(Ticket.STATUS_UNDER_REVIEW, self.soc, 'reviewing')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_UNDER_REVIEW)

    def test_under_review_to_verified(self):
        t = self._fresh_ticket()
        _advance_to(t, Ticket.STATUS_UNDER_REVIEW, self.soc, self.admin)
        t.transition_to(Ticket.STATUS_VERIFIED, self.soc, 'verified')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_VERIFIED)

    def test_verified_to_approved(self):
        t = self._fresh_ticket()
        _advance_to(t, Ticket.STATUS_APPROVED, self.soc, self.admin, mgr_user=self.mgr)
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_rejection_loop_under_review_back_to_awaiting(self):
        """SOC can reject: UNDER_REVIEW → AWAITING_CONTAINMENT (send back for re-containment)."""
        t = self._fresh_ticket()
        _advance_to(t, Ticket.STATUS_UNDER_REVIEW, self.soc, self.admin)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc, 'needs rework')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_log_created_on_each_transition(self):
        t = self._fresh_ticket()
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc, 'step 1')
        t.disposition = Ticket.DISP_TRUE_POSITIVE
        t.containment_report = 'report'
        t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin, 'step 2')
        self.assertEqual(t.logs.count(), 2)

    def test_same_status_note_only(self):
        """SOC can call transition_to with the current status to add a note."""
        t = self._fresh_ticket()
        before_count = t.logs.count()
        t.transition_to(Ticket.STATUS_NEW, self.soc, 'just a note')
        self.assertEqual(t.logs.count(), before_count + 1)
        self.assertEqual(t.status, Ticket.STATUS_NEW)

    # ── Illegal transitions ───────────────────────────────────────────────── #

    def test_cannot_skip_states(self):
        t = self._fresh_ticket()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_UNDER_REVIEW, self.soc, 'skip')

    def test_cannot_go_backwards_arbitrarily(self):
        t = self._fresh_ticket()
        _advance_to(t, Ticket.STATUS_VERIFIED, self.soc, self.admin)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_NEW, self.soc, 'backwards')

    def test_approved_is_terminal(self):
        t = self._fresh_ticket()
        _advance_to(t, Ticket.STATUS_APPROVED, self.soc, self.admin, mgr_user=self.mgr)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_UNDER_REVIEW, self.soc, 'reopen')

    def test_closed_fp_is_terminal(self):
        """CLOSED_FP has no outgoing transitions."""
        t = self._fresh_ticket()
        t.status = Ticket.STATUS_CLOSED_FP
        t.disposition = Ticket.DISP_FALSE_POSITIVE
        t.save()
        with self.assertRaises(ValidationError):
            # FP gate fires first
            t.transition_to(Ticket.STATUS_NEW, self.soc, 'reopen fp')

    def test_false_positive_ticket_rejects_all_transitions(self):
        """Once disposition=FALSE_POSITIVE, transition_to always raises."""
        t = self._fresh_ticket()
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc, 'dispatch')
        t.disposition = Ticket.DISP_FALSE_POSITIVE
        t.containment_report = 'FP found.'
        t.save()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin, 'fp report')

    def test_invalid_status_code_raises(self):
        t = self._fresh_ticket()
        with self.assertRaises(ValidationError):
            t.transition_to('BOGUS_STATUS', self.soc, 'bad code')


# ──────────────────────────────────────────────────────────────────────────── #
# 4. Permission matrix tests                                                   #
# ──────────────────────────────────────────────────────────────────────────── #

class WorkflowPermissionTest(TestCase):
    """
    Each transition's permission is enforced correctly.
    Covers both positive (allowed) and negative (forbidden) cases.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_user('pm_soc_staff', UserProfile.ROLE_SOC_STAFF)
        cls.soc_mgr   = _make_user('pm_soc_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin_a   = _make_user('pm_admin_a',   UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b   = _make_user('pm_admin_b',   UserProfile.ROLE_SYSTEM_ADMIN)
        cls.no_profile = User.objects.create_user(username='pm_noprofile', password='x')

    def _ticket_at(self, status, assigned_admin=None):
        """Build a ticket pre-set to the requested status (bypassing transition guards)."""
        t = _make_ticket(
            status=status,
            assigned_admin=assigned_admin or self.admin_a,
        )
        return t

    # NEW → AWAITING_CONTAINMENT  requires SOC ─────────────────────────────

    def test_soc_staff_can_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc_staff, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_soc_manager_can_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc_mgr, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_system_admin_cannot_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.admin_a, 'denied')

    def test_no_profile_cannot_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.no_profile, 'denied')

    # AWAITING_CONTAINMENT → CONTAINMENT_REPORTED  requires ASSIGNED_ADMIN ─

    def test_assigned_admin_can_report_containment(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=self.admin_a)
        t.disposition = Ticket.DISP_TRUE_POSITIVE
        t.containment_report = 'contained'
        t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin_a, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_CONTAINMENT_REPORTED)

    def test_other_admin_cannot_report_containment(self):
        """admin_b is not the assigned admin — must be denied."""
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=self.admin_a)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin_b, 'denied')

    def test_soc_staff_cannot_report_containment(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.soc_staff, 'denied')

    # CONTAINMENT_REPORTED → UNDER_REVIEW  requires SOC ───────────────────

    def test_soc_staff_can_start_review(self):
        t = self._ticket_at(Ticket.STATUS_CONTAINMENT_REPORTED)
        t.transition_to(Ticket.STATUS_UNDER_REVIEW, self.soc_staff, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_UNDER_REVIEW)

    def test_system_admin_cannot_start_review(self):
        t = self._ticket_at(Ticket.STATUS_CONTAINMENT_REPORTED)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_UNDER_REVIEW, self.admin_a, 'denied')

    # UNDER_REVIEW → VERIFIED  requires SOC ──────────────────────────────

    def test_soc_staff_can_verify(self):
        t = self._ticket_at(Ticket.STATUS_UNDER_REVIEW)
        t.transition_to(Ticket.STATUS_VERIFIED, self.soc_staff, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_VERIFIED)

    def test_system_admin_cannot_verify(self):
        t = self._ticket_at(Ticket.STATUS_UNDER_REVIEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_VERIFIED, self.admin_a, 'denied')

    # UNDER_REVIEW → AWAITING_CONTAINMENT (rejection loop)  requires SOC ─

    def test_soc_can_reject_back_to_awaiting(self):
        t = self._ticket_at(Ticket.STATUS_UNDER_REVIEW)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc_staff, 'rework')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_admin_cannot_self_reject(self):
        t = self._ticket_at(Ticket.STATUS_UNDER_REVIEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.admin_a, 'denied')

    # VERIFIED → APPROVED  requires MANAGER only ─────────────────────────

    def test_soc_manager_can_approve(self):
        t = self._ticket_at(Ticket.STATUS_VERIFIED)
        t.transition_to(Ticket.STATUS_APPROVED, self.soc_mgr, 'approved')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_soc_staff_cannot_approve(self):
        """SOC staff is not a manager — must be denied."""
        t = self._ticket_at(Ticket.STATUS_VERIFIED)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.soc_staff, 'denied')

    def test_system_admin_cannot_approve(self):
        t = self._ticket_at(Ticket.STATUS_VERIFIED)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.admin_a, 'denied')

    # Same-status note: SOC only ─────────────────────────────────────────

    def test_soc_staff_same_status_note(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        t.transition_to(Ticket.STATUS_NEW, self.soc_staff, 'note')
        self.assertEqual(t.logs.filter(status_at_time=Ticket.STATUS_NEW).count(), 1)

    def test_system_admin_same_status_raises(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=self.admin_a)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.admin_a, 'note')

    def test_no_profile_same_status_raises(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_NEW, self.no_profile, 'note')


# ──────────────────────────────────────────────────────────────────────────── #
# 5. Sign-off field tests                                                      #
# ──────────────────────────────────────────────────────────────────────────── #

class SignOffFieldsTest(TestCase):
    """
    verified_by/at and approved_by/at are set exactly once and never
    overwritten — even when the rejection loop re-enters UNDER_REVIEW.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc1  = _make_user('sf_soc1',  UserProfile.ROLE_SOC_STAFF)
        cls.soc2  = _make_user('sf_soc2',  UserProfile.ROLE_SOC_STAFF)
        cls.mgr1  = _make_user('sf_mgr1',  UserProfile.ROLE_SOC_MANAGER)
        cls.mgr2  = _make_user('sf_mgr2',  UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('sf_admin',  UserProfile.ROLE_SYSTEM_ADMIN)

    def _fresh(self):
        return _make_ticket(assigned_admin=self.admin)

    def test_verified_by_set_on_verified_transition(self):
        t = self._fresh()
        _advance_to(t, Ticket.STATUS_VERIFIED, self.soc1, self.admin)
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.soc1)
        self.assertIsNotNone(t.verified_at)

    def test_verified_at_is_recent(self):
        before = timezone.now()
        t = self._fresh()
        _advance_to(t, Ticket.STATUS_VERIFIED, self.soc1, self.admin)
        t.refresh_from_db()
        self.assertGreaterEqual(t.verified_at, before)

    def test_approved_by_set_on_approved_transition(self):
        t = self._fresh()
        _advance_to(t, Ticket.STATUS_APPROVED, self.soc1, self.admin, mgr_user=self.mgr1)
        t.refresh_from_db()
        self.assertEqual(t.approved_by, self.mgr1)

    def test_verified_by_not_overwritten_on_second_verified_transition(self):
        """
        Write-once guard: if verified_by is already set, a second call to
        transition_to(VERIFIED) must NOT overwrite it — even with a different user.

        The state machine has no path from VERIFIED back to UNDER_REVIEW, so
        we test the guard directly by resetting status in the DB and calling
        transition_to(VERIFIED) a second time with soc2.
        """
        t = self._fresh()
        _advance_to(t, Ticket.STATUS_VERIFIED, self.soc1, self.admin)
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.soc1)

        # Force status back to UNDER_REVIEW at the DB level (bypass the state machine)
        # so we can call transition_to(VERIFIED) a second time.
        Ticket.objects.filter(pk=t.pk).update(status=Ticket.STATUS_UNDER_REVIEW)
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_UNDER_REVIEW)

        # soc2 now verifies — write-once guard must keep soc1
        t.transition_to(Ticket.STATUS_VERIFIED, self.soc2, 'second verify attempt')
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.soc1,
                         "verified_by must remain soc1 (write-once guard failed)")

    def test_approved_by_not_overwritten(self):
        """
        Write-once guard: a second transition_to(APPROVED) must NOT overwrite
        approved_by.  Tested by forcing status back to VERIFIED in the DB.
        """
        t = self._fresh()
        _advance_to(t, Ticket.STATUS_APPROVED, self.soc1, self.admin, mgr_user=self.mgr1)
        t.refresh_from_db()
        self.assertEqual(t.approved_by, self.mgr1)

        # Force status back to VERIFIED at the DB level to allow a second approve call.
        Ticket.objects.filter(pk=t.pk).update(status=Ticket.STATUS_VERIFIED)
        t.refresh_from_db()

        # mgr2 tries to approve — write-once guard must keep mgr1.
        t.transition_to(Ticket.STATUS_APPROVED, self.mgr2, 'second approve attempt')
        t.refresh_from_db()
        self.assertEqual(t.approved_by, self.mgr1,
                         "approved_by must remain mgr1 (write-once guard failed)")

    def test_no_verified_by_before_verified_state(self):
        t = self._fresh()
        _advance_to(t, Ticket.STATUS_UNDER_REVIEW, self.soc1, self.admin)
        t.refresh_from_db()
        self.assertIsNone(t.verified_by)
        self.assertIsNone(t.verified_at)

    def test_no_approved_by_before_approved_state(self):
        t = self._fresh()
        _advance_to(t, Ticket.STATUS_VERIFIED, self.soc1, self.admin)
        t.refresh_from_db()
        self.assertIsNone(t.approved_by)
        self.assertIsNone(t.approved_at)


# ──────────────────────────────────────────────────────────────────────────── #
# 6. Email notification tests                                                   #
# ──────────────────────────────────────────────────────────────────────────── #

class NotificationEmailTest(TestCase):
    """
    Tests for apps.incidents.notifications.notify_containment_required().

    Django's test runner calls setup_test_environment() before the suite
    begins, which replaces EMAIL_BACKEND with the locmem backend and
    initialises django.core.mail.outbox — no real SMTP is needed and
    settings_local.py's console backend does not interfere.

    setUp() resets mail.outbox before each individual test so that one
    test's mail cannot pollute another's count.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('ne_soc', UserProfile.ROLE_SOC_STAFF)
        cls.mgr = _make_user('ne_mgr', UserProfile.ROLE_SOC_MANAGER)

        # Admin with a valid email address
        cls.admin = _make_user('ne_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin.email = 'sysadmin@example.com'
        cls.admin.save()

        # Admin whose User record has no email (blank string, Django default)
        cls.admin_no_email = _make_user('ne_admin_noemail', UserProfile.ROLE_SYSTEM_ADMIN)
        # admin_no_email.email is '' by default — no save() needed

    def setUp(self):
        """Reset the in-memory outbox before every test."""
        mail.outbox = []

    # ── Helper ───────────────────────────────────────────────────────────── #

    def _routed_ticket(self):
        """Return a ticket that has been moved to AWAITING_CONTAINMENT."""
        t = _make_ticket(assigned_admin=self.admin)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc, 'routing')
        return t

    # ── Initial routing (NEW → AWAITING_CONTAINMENT) ─────────────────────── #

    def test_routing_sends_exactly_one_email(self):
        """Calling the notifier once produces exactly one outbox entry."""
        t = self._routed_ticket()
        notify_containment_required(t)
        self.assertEqual(len(mail.outbox), 1)

    def test_routing_email_sent_to_assigned_admin(self):
        """The email is addressed to the assigned admin's email."""
        t = self._routed_ticket()
        notify_containment_required(t)
        self.assertIn(self.admin.email, mail.outbox[0].to)

    def test_routing_email_subject_contains_ticket_id(self):
        """The subject line contains the ticket ID so it can be filtered/searched."""
        t = self._routed_ticket()
        notify_containment_required(t)
        self.assertIn(t.ticket_id, mail.outbox[0].subject)

    def test_routing_email_subject_says_containment_required(self):
        """Initial routing subject does NOT say 'resubmission'."""
        t = self._routed_ticket()
        notify_containment_required(t)
        subject = mail.outbox[0].subject
        self.assertIn('Containment required', subject)
        self.assertNotIn('resubmission', subject.lower())

    def test_routing_returns_true_on_success(self):
        t = self._routed_ticket()
        result = notify_containment_required(t)
        self.assertTrue(result)

    # ── Rejection loop (UNDER_REVIEW → AWAITING_CONTAINMENT) ─────────────── #

    def test_rejection_loop_email_body_contains_reason(self):
        """
        When the analyst sends the ticket back, their rejection note must
        appear verbatim in the email body so the admin knows what to fix.
        """
        t = _make_ticket(assigned_admin=self.admin)
        _advance_to(t, Ticket.STATUS_UNDER_REVIEW, self.soc, self.admin)
        reason = 'Patch description is missing — please include the CVE reference.'
        notify_containment_required(t, reason=reason)
        self.assertIn(reason, mail.outbox[0].body)

    def test_rejection_loop_subject_contains_resubmission(self):
        """Rejection loop subject must say 'resubmission' to distinguish it from initial routing."""
        t = _make_ticket(assigned_admin=self.admin)
        notify_containment_required(t, reason='needs more detail')
        self.assertIn('resubmission', mail.outbox[0].subject.lower())

    def test_rejection_loop_subject_contains_ticket_id(self):
        """Rejection loop subject also contains the ticket ID."""
        t = _make_ticket(assigned_admin=self.admin)
        notify_containment_required(t, reason='incomplete')
        self.assertIn(t.ticket_id, mail.outbox[0].subject)

    # ── Missing admin / missing email ─────────────────────────────────────── #

    def test_no_email_when_admin_has_no_email_address(self):
        """notify_containment_required skips silently and returns False."""
        t = _make_ticket(assigned_admin=self.admin_no_email)
        result = notify_containment_required(t)
        self.assertFalse(result)
        self.assertEqual(len(mail.outbox), 0)

    def test_no_email_when_no_assigned_admin(self):
        """Ticket with no assigned_admin — returns False, outbox stays empty."""
        t = _make_ticket()  # no assigned_admin
        result = notify_containment_required(t)
        self.assertFalse(result)
        self.assertEqual(len(mail.outbox), 0)

    def test_transition_still_succeeds_without_email(self):
        """
        The state machine must not depend on email working.
        A ticket with no admin email still reaches AWAITING_CONTAINMENT.
        """
        t = _make_ticket(assigned_admin=self.admin_no_email)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.soc, 'routing')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        # Now send (or rather skip) the notification
        notify_containment_required(t)
        self.assertEqual(len(mail.outbox), 0)

    # ── Other transitions send no email ───────────────────────────────────── #

    def test_other_transitions_do_not_send_email(self):
        """
        Driving a ticket all the way to APPROVED via direct model calls
        should produce zero emails — the notifier is only called from the
        view, and only for AWAITING_CONTAINMENT transitions.
        """
        t = _make_ticket(assigned_admin=self.admin)
        _advance_to(t, Ticket.STATUS_APPROVED, self.soc, self.admin, mgr_user=self.mgr)
        self.assertEqual(len(mail.outbox), 0)

    def test_verified_to_approved_sends_no_email(self):
        """Spot-check: VERIFIED → APPROVED via transition_to sends no email."""
        t = _make_ticket(assigned_admin=self.admin)
        _advance_to(t, Ticket.STATUS_VERIFIED, self.soc, self.admin)
        t.transition_to(Ticket.STATUS_APPROVED, self.mgr, 'approved')
        self.assertEqual(len(mail.outbox), 0)
