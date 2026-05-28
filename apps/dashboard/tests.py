"""
Dashboard tests — Change 5.

Coverage:
  - Access control: SOC (staff + manager) sees dashboard; system admin is
    redirected; unauthenticated user hits the login redirect.
  - SLA-breach query: overdue active ticket counted; overdue terminal ticket
    NOT counted; not-yet-due active ticket NOT counted.
  - Metrics: active vs closed split, FP/TP counts and percentages, and the
    who-must-act backlog are correct given known fixture data.

These tests use Django's TestCase (each test wrapped in its own DB
transaction, rolled back on teardown), so ticket data created in one test
does not bleed into another.  Users are created with setUpTestData for
efficiency — they are shared across tests in the same class.
"""
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket


# ── Helpers ──────────────────────────────────────────────────────────────── #

def _make_user(username, role, email=''):
    """Create a User + UserProfile with the given role."""
    from django.contrib.auth.models import User
    user = User.objects.create_user(username=username, password='pw', email=email)
    UserProfile.objects.create(
        user=user, role=role, department='Test Dept', phone='000-000-0000',
    )
    return user


def _make_ticket(
    status=Ticket.STATUS_NEW,
    sla_offset_hours=None,
    disposition='',
):
    """
    Create a Ticket directly (bypassing the state machine).

    sla_offset_hours — if given, overrides the auto-set sla_deadline.
      Positive = future (not breached); negative = past (breached).
      If not given, Ticket.save() auto-sets sla_deadline = now + 48 h.
    """
    kwargs = {
        'device_name':      '192.168.1.1',
        'ip_address':       '10.0.0.1',
        'issue_description': 'Test incident',
        'status':           status,
        'disposition':      disposition,
    }
    if sla_offset_hours is not None:
        kwargs['sla_deadline'] = timezone.now() + timedelta(hours=sla_offset_hours)
    return Ticket.objects.create(**kwargs)


DASHBOARD_URL = reverse('home')


# ── Access-control tests ─────────────────────────────────────────────────── #

class DashboardAccessTest(TestCase):
    """Change 1: SOC roles see the dashboard; system admins are redirected."""

    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_user('soc_staff_ac',  UserProfile.ROLE_SOC_STAFF)
        cls.soc_mgr   = _make_user('soc_mgr_ac',    UserProfile.ROLE_SOC_MANAGER)
        cls.sys_admin = _make_user('sys_admin_ac',  UserProfile.ROLE_SYSTEM_ADMIN)

    def test_soc_staff_sees_dashboard(self):
        self.client.force_login(self.soc_staff)
        response = self.client.get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/dashboard.html')

    def test_soc_manager_sees_dashboard(self):
        self.client.force_login(self.soc_mgr)
        response = self.client.get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/dashboard.html')

    def test_system_admin_is_redirected(self):
        """System admins must not see org-wide aggregates — redirect to ticket_list."""
        self.client.force_login(self.sys_admin)
        response = self.client.get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('ticket_list'), fetch_redirect_response=False)

    def test_unauthenticated_user_redirected_to_login(self):
        response = self.client.get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response['Location'])


# ── SLA-breach counting tests ────────────────────────────────────────────── #

class DashboardSLABreachTest(TestCase):
    """
    Change 2: SLA breach count is pure-DB and excludes terminal tickets.

    Each test creates its own tickets; Django's TestCase rolls them back
    automatically, so tests are independent.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('soc_sla', UserProfile.ROLE_SOC_STAFF)

    def _get_sla_count(self):
        self.client.force_login(self.soc)
        return self.client.get(DASHBOARD_URL).context['stats']['sla_breaches']

    def test_overdue_active_ticket_is_counted(self):
        """An active ticket whose sla_deadline is in the past must be counted."""
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=-1)
        self.assertEqual(self._get_sla_count(), 1)

    def test_overdue_ticket_in_terminal_state_not_counted(self):
        """A terminal ticket whose sla_deadline is in the past must NOT be counted."""
        _make_ticket(status=Ticket.STATUS_APPROVED, sla_offset_hours=-1)
        self.assertEqual(self._get_sla_count(), 0)

    def test_overdue_closed_fp_ticket_not_counted(self):
        """CLOSED_FP is also a terminal state — must not appear in SLA breach count."""
        _make_ticket(status=Ticket.STATUS_CLOSED_FP, sla_offset_hours=-1)
        self.assertEqual(self._get_sla_count(), 0)

    def test_not_yet_due_active_ticket_not_counted(self):
        """An active ticket with sla_deadline still in the future must NOT be counted."""
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=24)
        self.assertEqual(self._get_sla_count(), 0)

    def test_mixed_tickets_only_active_overdue_counted(self):
        """Only the overdue-and-active subset contributes to the breach count."""
        _make_ticket(status=Ticket.STATUS_NEW,      sla_offset_hours=-2)   # counted
        _make_ticket(status=Ticket.STATUS_APPROVED, sla_offset_hours=-2)   # NOT counted (terminal)
        _make_ticket(status=Ticket.STATUS_NEW,      sla_offset_hours=48)   # NOT counted (future)
        self.assertEqual(self._get_sla_count(), 1)


# ── Metrics accuracy tests ───────────────────────────────────────────────── #

class DashboardMetricsTest(TestCase):
    """
    Change 3: active/closed split, FP/TP counts, and actionable backlog
    all match the known fixture data.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('soc_metrics', UserProfile.ROLE_SOC_STAFF)

    def _stats(self):
        self.client.force_login(self.soc)
        return self.client.get(DASHBOARD_URL).context['stats']

    # ── active / closed split ──────────────────────────────────────────── #

    def test_active_vs_closed_split(self):
        """active = non-terminal; closed = APPROVED + CLOSED_FP."""
        _make_ticket(status=Ticket.STATUS_NEW)                  # active
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT) # active
        _make_ticket(status=Ticket.STATUS_UNDER_REVIEW)         # active
        _make_ticket(status=Ticket.STATUS_APPROVED)             # closed (terminal)
        _make_ticket(status=Ticket.STATUS_CLOSED_FP)            # closed (terminal)

        s = self._stats()
        self.assertEqual(s['active'], 3)
        self.assertEqual(s['closed'], 2)
        self.assertEqual(s['total'],  5)

    def test_all_active_no_closed(self):
        _make_ticket(status=Ticket.STATUS_NEW)
        _make_ticket(status=Ticket.STATUS_VERIFIED)
        s = self._stats()
        self.assertEqual(s['active'], 2)
        self.assertEqual(s['closed'], 0)
        self.assertEqual(s['total'],  2)

    # ── FP/TP counts and percentages ───────────────────────────────────── #

    def test_tp_fp_counts_and_percentages(self):
        """2 TP + 1 FP → tp_pct=67, fp_pct=33."""
        _make_ticket(disposition=Ticket.DISP_TRUE_POSITIVE,  status=Ticket.STATUS_APPROVED)
        _make_ticket(disposition=Ticket.DISP_TRUE_POSITIVE,  status=Ticket.STATUS_APPROVED)
        _make_ticket(disposition=Ticket.DISP_FALSE_POSITIVE, status=Ticket.STATUS_CLOSED_FP)
        _make_ticket(status=Ticket.STATUS_NEW)  # no disposition — not counted in ratio

        s = self._stats()
        self.assertEqual(s['tp_count'], 2)
        self.assertEqual(s['fp_count'], 1)
        self.assertEqual(s['tp_pct'],  67)
        self.assertEqual(s['fp_pct'],  33)

    def test_tp_fp_zero_when_no_dispositions(self):
        """No tickets with a disposition → all zeros; no ZeroDivisionError."""
        _make_ticket(status=Ticket.STATUS_NEW)
        s = self._stats()
        self.assertEqual(s['tp_count'], 0)
        self.assertEqual(s['fp_count'], 0)
        self.assertEqual(s['tp_pct'],  0)
        self.assertEqual(s['fp_pct'],  0)

    def test_all_true_positive(self):
        """100% TP: fp_count=0, tp_pct=100, fp_pct=0."""
        _make_ticket(disposition=Ticket.DISP_TRUE_POSITIVE, status=Ticket.STATUS_APPROVED)
        s = self._stats()
        self.assertEqual(s['tp_count'], 1)
        self.assertEqual(s['fp_count'], 0)
        self.assertEqual(s['tp_pct'],  100)
        self.assertEqual(s['fp_pct'],  0)

    # ── Actionable backlog ─────────────────────────────────────────────── #

    def test_actionable_backlog_correct(self):
        """
        awaiting_admin   = AWAITING_CONTAINMENT count
        awaiting_soc     = CONTAINMENT_REPORTED + UNDER_REVIEW
        awaiting_manager = VERIFIED
        """
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT)  # → admin (×2)
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT)
        _make_ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED)  # → soc (×1)
        _make_ticket(status=Ticket.STATUS_UNDER_REVIEW)          # → soc (×1)
        _make_ticket(status=Ticket.STATUS_VERIFIED)              # → manager (×1)
        _make_ticket(status=Ticket.STATUS_NEW)                   # counted nowhere

        s = self._stats()
        self.assertEqual(s['awaiting_admin'],   2)
        self.assertEqual(s['awaiting_soc'],     2)
        self.assertEqual(s['awaiting_manager'], 1)

    def test_backlog_zero_when_no_tickets(self):
        """All backlog counters are 0 when there are no tickets."""
        s = self._stats()
        self.assertEqual(s['awaiting_admin'],   0)
        self.assertEqual(s['awaiting_soc'],     0)
        self.assertEqual(s['awaiting_manager'], 0)
