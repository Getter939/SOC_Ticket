"""
Tests for the seed_response_demo management command.

The command runs against environments holding REAL staff accounts, so the
safety properties matter as much as the data it writes:
  - it must never create, modify or unlock a user account (passwords especially)
  - it must attribute data to whoever actually holds each role
  - it must refuse to run (naming the gap) when a required role is unfilled,
    rather than inventing an account
  - it must degrade gracefully when the optional Red Team Manager role is unfilled
"""

from io import StringIO

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketSubtask
from apps.incidents.tests import (
    _make_user, _make_t1, _make_t2, _make_forensic, _make_redteam_manager,
)

MARKER = '[RESPONSE-DEMO]'


class ResponseDemoSeedTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.forensic = _make_forensic('rd_forensic')
        cls.manager = _make_user('rd_manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('rd_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.t1a = _make_t1('rd_t1a')
        cls.t1b = _make_t1('rd_t1b')
        cls.t2 = _make_t2('rd_t2')

    def _call(self, *args):
        out, err = StringIO(), StringIO()
        call_command('seed_response_demo', *args, stdout=out, stderr=err)
        return out.getvalue()

    def _demo(self):
        return Ticket.objects.filter(issue_description__contains=MARKER)

    # ── safety: never touches accounts ───────────────────────────────────── #

    def test_creates_no_user_accounts(self):
        before = set(User.objects.values_list('pk', flat=True))
        self._call()
        self.assertEqual(set(User.objects.values_list('pk', flat=True)), before)

    def test_does_not_change_passwords(self):
        before = {u.pk: u.password for u in User.objects.all()}
        self._call()
        after = {u.pk: u.password for u in User.objects.all()}
        self.assertEqual(after, before)

    def test_dry_run_writes_nothing(self):
        output = self._call('--dry-run')
        self.assertEqual(self._demo().count(), 0)
        self.assertIn('Dry run', output)
        self.assertIn(self.forensic.username, output)

    # ── attribution to the real role-holders ─────────────────────────────── #

    def test_requests_go_to_the_real_forensic_analyst(self):
        self._call()
        requests = TicketSubtask.objects.filter(
            ticket__in=self._demo(), subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
        )
        self.assertTrue(requests.exists())
        self.assertEqual({r.assigned_to for r in requests}, {self.forensic})
        # The SOC Manager is recorded as the requester.
        self.assertEqual({r.created_by for r in requests}, {self.manager})

    def test_authorship_is_spread_across_tier1_analysts(self):
        self._call()
        authors = set(self._demo().values_list('created_by__username', flat=True))
        self.assertEqual(authors, {self.t1a.username, self.t1b.username})

    def test_seeded_tickets_are_visible_to_the_forensic_analyst(self):
        self._call()
        visible = Ticket.objects.visible_to(self.forensic)
        self.assertEqual(visible.count(), self._demo().count())

    # ── graceful degradation / refusal ───────────────────────────────────── #

    def test_skips_red_team_when_role_unfilled(self):
        output = self._call()
        self.assertFalse(
            TicketSubtask.objects.filter(
                subtask_type__in=(TicketSubtask.TYPE_VA_PT, TicketSubtask.TYPE_INFRA_SEC),
            ).exists()
        )
        self.assertIn('Skipped', output)

    def test_includes_red_team_once_role_is_filled(self):
        redteam = _make_redteam_manager('rd_redteam')
        self._call()
        rt = TicketSubtask.objects.filter(
            subtask_type__in=(TicketSubtask.TYPE_VA_PT, TicketSubtask.TYPE_INFRA_SEC),
        )
        self.assertEqual(rt.count(), 2)
        self.assertEqual({r.assigned_to for r in rt}, {redteam})

    def test_refuses_when_forensic_role_unfilled(self):
        User.objects.filter(pk=self.forensic.pk).update(is_active=False)
        with self.assertRaises(CommandError) as ctx:
            self._call()
        self.assertIn('Forensic Analyst', str(ctx.exception))
        self.assertEqual(self._demo().count(), 0)

    def test_refuses_when_manager_role_unfilled(self):
        User.objects.filter(pk=self.manager.pk).update(is_active=False)
        with self.assertRaises(CommandError):
            self._call()

    # ── idempotency ──────────────────────────────────────────────────────── #

    def test_flush_removes_only_its_own_rows(self):
        keeper = Ticket.objects.create(
            device_name='REAL-HOST', ip_address='10.0.0.9',
            issue_description='A real tester ticket',
        )
        self._call()
        seeded = self._demo().count()
        self.assertTrue(seeded)

        self._call('--flush')
        self.assertEqual(self._demo().count(), seeded)  # re-seeded, not doubled
        self.assertTrue(Ticket.objects.filter(pk=keeper.pk).exists())

    def test_flush_no_seed_wipes_only(self):
        self._call()
        self.assertTrue(self._demo().exists())
        self._call('--flush', '--no-seed')
        self.assertEqual(self._demo().count(), 0)

    def test_gate_demo_blocks_approval(self):
        """The emergency scenario must genuinely hold its ticket out of closure."""
        self._call()
        gated = self._demo().filter(status=Ticket.STATUS_PENDING_MANAGER).first()
        self.assertIsNotNone(gated)
        self.assertTrue(gated.is_emergency)
        self.assertTrue(gated.has_open_response_requests)
        self.assertFalse(gated.can_transition_to(Ticket.STATUS_APPROVED))
