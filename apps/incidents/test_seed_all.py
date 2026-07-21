"""
Tests for the seed_all orchestration command.

The purge is the risky half: user FKs on Ticket are SET_NULL, so removing a
legacy account before its tickets would silently orphan those rows instead of
deleting them. These tests pin that ordering, and that real staff accounts and
tester-created tickets are never touched.
"""

from io import StringIO

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket
from apps.incidents.tests import (
    _make_user, _make_t1, _make_t2, _make_forensic,
)


class SeedAllTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Real staff — must survive everything.
        cls.t1 = _make_t1('real_t1')
        cls.t2 = _make_t2('real_t2')
        cls.manager = _make_user('real_mgr', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('real_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.forensic = _make_forensic('real_forensic')

    def _call(self, *args):
        out = StringIO()
        call_command('seed_all', *args, stdout=out, stderr=StringIO())
        return out.getvalue()

    def _legacy_user(self, username):
        return _make_t1(username)

    # ── purge ────────────────────────────────────────────────────────────── #

    def test_dry_run_writes_nothing(self):
        legacy = self._legacy_user('uat_t1')
        output = self._call('--dry-run')
        self.assertIn('Dry run', output)
        self.assertTrue(User.objects.filter(pk=legacy.pk).exists())

    def test_purges_legacy_accounts(self):
        for name in ('uat_t1', 'seed_manager', 'surapong'):
            self._legacy_user(name)
        self._call('--purge-only')
        for name in ('uat_t1', 'seed_manager', 'surapong'):
            self.assertFalse(User.objects.filter(username=name).exists(), name)

    def test_keeps_real_staff(self):
        self._call('--purge-only')
        for user in (self.t1, self.t2, self.manager, self.admin, self.forensic):
            self.assertTrue(User.objects.filter(pk=user.pk).exists(), user.username)

    def test_never_deletes_a_superuser_even_if_named_like_a_legacy_account(self):
        su = User.objects.create_superuser('uat_admin', 'su@x.local', 'pw')
        self._call('--purge-only')
        self.assertTrue(User.objects.filter(pk=su.pk).exists())

    def test_legacy_tickets_are_deleted_not_orphaned(self):
        """The ordering guarantee: rows go before their authors."""
        legacy = self._legacy_user('uat_t1')
        Ticket.objects.create(
            ticket_id='LEGACY-1', device_name='H', ip_address='10.0.0.1',
            issue_description='old seed row', created_by=legacy,
        )
        self._call('--purge-only')
        self.assertFalse(Ticket.objects.filter(ticket_id='LEGACY-1').exists())
        self.assertEqual(Ticket.objects.filter(created_by__isnull=True).count(), 0)

    def test_mock_named_author_tickets_are_deleted_not_orphaned(self):
        """Regression: mock-name accounts were purged without their tickets."""
        mock = self._legacy_user('kamjad')
        Ticket.objects.create(
            ticket_id='LEGACY-2', device_name='H', ip_address='10.0.0.2',
            issue_description='mock-authored row', created_by=mock,
        )
        self._call('--purge-only')
        self.assertFalse(Ticket.objects.filter(ticket_id='LEGACY-2').exists())
        self.assertEqual(Ticket.objects.filter(created_by__isnull=True).count(), 0)

    def test_tester_ticket_survives(self):
        keeper = Ticket.objects.create(
            ticket_id='TESTER-1', device_name='H', ip_address='10.0.0.3',
            issue_description='a real tester ticket', created_by=self.t1,
        )
        self._call('--purge-only')
        self.assertTrue(Ticket.objects.filter(pk=keeper.pk).exists())

    def test_keep_legacy_users_flag(self):
        legacy = self._legacy_user('uat_t1')
        self._call('--keep-legacy-users')
        self.assertTrue(User.objects.filter(pk=legacy.pk).exists())

    # ── reseed ───────────────────────────────────────────────────────────── #

    def test_full_run_reseeds_and_creates_no_accounts(self):
        before = {u.pk: u.password for u in User.objects.all()}
        output = self._call()
        self.assertIn('All seed datasets regenerated', output)
        self.assertTrue(Ticket.objects.exists())
        # Nothing created, nothing re-passworded.
        self.assertEqual({u.pk: u.password for u in User.objects.all()}, before)

    def test_seeded_data_is_attributed_to_real_staff_only(self):
        self._call()
        authors = set(
            Ticket.objects.exclude(created_by__isnull=True)
            .values_list('created_by__username', flat=True)
        )
        real = {self.t1.username, self.t2.username, self.manager.username,
                self.admin.username, self.forensic.username}
        self.assertTrue(authors <= real, authors - real)

    def test_no_uat_or_seed_accounts_exist_afterwards(self):
        for name in ('uat_t1', 'uat_forensic', 'seed_t1', 'natt'):
            self._legacy_user(name)
        self._call()
        leftover = User.objects.filter(
            username__startswith='uat_',
        ) | User.objects.filter(username__startswith='seed_')
        self.assertFalse(leftover.exists(), list(leftover))
