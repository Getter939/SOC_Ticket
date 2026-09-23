"""Tier 2 queue (คิวงาน Tier 2) — views, filters, ordering and paging.

Moved here from apps/wazuh_ingest/tests.py on 2026-09-23 along with the views;
the page is ticket code and never touched a WazuhAlert.
"""
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase

from .models import Ticket


def _make_user(username, role, department='Test', phone='000', tier=''):
    user = User.objects.create_user(username=username, password='testpass123')
    UserProfile.objects.create(
        user=user, role=role, department=department, phone=phone, tier=tier)
    return user


class EscalationQueueTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1_analyst = _make_user('esc_t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.t2_analyst = _make_user('esc_t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.t2_analyst2 = _make_user('esc_t2_other', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.manager = _make_user('esc_mgr', UserProfile.ROLE_SOC_MANAGER)

    def setUp(self):
        self.ticket = Ticket.objects.create(
            device_name='ESCALATED-ENDPOINT',
            ip_address='192.0.2.77',
            issue_description='Suspicious PowerShell execution',
            severity='Critical',
            classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_ESCALATED_T2,
            created_by=self.t1_analyst,
            escalated_to_t2_at=timezone.now(),
        )

    def test_t2_sees_ticket_escalated_to_t2(self):
        self.client.login(username='esc_t2', password='testpass123')
        response = self.client.get(reverse('escalation_queue'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Suspicious PowerShell execution')
        self.assertContains(response, self.ticket.ticket_id)

    def test_t1_is_redirected_from_tier2_queue(self):
        self.client.login(username='esc_t1', password='testpass123')
        response = self.client.get(reverse('escalation_queue'))
        self.assertRedirects(response, reverse('ticket_list'))

    def test_manager_is_redirected_from_tier2_queue(self):
        self.client.login(username='esc_mgr', password='testpass123')
        response = self.client.get(reverse('escalation_queue'))
        self.assertRedirects(response, reverse('ticket_list'))

    def test_unclaimed_ticket_offers_claim_but_not_release(self):
        self.client.login(username='esc_t2', password='testpass123')
        response = self.client.get(reverse('escalation_queue'))
        self.assertContains(response, reverse('claim_escalation'))
        self.assertNotContains(response, reverse('release_escalation'))

    def test_claim_takes_the_ticket_and_offers_release(self):
        self.client.login(username='esc_t2', password='testpass123')
        self.client.post(reverse('claim_escalation'), {'ticket_id': self.ticket.pk})

        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.t2_claimed_by.username, 'esc_t2')
        self.assertIsNotNone(self.ticket.t2_claimed_at)

        response = self.client.get(reverse('escalation_queue'))
        self.assertContains(response, reverse('release_escalation'))

    def test_second_analyst_cannot_claim_a_claimed_ticket(self):
        self.client.login(username='esc_t2', password='testpass123')
        self.client.post(reverse('claim_escalation'), {'ticket_id': self.ticket.pk})

        self.client.login(username='esc_t2_other', password='testpass123')
        self.client.post(reverse('claim_escalation'), {'ticket_id': self.ticket.pk})

        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.t2_claimed_by, self.t2_analyst)

    def test_release_requires_a_reason_and_returns_it_to_the_queue(self):
        self.client.login(username='esc_t2', password='testpass123')
        self.client.post(reverse('claim_escalation'), {'ticket_id': self.ticket.pk})

        self.client.post(reverse('release_escalation'), {'ticket_id': self.ticket.pk})
        self.ticket.refresh_from_db()
        self.assertIsNotNone(self.ticket.t2_claimed_by, 'no reason given — claim must hold')

        self.client.post(reverse('release_escalation'), {
            'ticket_id': self.ticket.pk, 'release_reason': 'ต้องส่งต่อให้ทีมอื่น',
        })
        self.ticket.refresh_from_db()
        self.assertIsNone(self.ticket.t2_claimed_by)
        self.assertIsNone(self.ticket.t2_claimed_at)

    def _claim_for(self, user):
        self.ticket.t2_claimed_by = user
        self.ticket.t2_claimed_at = timezone.now()
        self.ticket.save(update_fields=['t2_claimed_by', 't2_claimed_at'])

    def test_another_analysts_claim_blocks_the_transition(self):
        self._claim_for(self.t2_analyst)
        with self.assertRaises(ValidationError):
            self.ticket.transition_to(Ticket.STATUS_MONITORING, self.t2_analyst2)

    def test_unclaimed_ticket_stays_actionable(self):
        # Tier 2 also works straight from ticket detail, which has no claim
        # button — an unclaimed ticket must not be locked out.
        self.ticket.transition_to(Ticket.STATUS_MONITORING, self.t2_analyst)
        self.assertEqual(self.ticket.status, Ticket.STATUS_MONITORING)

    def test_claim_holder_may_transition(self):
        self._claim_for(self.t2_analyst)
        self.ticket.transition_to(Ticket.STATUS_MONITORING, self.t2_analyst)
        self.assertEqual(self.ticket.status, Ticket.STATUS_MONITORING)

    def test_claim_is_cleared_when_the_ticket_moves_stage(self):
        self._claim_for(self.t2_analyst)
        self.ticket.transition_to(Ticket.STATUS_MONITORING, self.t2_analyst)

        self.ticket.refresh_from_db()
        self.assertIsNone(self.ticket.t2_claimed_by)
        self.assertIsNone(self.ticket.t2_claimed_at)


class EscalationQueueFilterTest(TestCase):
    """Filtering, ordering and paging of the Tier 2 queue.

    Order is read from ``response.context['tickets']`` rather than the HTML, so a
    markup change cannot silently turn an ordering assertion green.
    """

    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_user('flt_t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.t2 = _make_user('flt_t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.t2_other = _make_user(
            'flt_t2_other', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)

    def setUp(self):
        self.client.login(username='flt_t2', password='testpass123')
        self._age = 0

    def _ticket(self, *, severity='High', status=None, claimed_by=None,
                is_emergency=False, device_name=None):
        """Create one queue ticket.

        status_changed_at is set explicitly and staggered: Ticket.save() only
        seeds it when absent, and it is the tie-breaker in every sort. Creating
        with status= bypasses transition_to, so a fixture claim survives.
        """
        self._age += 1
        ticket = Ticket.objects.create(
            device_name=device_name or 'HOST-%02d' % self._age,
            ip_address='192.0.2.%d' % self._age,
            issue_description='fixture %d' % self._age,
            severity=severity,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            status=status or Ticket.STATUS_ESCALATED_T2,
            created_by=self.t1,
            is_emergency=is_emergency,
            status_changed_at=timezone.now() - timedelta(minutes=self._age),
        )
        if claimed_by is not None:
            ticket.t2_claimed_by = claimed_by
            ticket.t2_claimed_at = timezone.now()
            ticket.save(update_fields=['t2_claimed_by', 't2_claimed_at'])
        return ticket

    def _get(self, **params):
        return self.client.get(reverse('escalation_queue'), params)

    def _rows(self, response):
        return list(response.context['tickets'])

    # ── Filter pills / facet counts ──────────────────────────────────── #

    @staticmethod
    def _facet(response, group, key):
        return next(
            f for f in response.context['%s_facets' % group] if f['key'] == key
        )

    def test_stage_facets_count_each_stage(self):
        """The stage split was previously unknowable without filtering three
        times — the pills carry it on every page load."""
        self._ticket(status=Ticket.STATUS_ESCALATED_T2)
        self._ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED)
        self._ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED)
        self._ticket(status=Ticket.STATUS_PENDING_T2_REVIEW)

        r = self._get()
        self.assertEqual(self._facet(r, 'stage', None)['count'], 4)
        self.assertEqual(self._facet(r, 'stage', 'escalated')['count'], 1)
        self.assertEqual(self._facet(r, 'stage', 'containment')['count'], 2)
        self.assertEqual(self._facet(r, 'stage', 'owner')['count'], 1)

    def test_claim_facets_count_pickable_and_mine(self):
        self._ticket()
        self._ticket(claimed_by=self.t2)
        self._ticket(claimed_by=self.t2_other)

        r = self._get()
        self.assertEqual(self._facet(r, 'claim', None)['count'], 3)
        self.assertEqual(self._facet(r, 'claim', 'unclaimed')['count'], 1)
        self.assertEqual(self._facet(r, 'claim', 'mine')['count'], 1)

    def test_facets_are_scoped_by_the_other_filter(self):
        """Each pill counts what you would get by clicking it, so the claim
        counts narrow once a stage is selected — and vice versa."""
        self._ticket(status=Ticket.STATUS_ESCALATED_T2, claimed_by=self.t2)
        self._ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED)
        self._ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED)

        scoped = self._get(stage='containment')
        self.assertEqual(self._facet(scoped, 'claim', None)['count'], 2)
        self.assertEqual(self._facet(scoped, 'claim', 'mine')['count'], 0)
        # The stage row itself stays whole-queue, so you can always navigate out.
        self.assertEqual(self._facet(scoped, 'stage', None)['count'], 3)

        mine = self._get(claim='mine')
        self.assertEqual(self._facet(mine, 'stage', None)['count'], 1)
        self.assertEqual(self._facet(mine, 'stage', 'containment')['count'], 0)

    def test_active_facet_is_flagged(self):
        self._ticket()
        r = self._get(stage='escalated')
        self.assertTrue(self._facet(r, 'stage', 'escalated')['active'])
        self.assertFalse(self._facet(r, 'stage', None)['active'])
        # Claim untouched, so its "all" pill is the active one.
        self.assertTrue(self._facet(r, 'claim', None)['active'])

    def test_invalid_filter_values_fall_back_to_all(self):
        self._ticket()
        r = self._get(stage='bogus', claim='bogus')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self._facet(r, 'stage', None)['active'])
        self.assertTrue(self._facet(r, 'claim', None)['active'])
        self.assertEqual(len(self._rows(r)), 1)

    # ── Severity sort (the CharField-ordering bug) ───────────────────────── #

    def test_severity_sort_ranks_medium_above_low(self):
        # The exact regression: ordering the raw CharField is alphabetical, so
        # 'Low' < 'Medium' and Low floated above Medium.
        low = self._ticket(severity='Low')
        medium = self._ticket(severity='Medium')
        rows = self._rows(self._get(sort='severity'))
        self.assertLess(rows.index(medium), rows.index(low))

    def test_severity_sort_puts_critical_first_and_unknown_last(self):
        critical = self._ticket(severity='Critical')
        high = self._ticket(severity='High')
        medium = self._ticket(severity='Medium')
        low = self._ticket(severity='Low')
        unknown = self._ticket(severity='Unknown')
        self.assertEqual(
            self._rows(self._get(sort='severity')),
            [critical, high, medium, low, unknown],
        )

    def test_severity_sort_breaks_ties_by_newest_in_stage(self):
        older = self._ticket(severity='High')   # status_changed_at -1 min
        newer = self._ticket(severity='High')   # -2 min → older in wall time
        rows = self._rows(self._get(sort='severity'))
        # _ticket staggers backwards, so the FIRST created is the most recent.
        self.assertEqual(rows, [older, newer])

    # ── Claim filter ─────────────────────────────────────────────────────── #

    def test_unclaimed_filter_excludes_claimed_tickets(self):
        free = self._ticket()
        taken = self._ticket(claimed_by=self.t2)
        rows = self._rows(self._get(claim='unclaimed'))
        self.assertIn(free, rows)
        self.assertNotIn(taken, rows)

    def test_mine_filter_shows_only_my_claims(self):
        mine = self._ticket(claimed_by=self.t2)
        theirs = self._ticket(claimed_by=self.t2_other)
        free = self._ticket()
        self.assertEqual(self._rows(self._get(claim='mine')), [mine])
        for other in (theirs, free):
            self.assertNotIn(other, self._rows(self._get(claim='mine')))

    def test_mine_filter_is_per_user(self):
        mine = self._ticket(claimed_by=self.t2)
        theirs = self._ticket(claimed_by=self.t2_other)

        self.assertEqual(self._rows(self._get(claim='mine')), [mine])
        self.client.login(username='flt_t2_other', password='testpass123')
        self.assertEqual(self._rows(self._get(claim='mine')), [theirs])

    def test_invalid_claim_value_is_ignored(self):
        free = self._ticket()
        taken = self._ticket(claimed_by=self.t2_other)
        response = self._get(claim='bogus')
        self.assertEqual(response.context['claim_filter'], '')
        self.assertCountEqual(self._rows(response), [free, taken])

    # ── Emergency filter removal ─────────────────────────────────────────── #

    def test_emergency_param_no_longer_hides_tickets(self):
        # The dead param must not suppress urgent work: ?emergency=0 used to
        # hide every emergency from the Tier 2 queue.
        urgent = self._ticket(is_emergency=True)
        normal = self._ticket()
        self.assertCountEqual(self._rows(self._get(emergency='0')), [urgent, normal])
        self.assertCountEqual(self._rows(self._get(emergency='1')), [urgent, normal])

    def test_emergency_filter_control_is_gone(self):
        self._ticket()
        response = self._get()
        self.assertNotContains(response, 'เฉพาะเคสปกติ')
        self.assertNotContains(response, 'name="emergency"')

    def test_emergency_signal_survives_as_stripe_and_flag(self):
        # The filter's replacement: the row is still visually unmissable.
        # The signal is the shared accent stripe every other ticket table uses,
        # not the full-row table-danger flood this queue used to paint alone.
        self._ticket(is_emergency=True)
        response = self._get()
        self.assertContains(response, 'is-emergency')
        self.assertContains(response, 'emg-flag')
        self.assertNotContains(response, 'table-danger')
        self.assertContains(response, '>ฉุกเฉิน<')

    # ── Stage filter and the other sorts ─────────────────────────────────── #

    def test_stage_filter_narrows_to_one_status(self):
        escalated = self._ticket(status=Ticket.STATUS_ESCALATED_T2)
        contained = self._ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED)
        owner = self._ticket(status=Ticket.STATUS_PENDING_T2_REVIEW)

        self.assertEqual(self._rows(self._get(stage='containment')), [contained])
        self.assertCountEqual(
            self._rows(self._get()), [escalated, contained, owner])

    def test_invalid_sort_falls_back_to_default(self):
        normal = self._ticket()
        urgent = self._ticket(is_emergency=True)
        response = self._get(sort='bogus')
        self.assertEqual(response.context['sort'], 'emergency')
        self.assertEqual(self._rows(response)[0], urgent)
        self.assertIn(normal, self._rows(response))

    def test_default_sort_puts_emergency_first(self):
        self._ticket()
        urgent = self._ticket(is_emergency=True)
        self.assertEqual(self._rows(self._get())[0], urgent)

    def test_ola_sort_puts_nulls_last(self):
        # Medium/Low get no contain deadline, so they belong below anything on
        # a clock rather than sorting first as SQL NULLs otherwise would.
        no_deadline = self._ticket(severity='Medium')
        on_clock = self._ticket(severity='Critical')
        self.assertIsNone(no_deadline.ola_contain_deadline)
        self.assertIsNotNone(on_clock.ola_contain_deadline)
        self.assertEqual(self._rows(self._get(sort='ola')), [on_clock, no_deadline])

    # ── Pagination ───────────────────────────────────────────────────────── #

    def test_second_page_is_reachable(self):
        for _ in range(26):
            self._ticket()
        response = self._get(page=2)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['page_obj'].number, 2)
        self.assertEqual(len(self._rows(response)), 1)

    def test_pagination_link_preserves_active_filters(self):
        for _ in range(26):
            self._ticket(status=Ticket.STATUS_ESCALATED_T2)
        response = self._get(stage='escalated', claim='unclaimed', sort='newest')
        self.assertContains(response, 'page=2')
        # {% querystring %} must carry every active param onto the next page.
        for param in ('stage=escalated', 'claim=unclaimed', 'sort=newest'):
            self.assertContains(response, param)

    # ── Filter-bar chrome ────────────────────────────────────────────────── #

    def test_clear_filters_link_only_shows_while_filtering(self):
        self._ticket()
        self.assertNotContains(self._get(), 'ล้างตัวกรองทั้งหมด')
        self.assertContains(self._get(claim='mine'), 'ล้างตัวกรองทั้งหมด')
        self.assertContains(self._get(stage='escalated'), 'ล้างตัวกรองทั้งหมด')

    def test_count_badge_reflects_active_filters(self):
        self._ticket(claimed_by=self.t2)
        self._ticket()
        self._ticket()
        self.assertEqual(self._get().context['escalated_count'], 3)
        self.assertEqual(self._get(claim='mine').context['escalated_count'], 1)

    def test_empty_state_distinguishes_filtered_from_empty_queue(self):
        self.assertContains(self._get(), 'ไม่มี Ticket ที่รอ Tier 2')
        self._ticket(claimed_by=self.t2_other)
        self.assertContains(self._get(claim='mine'), 'ไม่พบ Ticket ที่ตรงกับเงื่อนไข')


class Tier2QueueSuperuserAccessTest(TestCase):
    """A superuser has no UserProfile, so every tier gate must special-case them."""

    @classmethod
    def setUpTestData(cls):
        cls.superuser = User.objects.create_superuser(
            username='t2q_superuser',
            email='t2q-super@example.com',
            password='testpass123',
        )

    def setUp(self):
        self.client.force_login(self.superuser)

    def test_superuser_sees_ticket_escalation_queue(self):
        ticket = Ticket.objects.create(
            device_name='SUPERUSER-ESCALATION',
            ip_address='192.0.2.88',
            issue_description='Escalated ticket visible to superuser.',
            severity='High',
            classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_ESCALATED_T2,
            escalated_to_t2_at=timezone.now(),
        )
        response = self.client.get(reverse('escalation_queue'))
        self.assertEqual(response.status_code, 200)
        self.assertIn(ticket, list(response.context['tickets']))


class LegacyWazuhUrlRedirectTest(TestCase):
    """The page answered at /wazuh/escalation_queue/ until 2026-09-23.

    Analysts bookmark a queue they open every shift, so the old path still
    redirects — permanently, and carrying the filters.
    """

    @classmethod
    def setUpTestData(cls):
        cls.t2 = _make_user(
            'legacy_t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)

    def setUp(self):
        self.client.force_login(self.t2)

    def test_old_path_redirects_permanently_to_the_new_one(self):
        response = self.client.get('/wazuh/escalation_queue/')
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response.url, reverse('escalation_queue'))

    def test_redirect_preserves_the_query_string(self):
        response = self.client.get(
            '/wazuh/escalation_queue/?stage=containment&claim=mine')
        self.assertEqual(response.status_code, 301)
        self.assertIn('stage=containment', response.url)
        self.assertIn('claim=mine', response.url)

    def test_the_queue_now_lives_under_incidents(self):
        self.assertEqual(reverse('escalation_queue'), '/incidents/tier2-queue/')
