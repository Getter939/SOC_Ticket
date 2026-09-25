"""Ticket History and Active Tickets list controls.

History: searches the same fields as Active Tickets, names who closed every
terminal ticket (not only APPROVED ones), keeps filters across pill and page
links, counts each result pill within the current filters, and orders by the
close date it shows. Active Tickets: an optional วันที่แจ้ง range with quick
presets that the Manager Queue (same renderer) does not get.
"""

from datetime import timedelta

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase
from apps.incidents.models import Ticket, TicketLog
from apps.incidents.test_ticket_workflow import _ticket, _user
from apps.incidents.ticket_workflow import cancellation_action


def _days_ago(days):
    return timezone.now() - timedelta(days=days)


def _backdate(ticket, days):
    Ticket.objects.filter(pk=ticket.pk).update(created_at=_days_ago(days))


def _closed_event(closer, **kwargs):
    ticket = _ticket(status=Ticket.STATUS_CLOSED_EVENT,
                     classification=Ticket.CLASSIFICATION_EVENT,
                     closed_at=timezone.now(), **kwargs)
    TicketLog.objects.create(ticket=ticket, author=closer, note='ปิดเป็น Event',
                             status_at_time=Ticket.STATUS_CLOSED_EVENT)
    return ticket


def _approved(approver, **kwargs):
    now = timezone.now()
    return _ticket(status=Ticket.STATUS_APPROVED, approved_by=approver,
                   approved_at=now, closed_at=now, **kwargs)


class TicketHistoryTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user('hist-t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.t2 = _user('hist-t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.manager = _user('hist-mgr', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _user('hist-admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def setUp(self):
        self.client.force_login(self.manager)

    def _get(self, **params):
        return self.client.get(reverse('ticket_history'), params)

    def _ids(self, response):
        return [ticket.pk for ticket in response.context['tickets']]

    def test_search_matches_the_case_name_shown_on_screen(self):
        named = _approved(self.manager, incident_name='Ransomware on finance share')
        _approved(self.manager, incident_name='Phishing wave')
        response = self._get(q='ransomware')
        self.assertEqual(self._ids(response), [named.pk])

    def test_old_search_ticket_param_still_works(self):
        ticket = _approved(self.manager)
        response = self._get(search_ticket=ticket.ticket_id)
        self.assertEqual(self._ids(response), [ticket.pk])

    def test_closer_is_named_for_event_and_cancelled_tickets(self):
        event = _closed_event(self.t2)
        cancelled = _ticket(created_by=self.t1, assigned_admin=self.admin,
                            status=Ticket.STATUS_AWAITING_CONTAINMENT, severity='High')
        record = cancellation_action(ticket=cancelled, actor=self.t1, action='request',
                                     reason='CREATED_IN_ERROR', explanation='สร้างผิด')
        cancellation_action(ticket=cancelled, actor=self.manager, action='approve',
                            request_id=record.pk, decision_note='อนุมัติ')
        cancelled.refresh_from_db()
        self.assertEqual(cancelled.status, Ticket.STATUS_CANCELLED)
        self.assertIsNone(cancelled.approved_by)

        closers = {t.pk: t.closer for t in self._get().context['tickets']}
        self.assertEqual(closers[event.pk], self.t2)
        self.assertEqual(closers[cancelled.pk], self.manager)

    def test_approver_filter_finds_an_event_by_its_closer(self):
        event = _closed_event(self.t2)
        _approved(self.manager)
        response = self._get(approved_by=str(self.t2.pk))
        self.assertEqual(self._ids(response), [event.pk])
        self.assertIn(self.t2, response.context['approver_choices'])

    def test_approver_choices_only_list_closers_of_visible_tickets(self):
        other_manager = _user('hist-mgr2', UserProfile.ROLE_SOC_MANAGER)
        _approved(self.manager, assigned_admin=self.admin)
        _approved(other_manager)
        self.client.force_login(self.admin)
        choices = list(self._get().context['approver_choices'])
        self.assertEqual(choices, [self.manager])

    def test_pill_links_keep_filters_and_encode_the_search(self):
        _approved(self.manager, severity='High')
        response = self._get(q='a&b', severity='High', start_date='2020-01-01',
                             end_date='2030-12-31')
        content = response.content.decode()
        self.assertIn('status=APPROVED', content)
        self.assertIn('q=a%26b', content)
        self.assertNotIn('q=a&b', content)
        # The APPROVED pill carries the other filters along.
        self.assertRegex(
            content,
            r'href="\?[^"]*severity=High[^"]*start_date=2020-01-01[^"]*status=APPROVED',
        )

    def test_a_lone_date_bound_filters(self):
        old = _approved(self.manager)
        new = _approved(self.manager)
        _backdate(old, 60)
        cutoff = timezone.localdate() - timedelta(days=30)
        self.assertEqual(self._ids(self._get(start_date=cutoff.isoformat())), [new.pk])
        self.assertEqual(self._ids(self._get(end_date=cutoff.isoformat())), [old.pk])

    def test_invalid_status_is_cleared(self):
        response = self._get(status='BOGUS')
        self.assertEqual(response.context['status_filter'], '')

    def test_pill_counts_follow_the_date_range_and_other_filters(self):
        _approved(self.manager)
        _approved(self.manager, severity='Low')
        _backdate(_closed_event(self.t2), 70)  # outside the default month

        pills = {p['code']: p['count'] for p in self._get().context['status_pills']}
        self.assertEqual(pills, {'': 2, Ticket.STATUS_APPROVED: 2,
                                 Ticket.STATUS_CLOSED_EVENT: 0, Ticket.STATUS_CANCELLED: 0})

        pills = {p['code']: p['count']
                 for p in self._get(all_time='1', severity='Low').context['status_pills']}
        self.assertEqual(pills[''], 1)

        # The result pill itself doesn't shrink the other pills' counts.
        pills = {p['code']: p['count']
                 for p in self._get(all_time='1', status='APPROVED').context['status_pills']}
        self.assertEqual(pills[Ticket.STATUS_CLOSED_EVENT], 1)

    def test_default_sort_is_newest_close_first(self):
        closed_earlier = _approved(self.manager)
        closed_later = _approved(self.manager)
        Ticket.objects.filter(pk=closed_earlier.pk).update(
            closed_at=_days_ago(2), updated_at=timezone.now())
        Ticket.objects.filter(pk=closed_later.pk).update(
            closed_at=_days_ago(1), updated_at=_days_ago(5))
        response = self._get()
        self.assertEqual(response.context['sort'], 'closed')
        self.assertEqual(self._ids(response), [closed_later.pk, closed_earlier.pk])
        self.assertEqual(self._ids(self._get(sort='closed_oldest')),
                         [closed_earlier.pk, closed_later.pk])

    def test_table_shows_close_date_not_opening_date(self):
        _approved(self.manager)
        response = self._get()
        content = response.content.decode()
        labels = [header['label'] for header in response.context['sort_headers']]
        self.assertIn('วันที่ปิด', labels)
        self.assertNotIn('วันที่แจ้ง', labels)
        # The range is by opening date, which the table no longer shows, so
        # the control itself is labelled with it.
        self.assertIn('id="filter-date-label">วันที่แจ้ง<', content)

    def test_query_count_does_not_grow_with_rows(self):
        def count_queries():
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self._get().status_code, 200)
            return len(ctx.captured_queries)

        _approved(self.manager)
        one_row = count_queries()
        for index in range(4):
            _approved(_user(f'hist-approver-{index}', UserProfile.ROLE_SOC_MANAGER))
        self.assertEqual(count_queries(), one_row)


class ActiveTicketsDateFilterTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t2 = _user('active-t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.manager = _user('active-mgr', UserProfile.ROLE_SOC_MANAGER)

    def setUp(self):
        self.client.force_login(self.t2)

    def _ids(self, response):
        return {ticket.pk for ticket in response.context['tickets']}

    def test_no_range_shows_every_open_ticket(self):
        old = _ticket()
        _backdate(old, 120)
        new = _ticket()
        response = self.client.get(reverse('ticket_list'))
        self.assertEqual(self._ids(response), {old.pk, new.pk})
        self.assertEqual(response.context['start_date'], '')

    def test_range_filters_on_opening_date_and_lone_bounds_work(self):
        old = _ticket()
        _backdate(old, 60)
        new = _ticket()
        cutoff = (timezone.localdate() - timedelta(days=30)).isoformat()
        url = reverse('ticket_list')
        self.assertEqual(self._ids(self.client.get(url, {'start_date': cutoff})), {new.pk})
        self.assertEqual(self._ids(self.client.get(url, {'end_date': cutoff})), {old.pk})

    def test_malformed_dates_are_ignored(self):
        ticket = _ticket()
        response = self.client.get(reverse('ticket_list'),
                                   {'start_date': '2026-02-31', 'end_date': 'nope'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._ids(response), {ticket.pk})

    def test_presets_render_and_the_active_one_is_marked(self):
        today = timezone.localdate().isoformat()
        response = self.client.get(reverse('ticket_list'),
                                   {'start_date': today, 'end_date': today, 'severity': 'High'})
        presets = response.context['date_presets']
        self.assertEqual([p['label'] for p in presets], ['วันนี้', '7 วัน', '30 วัน', 'เดือนนี้'])
        self.assertEqual([p['active'] for p in presets], [True, False, False, False])
        # Preset links keep the other filters.
        self.assertIn('severity=High', response.content.decode())

    def test_pagination_keeps_the_date_range(self):
        for _ in range(26):
            _ticket()
        today = timezone.localdate().isoformat()
        response = self.client.get(reverse('ticket_list'),
                                   {'start_date': today, 'end_date': today})
        content = response.content.decode()
        self.assertIn(f'start_date={today}', content)
        self.assertRegex(content, r'href="\?[^"]*start_date=[^"]*page=2"')

    def test_manager_queue_has_no_date_filter(self):
        self.client.force_login(self.manager)
        queued = _ticket(status=Ticket.STATUS_PENDING_MGR_TRIAGE)
        _backdate(queued, 90)
        today = timezone.localdate().isoformat()
        response = self.client.get(reverse('manager_queue'), {'start_date': today})
        self.assertFalse(response.context['date_filter_enabled'])
        self.assertNotContains(response, 'name="start_date"')
        self.assertIn(queued.pk, self._ids(response))


class FilterBarTests(TestCase):
    """The shared filter bar: chips for every active filter, auto-applying
    controls, the "more filters" panel, and the count + sort results bar."""

    @classmethod
    def setUpTestData(cls):
        cls.t2 = _user('bar-t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.manager = _user('bar-mgr', UserProfile.ROLE_SOC_MANAGER)

    def setUp(self):
        self.client.force_login(self.manager)

    def _chips(self, response):
        return {chip['label']: chip for chip in response.context['filter_chips']}

    def test_active_tickets_shows_a_chip_per_filter_that_removes_only_itself(self):
        _ticket(severity='High')
        response = self.client.get(reverse('ticket_list'), {
            'q': 'web', 'severity': 'High', 'ola': 'overdue', 'page': '2',
        })
        chips = self._chips(response)
        self.assertEqual(list(chips), ['ค้นหา: “web”', 'ความรุนแรง: High', 'OLA: Overdue'])
        remove_severity = chips['ความรุนแรง: High']['remove_url']
        self.assertIn('q=web', remove_severity)
        self.assertIn('ola=overdue', remove_severity)
        self.assertNotIn('severity', remove_severity)
        self.assertNotIn('page=', remove_severity)
        self.assertTrue(response.context['has_clearable_filters'])
        self.assertContains(response, 'ล้างทั้งหมด')

    def test_no_filters_means_no_chips_and_no_clear_all(self):
        response = self.client.get(reverse('ticket_list'))
        self.assertEqual(response.context['filter_chips'], [])
        self.assertNotContains(response, 'ล้างทั้งหมด')

    def test_date_range_chip_uses_the_preset_name(self):
        today = timezone.localdate().isoformat()
        response = self.client.get(reverse('ticket_list'), {'start_date': today, 'end_date': today})
        self.assertIn('วันที่แจ้ง: วันนี้', self._chips(response))
        self.assertEqual(response.context['date_label'], 'วันนี้')

    def test_selects_apply_on_change_and_sort_lives_in_the_results_bar(self):
        content = self.client.get(reverse('ticket_list')).content.decode()
        self.assertRegex(content, r'name="severity" class="[^"]*js-autosubmit')
        self.assertRegex(content, r'name="sort" form="ticket-filters" class="[^"]*js-autosubmit')
        self.assertNotIn('>กรอง</button>', content)

    def test_more_filters_panel_counts_and_opens_for_its_own_filters(self):
        closed = self.client.get(reverse('ticket_list'), {'severity': 'High'})
        self.assertEqual(closed.context['more_filter_count'], 0)
        self.assertContains(closed, 'class="collapse " id="more-filters"')

        opened = self.client.get(reverse('ticket_list'), {'emergency': '1', 'ola': 'overdue'})
        self.assertEqual(opened.context['more_filter_count'], 2)
        self.assertContains(opened, 'class="collapse show" id="more-filters"')

    def test_results_bar_says_how_many_the_filters_hide(self):
        _ticket(severity='High')
        _ticket(severity='Low')
        narrowed = self.client.get(reverse('ticket_list'), {'severity': 'High'})
        self.assertEqual((narrowed.context['result_count'], narrowed.context['result_total']), (1, 2))
        self.assertContains(narrowed, 'จาก 2 ที่เปิดอยู่')
        self.assertNotContains(self.client.get(reverse('ticket_list')), 'จาก 2')

    def test_manager_queue_gets_the_bar_without_the_date_control(self):
        _ticket(status=Ticket.STATUS_PENDING_MGR_TRIAGE, severity='Low')
        response = self.client.get(reverse('manager_queue'), {'severity': 'High'})
        self.assertIn('ความรุนแรง: High', self._chips(response))
        self.assertContains(response, 'id="more-filters"')
        self.assertNotContains(response, 'id="filter-date-label"')
        self.assertContains(response, 'ในคิว')

    def test_history_default_month_chip_is_muted_and_removing_it_shows_all_time(self):
        response = self.client.get(reverse('ticket_history'))
        chip = self._chips(response)['วันที่แจ้ง: เดือนนี้']
        self.assertTrue(chip['is_default'])
        self.assertIn('all_time=1', chip['remove_url'])
        self.assertFalse(response.context['has_clearable_filters'])
        self.assertFalse(response.context['date_is_set'])
        # The inputs stay blank, so changing another filter keeps the implied
        # month instead of pinning it as an explicit range.
        self.assertEqual(response.context['date_input_start'], '')

    def test_history_empty_default_month_offers_all_time(self):
        old = _approved(self.manager)
        _backdate(old, 70)
        response = self.client.get(reverse('ticket_history'))
        self.assertContains(response, 'ยังไม่มีเคสที่แจ้งในเดือนนี้')
        self.assertContains(response, 'href="?all_time=1"')

    def test_history_all_time_is_kept_when_other_filters_change(self):
        response = self.client.get(reverse('ticket_history'), {'all_time': '1'})
        self.assertContains(response, '<input type="hidden" name="all_time" value="1">')
        self.assertTrue(response.context['date_is_empty'])
        self.assertTrue(response.context['has_clearable_filters'])

    def test_history_closer_chip_names_the_person(self):
        event = _closed_event(self.t2)
        response = self.client.get(reverse('ticket_history'), {'approved_by': str(self.t2.pk)})
        self.assertIn(f'ผู้อนุมัติ/ปิดเคส: {self.t2.username}', self._chips(response))
        self.assertEqual([t.pk for t in response.context['tickets']], [event.pk])


def _named_user(username, role, first_name='', **kwargs):
    user = _user(username, role, **kwargs)
    if first_name:
        user.first_name = first_name
        user.save(update_fields=['first_name'])
    return user


class ActiveTicketsColumnSortTests(TestCase):
    """Every header sorts the whole list on the server, by what the cell shows.

    Three tickets whose every sortable column orders them differently, so no
    assertion can pass on a shared tie-break.
    """

    @classmethod
    def setUpTestData(cls):
        cls.manager = _user('sort-mgr', UserProfile.ROLE_SOC_MANAGER)
        admin_zed = _named_user('sort-admin-z', UserProfile.ROLE_SYSTEM_ADMIN, first_name='Zed')
        admin_amy = _named_user('sort-admin-a', UserProfile.ROLE_SYSTEM_ADMIN, first_name='Amy')
        bob = _user('bob', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        carol = _user('carol', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        alice = _user('alice', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        now = timezone.now()
        cls.a = _ticket(
            ticket_id='LST-003', incident_name='golf', severity='Low',
            ola_contain_deadline=now + timedelta(hours=1), issue_type='SIEM',
            assigned_admin=admin_zed, created_by=bob,
            status=Ticket.STATUS_AWAITING_CONTAINMENT,
        )
        # No incident_name: the list shows the sub-category LABEL ("Login
        # ล้มเหลว…"), which sorts after 'golf' — its code ("Failed Login") would not.
        cls.b = _ticket(
            ticket_id='LST-001', incident_name='', detailed_issue2='Failed Login',
            severity='Critical', ola_contain_deadline=None, issue_type='EDR',
            assigned_admin=None, created_by=carol, status=Ticket.STATUS_NEW,
        )
        cls.c = _ticket(
            ticket_id='LST-002', incident_name='alpha', severity='Medium',
            ola_contain_deadline=now + timedelta(hours=5), issue_type='Email',
            assigned_admin=admin_amy, created_by=alice,
            status=Ticket.STATUS_PENDING_T2_REVIEW,
        )
        for ticket, days in ((cls.a, 3), (cls.b, 1), (cls.c, 2)):
            _backdate(ticket, days)
        # save() derives the OLA deadline from severity; pin the fixture's.
        for ticket, deadline in ((cls.a, now + timedelta(hours=1)), (cls.b, None),
                                 (cls.c, now + timedelta(hours=5))):
            Ticket.objects.filter(pk=ticket.pk).update(ola_contain_deadline=deadline)

    def setUp(self):
        self.client.force_login(self.manager)

    def _order(self, sort, url_name='ticket_list'):
        response = self.client.get(reverse(url_name), {'sort': sort})
        self.assertEqual(response.context['sort'], sort)
        return [t.pk for t in response.context['tickets']]

    def test_every_column_sorts_both_ways(self):
        a, b, c = self.a.pk, self.b.pk, self.c.pk
        status_rank = {code: i for i, (code, _) in enumerate(Ticket.STATUS_CHOICES)}
        by_status = [t.pk for t in sorted((self.a, self.b, self.c), key=lambda t: status_rank[t.status])]
        expected = {
            '-id': [a, c, b], 'id': [b, c, a],
            'name': [c, a, b], '-name': [b, a, c],
            'severity': [b, c, a], 'severity_asc': [a, c, b],
            # Blank OLA / admin go last in BOTH directions.
            'ola': [a, c, b], '-ola': [c, a, b],
            'source': [b, c, a], '-source': [a, c, b],
            'admin': [c, a, b], '-admin': [a, c, b],
            'creator': [c, a, b], '-creator': [b, a, c],
            'newest': [b, c, a], 'oldest': [a, c, b],
            'status': by_status, '-status': by_status[::-1],
        }
        for sort, order in expected.items():
            with self.subTest(sort=sort):
                self.assertEqual(self._order(sort), order)

    def test_classification_sorts_by_its_label(self):
        Ticket.objects.filter(pk=self.b.pk).update(classification=Ticket.CLASSIFICATION_EVENT)
        labels = dict(Ticket.CLASSIFICATION_CHOICES)
        for sort in ('classification', '-classification'):
            with self.subTest(sort=sort):
                response = self.client.get(reverse('ticket_list'), {'sort': sort})
                shown = [labels.get(t.classification, t.classification) for t in response.context['tickets']]
                self.assertEqual(shown, sorted(shown, reverse=sort.startswith('-')))

    def test_headers_link_to_the_next_sort_and_mark_the_active_one(self):
        response = self.client.get(reverse('ticket_list'), {'sort': '-id', 'severity': 'Low', 'page': '1'})
        headers = {h['label']: h for h in response.context['sort_headers']}
        self.assertEqual((headers['เลขที่เคส']['direction'], headers['เลขที่เคส']['next_sort']), ('desc', 'id'))
        self.assertEqual((headers['ชื่อเรื่อง']['direction'], headers['ชื่อเรื่อง']['next_sort']), (None, 'name'))
        # First click = the most useful direction for the column.
        self.assertEqual(headers['วันที่แจ้ง']['next_sort'], 'newest')
        self.assertEqual(headers['ความรุนแรง']['next_sort'], 'severity')
        self.assertFalse(headers['']['sortable'])

        content = response.content.decode()
        self.assertIn('aria-sort="descending"', content)
        self.assertEqual(content.count('aria-sort="descending"') + content.count('aria-sort="ascending"'), 1)
        # Header links keep the filters and drop the page number.
        self.assertIn('href="?sort=id&amp;severity=Low"', content)

    def test_active_header_flips_on_second_click(self):
        headers = {h['label']: h for h in
                   self.client.get(reverse('ticket_list'), {'sort': 'id'}).context['sort_headers']}
        self.assertEqual((headers['เลขที่เคส']['direction'], headers['เลขที่เคส']['next_sort']), ('asc', '-id'))

    def test_dropdown_says_when_a_header_set_the_order(self):
        by_column = self.client.get(reverse('ticket_list'), {'sort': 'name'})
        self.assertTrue(by_column.context['sort_is_from_column'])
        self.assertContains(by_column, '<option value="name" selected>ตามคอลัมน์ในตาราง</option>')

        preset = self.client.get(reverse('ticket_list'), {'sort': 'newest'})
        self.assertFalse(preset.context['sort_is_from_column'])
        self.assertNotContains(preset, 'ตามคอลัมน์ในตาราง')
        # A preset that is also a column's first click marks that header.
        headers = {h['label']: h for h in preset.context['sort_headers']}
        self.assertEqual(headers['วันที่แจ้ง']['direction'], 'desc')

    def test_old_sort_keys_still_work(self):
        a, b, c = self.a.pk, self.b.pk, self.c.pk
        self.assertEqual(self._order('newest'), [b, c, a])
        self.assertEqual(self._order('oldest'), [a, c, b])
        Ticket.objects.filter(pk=self.c.pk).update(is_emergency=True)
        self.assertEqual(self._order('emergency')[0], c)

    def test_manager_queue_has_the_same_headers(self):
        Ticket.objects.filter(pk__in=[self.a.pk, self.c.pk]).update(status=Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(self._order('-id', 'manager_queue'), [self.a.pk, self.c.pk])
        response = self.client.get(reverse('manager_queue'))
        self.assertEqual(len(response.context['sort_headers']), 11)


class HistoryColumnSortTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.manager = _user('hsort-mgr', UserProfile.ROLE_SOC_MANAGER)
        zed = _named_user('hsort-zed', UserProfile.ROLE_SOC_MANAGER, first_name='Zed')
        amy = _named_user('hsort-amy', UserProfile.ROLE_SOC_STAFF, first_name='Amy',
                          tier=UserProfile.TIER_T2)
        cls.a = _approved(zed, ticket_id='HST-003', incident_name='golf', severity='Low')
        cls.b = _closed_event(amy, ticket_id='HST-001', incident_name='', detailed_issue2='Failed Login',
                              severity='Critical')
        # No closing log and no approver: the closer is blank and sorts last.
        cls.c = _ticket(ticket_id='HST-002', incident_name='alpha', severity='Medium',
                        status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=cls.c.pk).update(status=Ticket.STATUS_CANCELLED)
        for ticket, days in ((cls.a, 1), (cls.b, 3), (cls.c, 2)):
            Ticket.objects.filter(pk=ticket.pk).update(closed_at=_days_ago(days))

    def setUp(self):
        self.client.force_login(self.manager)

    def _order(self, sort):
        response = self.client.get(reverse('ticket_history'), {'sort': sort, 'all_time': '1'})
        self.assertEqual(response.context['sort'], sort)
        return [t.pk for t in response.context['tickets']]

    def test_every_column_sorts_both_ways(self):
        a, b, c = self.a.pk, self.b.pk, self.c.pk
        status_rank = {code: i for i, (code, _) in enumerate(Ticket.STATUS_CHOICES)}
        by_status = [t.pk for t in sorted((self.a, self.b, self.c),
                                          key=lambda t: status_rank[Ticket.objects.get(pk=t.pk).status])]
        expected = {
            '-id': [a, c, b], 'id': [b, c, a],
            'name': [c, a, b], '-name': [b, a, c],
            'severity': [b, c, a], 'severity_asc': [a, c, b],
            'closed': [a, c, b], 'closed_oldest': [b, c, a],
            'status': by_status, '-status': by_status[::-1],
            # Amy closed the Event, Zed approved; the cancelled one has no closer.
            'closer': [b, a, c], '-closer': [a, b, c],
        }
        for sort, order in expected.items():
            with self.subTest(sort=sort):
                self.assertEqual(self._order(sort), order)

    def test_free_text_columns_are_not_sortable(self):
        response = self.client.get(reverse('ticket_history'), {'all_time': '1'})
        headers = {h['label']: h for h in response.context['sort_headers']}
        self.assertFalse(headers['รายละเอียดเหตุการณ์']['sortable'])
        self.assertFalse(headers['การแก้ไขล่าสุด']['sortable'])
        self.assertEqual(headers['วันที่ปิด']['direction'], 'desc')  # the default sort
        self.assertFalse(response.context['sort_is_from_column'])

    def test_closer_sort_adds_no_per_row_queries(self):
        def count_queries():
            with CaptureQueriesContext(connection) as ctx:
                self.client.get(reverse('ticket_history'), {'sort': 'closer', 'all_time': '1'})
            return len(ctx.captured_queries)

        before = count_queries()
        for index in range(4):
            _approved(_user(f'hsort-extra-{index}', UserProfile.ROLE_SOC_MANAGER))
        self.assertEqual(count_queries(), before)
