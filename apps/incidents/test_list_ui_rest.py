"""The shared filter bar and server-side header sorting on the remaining lists:
IOC search, the IOC Database, the Response Requests queue, My Queue, the
System Owner page and the Wazuh triage queue.

Orders are read from the view context, not the HTML, so a markup change cannot
turn an ordering assertion green.
"""

from datetime import timedelta

from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase
from apps.incidents.models import Ticket, TicketIOC, TicketSubtask, TriageRecord
from apps.incidents.test_ticket_workflow import _ticket, _user
from apps.incidents.ti_platform import create_manual_iocs
from apps.wazuh_ingest.tests import _make_alert


def _named(username, role, first_name, **kwargs):
    user = _user(username, role, **kwargs)
    user.first_name = first_name
    user.save(update_fields=['first_name'])
    return user


def _headers(response, key='sort_headers'):
    return {h['label']: h for h in response.context[key]}


# ── IOC search ──────────────────────────────────────────────────────────── #

class GlobalSearchSortTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc = _user('gs-t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.a = _ticket(ticket_id='GS-003', device_name='zulu-host', destination_ip='10.0.0.9',
                        issue_description='needle one', status=Ticket.STATUS_AWAITING_CONTAINMENT)
        cls.b = _ticket(ticket_id='GS-001', device_name='alpha-host', destination_ip='',
                        issue_description='needle two', status=Ticket.STATUS_NEW)
        cls.c = _ticket(ticket_id='GS-002', device_name='mike-host', destination_ip='10.0.0.1',
                        issue_description='needle three', status=Ticket.STATUS_PENDING_T2_REVIEW)
        # The IOC join fans out (so the query is DISTINCT); give one ticket two.
        TicketIOC.objects.create(ticket=cls.a, category='domain', value='needle.example')
        TicketIOC.objects.create(ticket=cls.a, category='ip', value='203.0.113.7')
        sources = [code for code, _ in TriageRecord._meta.get_field('source').flatchoices]
        cls.r1 = TriageRecord.objects.create(source=sources[0], alert_description='needle r1',
                                             source_ip='10.9.9.9', analyst=cls.soc)
        cls.r2 = TriageRecord.objects.create(source=sources[-1], alert_description='needle r2',
                                             source_ip='10.1.1.1', analyst=cls.soc)

    def setUp(self):
        self.client.force_login(self.soc)

    def _tickets(self, **params):
        response = self.client.get(reverse('global_search'), {'q': 'needle', **params})
        return response, [t.pk for t in response.context['ticket_results']]

    def test_ticket_columns_sort_both_ways_on_a_distinct_query(self):
        a, b, c = self.a.pk, self.b.pk, self.c.pk
        rank = {code: i for i, (code, _) in enumerate(Ticket.STATUS_CHOICES)}
        by_status = [t.pk for t in sorted((self.a, self.b, self.c), key=lambda t: rank[t.status])]
        expected = {
            '-id': [a, c, b], 'id': [b, c, a],
            'device': [b, c, a], '-device': [a, c, b],
            # Blank destination goes last either way.
            'dest': [c, a, b], '-dest': [a, c, b],
            'status': by_status, '-status': by_status[::-1],
        }
        for sort, order in expected.items():
            with self.subTest(sort=sort):
                response, pks = self._tickets(ts=sort)
                self.assertEqual(response.context['ticket_sort'], sort)
                self.assertEqual(pks, order)

    def test_triage_table_sorts_on_its_own_parameter(self):
        response = self.client.get(reverse('global_search'), {'q': 'needle', 'rs': 'ip'})
        self.assertEqual([r.pk for r in response.context['triage_results']], [self.r2.pk, self.r1.pk])
        # The ticket table keeps its own default.
        self.assertEqual(response.context['ticket_sort'], 'newest')

    def test_header_links_use_each_tables_own_parameters(self):
        response = self.client.get(reverse('global_search'), {'q': 'needle', 'tp': '2', 'rs': 'ip'})
        ticket_href = _headers(response, 'ticket_sort_headers')['เลข Ticket']['href']
        self.assertIn('ts=-id', ticket_href)
        self.assertIn('rs=ip', ticket_href)      # the other table's sort survives
        self.assertNotIn('tp=', ticket_href)     # its own page resets
        triage_href = _headers(response, 'triage_sort_headers')['IP ต้นทาง']['href']
        self.assertIn('rs=-ip', triage_href)
        self.assertIn('tp=2', triage_href)
        self.assertContains(response, 'aria-sort="ascending"')


# ── IOC Database ────────────────────────────────────────────────────────── #

class IOCDatabaseSortTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.forensic = _user('iocs-fa', UserProfile.ROLE_FORENSIC)
        ticket = _ticket()
        TicketIOC.objects.create(ticket=ticket, category='domain', value='mmm.example')
        create_manual_iocs([
            {'category': 'domain', 'value': 'aaa.example', 'file_name': '', 'note': 'seen before'},
            {'category': 'ip', 'value': '198.51.100.7', 'file_name': '', 'note': ''},
        ], cls.forensic)

    def setUp(self):
        self.client.force_login(self.forensic)

    def _values(self, **params):
        response = self.client.get(reverse('ioc_database'), params)
        return response, [row['value'] for row in response.context['database']]

    def test_value_and_source_sort_in_sql(self):
        self.assertEqual(self._values(sort='value')[1], ['198.51.100.7', 'aaa.example', 'mmm.example'])
        self.assertEqual(self._values(sort='-value')[1], ['mmm.example', 'aaa.example', '198.51.100.7'])
        # 'Manual' < 'Ticket' by the label the Source column shows.
        _, by_source = self._values(sort='source')
        self.assertEqual(by_source[-1], 'mmm.example')

    def test_blank_notes_sort_last_both_ways(self):
        for sort in ('note', '-note'):
            with self.subTest(sort=sort):
                self.assertEqual(self._values(sort=sort)[1][0], 'aaa.example')

    def test_sort_orders_the_whole_database_not_the_page(self):
        create_manual_iocs([
            {'category': 'domain', 'value': f'z{index:02d}.example', 'file_name': '', 'note': ''}
            for index in range(35)
        ], self.forensic)
        response, values = self._values(sort='-value')
        self.assertEqual(response.context['database'].paginator.num_pages, 2)
        self.assertEqual(values[0], 'z34.example')   # the top of the WHOLE set

    def test_bar_chips_results_and_invalid_sort(self):
        response, values = self._values(q='example', category='domain', sort='bogus')
        self.assertEqual(response.context['sort'], 'worklist')
        labels = [chip['label'] for chip in response.context['filter_chips']]
        self.assertEqual(labels, ['ค้นหา: “example”', 'ประเภท: Domain'])
        self.assertEqual(response.context['result_count'], 2)
        self.assertNotContains(response, 'th.sortable')          # old in-browser sort is gone
        self.assertFalse(_headers(response)['การดำเนินการ']['sortable'])


# ── Response Requests queue ─────────────────────────────────────────────── #

class ResponseQueueBarTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.manager = _user('rq-mgr', UserProfile.ROLE_SOC_MANAGER)
        cls.forensic = _named('rq-fa', UserProfile.ROLE_FORENSIC, 'Zed')
        cls.forensic2 = _named('rq-fa2', UserProfile.ROLE_FORENSIC, 'Amy')
        ticket = _ticket(ticket_id='RQ-TICKET')
        make = TicketSubtask.objects.create
        cls.open_one = make(ticket=ticket, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
                            title='Memory dump', assigned_to=cls.forensic, created_by=cls.manager,
                            status=TicketSubtask.STATUS_OPEN)
        cls.working = make(ticket=ticket, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
                           title='Disk image', assigned_to=cls.forensic2, created_by=cls.manager,
                           status=TicketSubtask.STATUS_IN_PROGRESS, report_number='SOC-RCA-1')
        cls.done = make(ticket=ticket, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
                        title='Browser history', assigned_to=cls.forensic, created_by=cls.manager,
                        status=TicketSubtask.STATUS_DONE, report_number='SOC-RCA-2')

    def _get(self, user, **params):
        self.client.force_login(user)
        return self.client.get(reverse('response_request_queue'), params)

    def _pks(self, response):
        return [r.pk for r in response.context['requests']]

    def test_default_order_is_open_work_first(self):
        self.assertEqual(self._pks(self._get(self.manager)),
                         [self.open_one.pk, self.working.pk, self.done.pk])

    def test_search_narrows_and_status_pills_count_within_it(self):
        response = self._get(self.manager, q='image')
        self.assertEqual(self._pks(response), [self.working.pk])
        pills = {p['code']: p['count'] for p in response.context['status_pills']}
        self.assertEqual((pills[''], pills[TicketSubtask.STATUS_IN_PROGRESS],
                          pills[TicketSubtask.STATUS_OPEN]), (1, 1, 0))
        self.assertEqual(response.context['open_count'], 2)   # the whole queue
        self.assertIn('ค้นหา: “image”', [c['label'] for c in response.context['filter_chips']])

    def test_column_sorts(self):
        self.assertEqual(self._pks(self._get(self.manager, sort='title')),
                         [self.done.pk, self.working.pk, self.open_one.pk])
        # Amy before Zed; the report number sorts with blanks last both ways.
        self.assertEqual(self._pks(self._get(self.manager, sort='assignee'))[0], self.working.pk)
        self.assertEqual(self._pks(self._get(self.manager, sort='report'))[-1], self.open_one.pk)
        self.assertEqual(self._pks(self._get(self.manager, sort='-report'))[-1], self.open_one.pk)

    def test_assignee_column_only_in_the_overview(self):
        overview = _headers(self._get(self.manager))
        mine = _headers(self._get(self.forensic))
        self.assertIn('ผู้รับผิดชอบ', overview)
        self.assertNotIn('ผู้รับผิดชอบ', mine)
        self.assertEqual(self._pks(self._get(self.forensic)), [self.open_one.pk, self.done.pk])


# ── My Queue ────────────────────────────────────────────────────────────── #

class MyQueueBarTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user('mq-t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        # AWAITING_OWNER: one of Tier 1's own-court statuses (TIER1_QUEUE_STATUSES).
        cls.alpha = _ticket(incident_name='alpha phishing', created_by=cls.t1, severity='Low',
                            status=Ticket.STATUS_AWAITING_OWNER)
        cls.bravo = _ticket(incident_name='bravo malware', created_by=cls.t1, severity='Critical',
                            status=Ticket.STATUS_AWAITING_OWNER)
        cls.watch = _ticket(incident_name='alpha watch', created_by=cls.t1,
                            status=Ticket.STATUS_MONITORING,
                            monitor_until=timezone.now() + timedelta(days=3))
        cls.report = TriageRecord.objects.create(alert_description='alpha report', analyst=cls.t1)

    def setUp(self):
        self.client.force_login(self.t1)

    def _get(self, **params):
        return self.client.get(reverse('my_queue'), params)

    def test_one_search_narrows_every_work_tab_and_its_badge(self):
        response = self._get(q='alpha')
        self.assertEqual([t.pk for t in response.context['my_tickets']], [self.alpha.pk])
        self.assertEqual(response.context['my_tickets_total'], 1)
        self.assertEqual([t.pk for t in response.context['monitoring_tickets']], [self.watch.pk])
        self.assertEqual([r.pk for r in response.context['manual_queue']], [self.report.pk])
        self.assertEqual(self._get(q='bravo').context['manual_queue_count'], 0)

    def test_tab_headers_sort_that_tab_and_keep_it_open(self):
        response = self._get(sort='severity')
        self.assertEqual([t.pk for t in response.context['my_tickets']][0], self.bravo.pk)
        href = _headers(response, 'manual_sort_headers')['ผู้รับผิดชอบ']['href']
        self.assertIn('qsort=claimer', href)
        self.assertIn('tab=manual', href)
        self.assertIn('sort=severity', href)    # the other tab's sort survives

    def test_search_form_follows_the_active_tab(self):
        response = self._get(tab='manual', q='alpha')
        self.assertContains(response, 'name="tab" value="manual"')
        self.assertContains(response, 'shown.bs.tab')


# ── System Owner page ───────────────────────────────────────────────────── #

class SystemOwnerListTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = _user('so-owner', UserProfile.ROLE_SYSTEM_OWNER)
        cls.tickets = [
            _ticket(incident_name=f'case {index:02d}', system_owner=cls.owner,
                    status=Ticket.STATUS_AWAITING_CONTAINMENT, is_emergency=(index == 0))
            for index in range(12)
        ]

    def setUp(self):
        self.client.force_login(self.owner)

    def _get(self, **params):
        return self.client.get(reverse('system_owner_dashboard'), params)

    def test_every_open_case_is_reachable(self):
        # It used to stop at the newest 10.
        response = self._get()
        self.assertEqual(response.context['result_count'], 12)
        self.assertEqual(len(response.context['recent_tickets']), 12)

    def test_filters_chips_and_sorts(self):
        response = self._get(emergency='1')
        self.assertEqual([t.pk for t in response.context['recent_tickets']], [self.tickets[0].pk])
        self.assertIn('เฉพาะเคสฉุกเฉิน', [c['label'] for c in response.context['filter_chips']])
        by_name = [t.display_name for t in self._get(sort='name').context['recent_tickets']]
        self.assertEqual(by_name, sorted(by_name))
        self.assertEqual(self._get(q='case 07').context['result_count'], 1)


# ── Wazuh triage queue ──────────────────────────────────────────────────── #

class TriageQueueBarTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user('tq-t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        _make_alert(opensearch_id='tq-1', agent_name='HOST-A')

    def setUp(self):
        self.client.force_login(self.t1)

    def test_shared_bar_headers_and_results(self):
        response = self.client.get(reverse('triage_queue'), {'q': 'HOST', 'sort': 'agent'})
        self.assertIn('ค้นหา: “HOST”', [c['label'] for c in response.context['filter_chips']])
        content = response.content.decode()
        # aria-sort on the header cell, per ARIA (it used to sit on the link).
        self.assertRegex(content, r'<th[^>]*aria-sort="ascending"')
        self.assertIn('name="per_page" form="alert-filters"', content)
        self.assertIn('<option value="agent" selected>ตามคอลัมน์ในตาราง</option>', content)
        self.assertTrue(response.context['has_clearable_filters'])
        self.assertFalse(self.client.get(reverse('triage_queue')).context['has_clearable_filters'])
