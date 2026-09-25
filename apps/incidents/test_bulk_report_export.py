"""Bulk PDF export from Active Tickets and Ticket History.

The export re-posts the page's querystring and must ZIP exactly the tickets the
page shows (every page of them), one PDF each via the single-export generator,
SOC Manager and Tier 2 only (not Tier 1), capped at BULK_REPORT_LIMIT. Most tests stub the generator for speed;
one renders a real PDF end to end.
"""

import zipfile
from datetime import timedelta
from io import BytesIO
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase
from apps.incidents.models import Ticket
from apps.incidents.reports import BULK_REPORT_FAILURES_NAME, PDF_CONTENT_TYPE, GeneratedTicketReport
from apps.incidents.test_ticket_lists import _approved, _backdate, _closed_event
from apps.incidents.test_ticket_workflow import _ticket, _user

GENERATOR = 'apps.incidents.reports.generate_ticket_report_pdf'


def _fake_report(pk, **kwargs):
    return GeneratedTicketReport(
        filename=f'report_{Ticket.objects.get(pk=pk).ticket_id}.pdf',
        content=b'%PDF-1.4 fake', content_type=PDF_CONTENT_TYPE,
    )


def _zip_names(response):
    archive = zipfile.ZipFile(BytesIO(b''.join(response.streaming_content)))
    return archive, sorted(archive.namelist())


class BulkReportExportTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user('bulk-t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.t2 = _user('bulk-t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.manager = _user('bulk-mgr', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _user('bulk-admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.forensic = _user('bulk-fa', UserProfile.ROLE_FORENSIC)
        cls.high = _ticket(ticket_id='BULK-HIGH', severity='High',
                           status=Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=cls.admin)
        cls.low = _ticket(ticket_id='BULK-LOW', severity='Low',
                          status=Ticket.STATUS_AWAITING_CONTAINMENT)
        cls.old = _ticket(ticket_id='BULK-OLD', severity='High',
                          status=Ticket.STATUS_AWAITING_CONTAINMENT)
        _backdate(cls.old, 60)

    def setUp(self):
        self.client.force_login(self.t2)

    def _export(self, url_name, query='', **extra):
        return self.client.post(reverse(url_name), {'query': query, **extra})

    # ── What goes in the ZIP ────────────────────────────────────────────── #

    @patch(GENERATOR, side_effect=_fake_report)
    def test_active_zip_follows_the_filters_on_screen(self, generator):
        response = self._export('ticket_list_reports_pdf', 'severity=High')
        self.assertEqual(response['Content-Type'], 'application/zip')
        self.assertRegex(response['Content-Disposition'], r'attachment; filename="reports_active_\d{8}-\d{4}\.zip"')
        _, names = _zip_names(response)
        self.assertEqual(names, ['report_BULK-HIGH.pdf', 'report_BULK-OLD.pdf'])

        cutoff = (timezone.localdate() - timedelta(days=30)).isoformat()
        _, names = _zip_names(self._export('ticket_list_reports_pdf', f'severity=High&start_date={cutoff}'))
        self.assertEqual(names, ['report_BULK-HIGH.pdf'])

    @patch(GENERATOR, side_effect=_fake_report)
    def test_history_zip_follows_default_month_pills_and_closer(self, generator):
        recent = _approved(self.manager, ticket_id='BULK-APPROVED')
        event = _closed_event(self.t2, ticket_id='BULK-EVENT')
        old = _approved(self.manager, ticket_id='BULK-OLD-CLOSED')
        _backdate(old, 70)   # opened outside the default month

        _, names = _zip_names(self._export('ticket_history_reports_pdf', ''))
        self.assertEqual(names, ['report_BULK-APPROVED.pdf', 'report_BULK-EVENT.pdf'])
        _, names = _zip_names(self._export('ticket_history_reports_pdf', 'all_time=1&status=APPROVED'))
        self.assertEqual(names, ['report_BULK-APPROVED.pdf', 'report_BULK-OLD-CLOSED.pdf'])
        _, names = _zip_names(self._export('ticket_history_reports_pdf', f'all_time=1&approved_by={self.t2.pk}'))
        self.assertEqual(names, ['report_BULK-EVENT.pdf'])
        self.assertTrue(recent and event)

    @patch(GENERATOR, side_effect=_fake_report)
    def test_options_and_exporter_reach_every_report(self, generator):
        b''.join(self._export('ticket_list_reports_pdf', 'q=BULK-LOW', show_signoff='1').streaming_content)
        kwargs = generator.call_args.kwargs
        # hide_empty unticked (not posted) → off; show_signoff ticked → on.
        self.assertEqual((kwargs['hide_empty'], kwargs['show_signoff']), (False, True))
        self.assertEqual(kwargs['generated_by'], self.t2)
        b''.join(self._export('ticket_list_reports_pdf', 'q=BULK-LOW', hide_empty='1').streaming_content)
        self.assertEqual((generator.call_args.kwargs['hide_empty'],
                          generator.call_args.kwargs['show_signoff']), (True, False))

    def test_one_failing_report_does_not_cost_the_rest(self):
        def flaky(pk, **kwargs):
            if pk == self.low.pk:
                raise RuntimeError('render failed')
            return _fake_report(pk)

        with patch(GENERATOR, side_effect=flaky):
            archive, names = _zip_names(self._export('ticket_list_reports_pdf', ''))
        self.assertIn('report_BULK-HIGH.pdf', names)
        self.assertNotIn('report_BULK-LOW.pdf', names)
        self.assertIn(BULK_REPORT_FAILURES_NAME, names)
        self.assertIn('BULK-LOW', archive.read(BULK_REPORT_FAILURES_NAME).decode('utf-8'))

    def test_duplicate_filenames_are_made_unique(self):
        same = GeneratedTicketReport(filename='report_same.pdf', content=b'%PDF', content_type=PDF_CONTENT_TYPE)
        with patch(GENERATOR, return_value=same):
            _, names = _zip_names(self._export('ticket_list_reports_pdf', 'severity=High'))
        self.assertEqual(len(names), 2)
        self.assertEqual(len(set(names)), 2)
        self.assertIn('report_same.pdf', names)

    # ── Limits and access ───────────────────────────────────────────────── #

    @patch(GENERATOR, side_effect=_fake_report)
    def test_over_the_limit_or_empty_goes_back_with_a_message(self, generator):
        with patch('apps.incidents.views.reports.BULK_REPORT_LIMIT', 2):
            response = self._export('ticket_list_reports_pdf', 'sort=newest')
        self.assertRedirects(response, reverse('ticket_list') + '?sort=newest', fetch_redirect_response=False)
        response = self._export('ticket_history_reports_pdf', 'q=nothing-matches')
        self.assertRedirects(response, reverse('ticket_history') + '?q=nothing-matches',
                             fetch_redirect_response=False)
        generator.assert_not_called()

    @patch(GENERATOR, side_effect=_fake_report)
    def test_only_manager_and_tier2_may_export_and_only_by_post(self, generator):
        # Tier 1 keeps the one-report export on the ticket page, but not bulk.
        for user in (self.t1, self.admin, self.forensic):
            self.client.force_login(user)
            for url_name in ('ticket_list_reports_pdf', 'ticket_history_reports_pdf'):
                with self.subTest(user=user.username, url=url_name):
                    self.assertEqual(self._export(url_name).status_code, 404)
        self.client.force_login(self.t2)
        self.assertEqual(self.client.get(reverse('ticket_list_reports_pdf')).status_code, 405)
        generator.assert_not_called()

    @patch(GENERATOR, side_effect=_fake_report)
    def test_manager_may_export(self, generator):
        self.client.force_login(self.manager)
        _, names = _zip_names(self._export('ticket_list_reports_pdf', 'q=BULK-LOW'))
        self.assertEqual(names, ['report_BULK-LOW.pdf'])

    def test_menu_shows_on_active_and_history_only_for_soc(self):
        page = self.client.get(reverse('ticket_list'), {'severity': 'High', 'page': '1'})
        self.assertContains(page, f'action="{reverse("ticket_list_reports_pdf")}"')
        self.assertContains(page, 'name="query" value="severity=High"')   # page number dropped
        self.assertContains(self.client.get(reverse('ticket_history'), {'all_time': '1'}),
                            reverse('ticket_history_reports_pdf'))
        self.client.force_login(self.manager)
        self.assertContains(self.client.get(reverse('ticket_list')), 'ส่งออก PDF')
        self.assertNotContains(self.client.get(reverse('manager_queue')), 'ส่งออก PDF')
        for user in (self.t1, self.admin):
            self.client.force_login(user)
            with self.subTest(user=user.username):
                self.assertNotContains(self.client.get(reverse('ticket_list')), 'ส่งออก PDF')
                self.assertNotContains(self.client.get(reverse('ticket_history')), 'ส่งออก PDF')

    def test_menu_explains_the_limit_instead_of_offering_the_form(self):
        with patch('apps.incidents.views._helpers.BULK_REPORT_LIMIT', 2):
            page = self.client.get(reverse('ticket_list'))
        self.assertContains(page, 'ส่งออกได้ครั้งละไม่เกิน 2 เคส')
        self.assertNotContains(page, 'ดาวน์โหลด ZIP')

    # ── End to end, real PDF ────────────────────────────────────────────── #

    def test_real_export_renders_pdfs_and_records_provenance(self):
        archive, names = _zip_names(self._export('ticket_list_reports_pdf', 'q=BULK-LOW', hide_empty='1'))
        self.assertEqual(len(names), 1)
        self.assertTrue(archive.read(names[0]).startswith(b'%PDF'))
        self.low.refresh_from_db()
        self.assertEqual(self.low.report_format, 'pdf')
        self.assertEqual(self.low.report_generated_by, self.t2)
