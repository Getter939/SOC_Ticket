"""IOC Database: analyst-IOC imports, the two-source unified view, manual review
status, removal, filters, access boundaries and ticket IOC integration."""

import csv
import io
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import IntegrityError, transaction
from django.http import QueryDict
from django.test import override_settings
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from openpyxl import Workbook

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase
from .forms import ProjectIncidentForm, TicketEditForm, TicketForm
from .models import AnalystIOC, AnalystIOCImport, IOCReviewStatus, Ticket, TicketIOC
from .reports import build_ticket_report_context
from .tests import _pi_post_data, _ticket_post_data
from .ticket_updates import save_ticket_edit
from .ti_platform import HEADERS, build_ioc_database, import_inventory, parse_import

HASH = 'ab' * 32


def csv_upload(rows, header=HEADERS):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(header)
    writer.writerows(rows)
    return SimpleUploadedFile('inventory.csv', stream.getvalue().encode('utf-8-sig'))


def xlsx_upload(rows):
    workbook = Workbook()
    for row in rows:
        workbook.active.append(row)
    stream = io.BytesIO()
    workbook.save(stream)
    workbook.close()
    return SimpleUploadedFile('inventory.xlsx', stream.getvalue())


def user(name, role, tier=''):
    account = User.objects.create_user(name, password='testpass123')
    UserProfile.objects.create(user=account, role=role, tier=tier, department='Test', phone='000')
    return account


def _qd(base, **iocs):
    qd = QueryDict('', mutable=True)
    for key, value in base.items():
        qd[key] = value
    for name, values in iocs.items():
        qd.setlist(name, list(values) if isinstance(values, (list, tuple)) else [values])
    return qd


class IOCDatabaseTests(MFATestCase):
    @classmethod
    def setUpTestData(cls):
        cls.forensic = user('ti-forensic', UserProfile.ROLE_FORENSIC)
        cls.soc = user('ti-soc', UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T1)
        cls.admin = user('ti-admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='soc-ti-test-', ignore_cleanup_errors=True)
        self.addCleanup(directory.cleanup)
        self.media = Path(directory.name)
        setting = override_settings(MEDIA_ROOT=directory.name)
        setting.enable()
        self.addCleanup(setting.disable)

    def import_rows(self, rows):
        return import_inventory(csv_upload(rows), self.forensic)

    def _rows(self, **kwargs):
        return {r['value']: r for r in build_ioc_database(**kwargs)[0]}

    # ── Import & dedup ─────────────────────────────────────────────────── #

    def test_import_normalizes_values_and_dedups_on_id(self):
        first = self.import_rows([
            ['TI-1', 'Hash', 'malware.exe', HASH, 'Loader'],
            ['TI-2', 'IP', '', '203.0.113.1', 'C2'],
        ])
        self.assertEqual((first.row_count, first.added_count, first.skipped_count), (2, 2, 0))
        second = import_inventory(csv_upload([
            ['TI-1', 'Hash', 'malware.exe', HASH.upper(), 'Loader'],
            ['TI-2', 'IP', '', '203[.]0[.]113[.]1', 'C2'],
            ['TI-5', 'IP', '', '2001:0db8:0:0:0:0:0:1', 'IPv6'],
        ]), self.forensic)
        self.assertEqual((second.added_count, second.skipped_count), (1, 2))
        self.assertEqual(AnalystIOC.objects.count(), 3)
        self.assertEqual(AnalystIOC.objects.get(ext_id='TI-1').ioc_detail, HASH)
        self.assertTrue(AnalystIOC.objects.filter(ioc_detail='2001:db8::1').exists())
        self.assertEqual(AnalystIOC.objects.get(ext_id='TI-1').source_import, first)
        self.assertEqual(AnalystIOC.objects.get(ext_id='TI-1').last_seen_import, second)

    def test_duplicate_id_keeps_original_values(self):
        self.import_rows([['TI-1', 'Domain', '', 'example.org', 'first']])
        self.import_rows([['TI-1', 'IP', '', '203.0.113.9', 'changed']])
        row = AnalystIOC.objects.get(ext_id='TI-1')
        self.assertEqual((row.category, row.ioc_detail, row.note), ('domain', 'example.org', 'first'))

    def test_unique_id_enforced_by_database(self):
        self.import_rows([['TI-1', 'Hash', '', HASH, '']])
        dup = AnalystIOC.objects.get()
        dup.pk = None
        with self.assertRaises(IntegrityError), transaction.atomic():
            dup.save(force_insert=True)

    def test_thai_headers_and_categories(self):
        upload = xlsx_upload([
            ['รหัส', 'ประเภท', 'ชื่อไฟล์', 'รายละเอียด IOC', 'หมายเหตุ'],
            ['TI-TH', 'โดเมน', '', 'EXAMPLE.ORG', 'โดเมนอันตราย'],
        ])
        import_inventory(upload, self.forensic)
        row = AnalystIOC.objects.get()
        self.assertEqual((row.category, row.ioc_detail), ('domain', 'example.org'))

    def test_invalid_rows_are_reported_together(self):
        upload = csv_upload([
            ['TI-A', 'Hash', '', 'bad-hash', ''],
            ['TI-B', 'Domain', '', 'https://x.example', ''],
            ['TI-C', 'Hash', '', HASH, ''],
            ['TI-D', 'Nope', '', 'x', ''],
        ])
        with self.assertRaises(ValidationError) as ctx:
            parse_import(upload)
        joined = ' '.join(ctx.exception.messages)
        for marker in ('Row 2', 'Row 3', 'Row 5'):
            self.assertIn(marker, joined)
        self.assertFalse(AnalystIOC.objects.exists())

    def test_missing_id_detail_and_bad_header(self):
        for rows, header in [
            ([['', 'Hash', '', HASH, '']], HEADERS),
            ([['TI-1', 'Hash', '', '', '']], HEADERS),
            ([['TI-1', 'Hash', '', HASH, '']], ('ID', 'Category')),
            ([], HEADERS),
        ]:
            with self.subTest(rows=rows), self.assertRaises(ValidationError):
                parse_import(csv_upload(rows, header=header))

    def test_rejects_formulas_and_corrupt_workbook(self):
        for upload in [xlsx_upload([HEADERS, ['=1+1', 'Hash', '', HASH, '']]),
                       SimpleUploadedFile('fake.xlsx', b'not a workbook')]:
            with self.subTest(name=upload.name), self.assertRaises(ValidationError):
                parse_import(upload)

    def test_import_limits(self):
        with patch('apps.incidents.ti_platform.MAX_IMPORT_ROWS', 1):
            with self.assertRaisesMessage(ValidationError, 'at most 1'):
                parse_import(csv_upload([['TI-1', 'Hash', '', HASH, ''],
                                         ['TI-2', 'Hash', '', HASH, '']]))
        with patch('apps.incidents.ti_platform.MAX_IMPORT_BYTES', 10):
            with self.assertRaises(ValidationError):
                parse_import(csv_upload([['TI-1', 'Hash', '', HASH, '']]))

    def test_database_failure_cleans_raw_file_and_batch(self):
        with patch.object(AnalystIOC.objects, 'get_or_create', side_effect=IntegrityError):
            with self.assertRaises(IntegrityError):
                self.import_rows([['TI-1', 'Hash', '', HASH, '']])
        self.assertFalse(AnalystIOCImport.objects.exists())
        self.assertEqual([p for p in self.media.rglob('*') if p.is_file()], [])

    def test_older_import_does_not_regress_last_seen(self):
        newer = self.import_rows([['TI-1', 'Hash', '', HASH, '']])
        row = AnalystIOC.objects.get()
        self.assertEqual(row.last_seen_import, newer)
        with patch('django.utils.timezone.now', return_value=timezone.now() - timedelta(hours=1)):
            self.import_rows([['TI-1', 'Hash', '', HASH, '']])
        row.refresh_from_db()
        self.assertEqual(row.last_seen_import, newer)

    # ── Unified view, status & removal ─────────────────────────────────── #

    def test_database_unifies_both_sources(self):
        self.import_rows([['TI-1', 'Hash', '', HASH, ''], ['TI-2', 'IP', '', '198.51.100.7', '']])
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='hash', value=HASH)          # both
        TicketIOC.objects.create(ticket=ticket, category='domain', value='t.example')  # ticket only
        rows = self._rows()
        self.assertEqual(set(rows[HASH]['sources']), {'ticket', 'analyst'})
        self.assertEqual(rows['198.51.100.7']['sources'], ['analyst'])
        self.assertEqual(rows['t.example']['sources'], ['ticket'])
        self.assertEqual(rows[HASH]['status'], 'not_checked')       # default
        self.assertEqual(rows[HASH]['ticket_count'], 1)

    def test_status_toggle_persists_and_is_shared_across_sources(self):
        self.import_rows([['TI-1', 'Hash', '', HASH, '']])
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='hash', value=HASH)
        self.client.force_login(self.forensic)
        response = self.client.post(reverse('ioc_status_toggle'),
                                    {'category': 'hash', 'value': HASH, 'checked': '1'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(IOCReviewStatus.objects.get(category='hash', value=HASH).checked)
        self.assertEqual(self._rows()[HASH]['status'], 'checked')   # shared across both sources
        # Unticking (checkbox absent) sets it back to Not Checked.
        self.client.post(reverse('ioc_status_toggle'), {'category': 'hash', 'value': HASH})
        self.assertEqual(self._rows()[HASH]['status'], 'not_checked')

    def test_remove_soft_deletes_analyst_ioc_but_keeps_ticket_twin(self):
        self.import_rows([['TI-1', 'Hash', '', HASH, '']])
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='hash', value=HASH)
        rec = AnalystIOC.objects.get()
        self.client.force_login(self.forensic)
        response = self.client.post(reverse('analyst_ioc_remove'), {'pk': rec.pk})
        self.assertEqual(response.status_code, 302)
        rec.refresh_from_db()
        self.assertFalse(rec.is_active)
        self.assertEqual(rec.removed_by, self.forensic)
        # Still present via its ticket source, now analyst-less.
        self.assertEqual(self._rows()[HASH]['sources'], ['ticket'])

    def test_filters_status_source_category(self):
        self.import_rows([['TI-1', 'Hash', '', HASH, '']])
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='domain', value='only.ticket')
        IOCReviewStatus.objects.create(category='hash', value=HASH, checked=True)
        self.assertEqual(list(self._rows(status='checked')), [HASH])
        self.assertEqual(list(self._rows(status='not_checked')), ['only.ticket'])
        self.assertEqual(list(self._rows(source='analyst')), [HASH])
        self.assertEqual(list(self._rows(source='ticket')), ['only.ticket'])
        self.assertEqual(list(self._rows(category='domain')), ['only.ticket'])

    # ── Access boundaries ──────────────────────────────────────────────── #

    def test_forensic_can_manage_and_download(self):
        self.client.force_login(self.forensic)
        response = self.client.post(reverse('ioc_database_import'),
                                    {'file': csv_upload([['TI-1', 'Hash', '', HASH, '']])})
        self.assertRedirects(response, reverse('ioc_database'))
        page = self.client.get(reverse('ioc_database'))
        self.assertContains(page, 'IOC Database')
        self.assertContains(page, 'TI-1')
        self.assertContains(page, 'Upload analyst findings')
        self.assertContains(self.client.get(reverse('ioc_database_template')),
                            'ID,Category,File name,IOC detail,Note')
        download = self.client.get(reverse('analyst_ioc_download',
                                           args=[AnalystIOCImport.objects.get().pk]))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download['X-Content-Type-Options'], 'nosniff')

    def test_database_restricted_to_forensic_and_superuser(self):
        self.import_rows([['TI-1', 'Hash', '', HASH, '']])
        rec = AnalystIOC.objects.get()
        for account in [self.soc, self.admin,
                        user('ti-owner', UserProfile.ROLE_SYSTEM_OWNER),
                        user('ti-redteam', UserProfile.ROLE_REDTEAM_MANAGER),
                        user('ti-exec', UserProfile.ROLE_EXECUTIVE),
                        User.objects.create_user('ti-no-profile')]:
            with self.subTest(account=account.username):
                self.client.force_login(account)
                self.assertEqual(self.client.get(reverse('ioc_database')).status_code, 403)
                self.assertEqual(self.client.post(reverse('ioc_database_import')).status_code, 403)
                self.assertEqual(self.client.post(reverse('ioc_status_toggle'),
                                                  {'category': 'hash', 'value': HASH}).status_code, 403)
                self.assertEqual(self.client.post(reverse('analyst_ioc_remove'),
                                                  {'pk': rec.pk}).status_code, 403)
                self.assertNotContains(self.client.get(reverse('global_search')), 'data-label="IOC Database"')

    def test_login_required_and_bad_import_reports_row(self):
        self.assertEqual(self.client.get(reverse('ioc_database')).status_code, 302)
        self.client.force_login(self.forensic)
        response = self.client.post(reverse('ioc_database_import'),
                                    {'file': csv_upload([['TI-1', 'Hash', '', 'bad', '']])})
        self.assertContains(response, 'Row 2', status_code=400)
        self.assertFalse(AnalystIOCImport.objects.exists())

    def test_old_routes_are_gone(self):
        for name in ('ti_platform', 'ti_platform_status', 'ti_platform_mark', 'ioc_check'):
            with self.subTest(name=name), self.assertRaises(NoReverseMatch):
                reverse(name)

    # ── Ticket IOC integration ─────────────────────────────────────────── #

    def test_create_ticket_saves_multi_value_structured_iocs(self):
        self.client.force_login(self.soc)
        data = _ticket_post_data()
        data['ioc_ip'] = ['203[.]0[.]113[.]1', '10.0.0.5']
        data['ioc_hash'] = [HASH.upper()]
        data['ioc_url'] = ['https://bad.example.com/x']
        response = self.client.post(reverse('create_ticket'), data)
        self.assertEqual(response.status_code, 302)
        ticket = Ticket.objects.latest('id')
        values = {(r.category, r.value) for r in ticket.iocs.all()}
        self.assertEqual(values, {
            ('ip', '203.0.113.1'), ('ip', '10.0.0.5'),
            ('hash', HASH), ('url', 'https://bad.example.com/x'),
        })

    def test_ticket_form_rejects_invalid_ioc_value(self):
        form = TicketForm(_qd(_ticket_post_data(), ioc_hash=['not-a-hash']), user=self.soc)
        self.assertFalse(form.is_valid())
        self.assertIn('__all__', form.errors)

    def test_edit_records_ioc_change_audit(self):
        ticket = Ticket.objects.create(created_by=self.soc, device_name='H1')
        TicketIOC.objects.create(ticket=ticket, category='hash', value=HASH, order=0)
        form = TicketEditForm(_qd(_ticket_post_data(), ioc_ip=['203.0.113.1']), instance=ticket)
        self.assertTrue(form.is_valid(), form.errors)
        save_ticket_edit(ticket=ticket, actor=self.soc, edit_form=form, reason='Corrected')
        change = ticket.field_changes.get(field_name='iocs')
        self.assertIn('Hash', change.old_value)
        self.assertIn('203.0.113.1', change.new_value)
        self.assertEqual({(r.category, r.value) for r in ticket.iocs.all()}, {('ip', '203.0.113.1')})

    def test_project_incident_copies_iocs_to_all_members(self):
        self.client.force_login(self.soc)
        data = _pi_post_data(self.admin, self.admin)
        data['ioc_hash'] = [HASH]
        data['ioc_domain'] = ['example.org']
        response = self.client.post(reverse('create_project_incident'), data)
        self.assertEqual(response.status_code, 302)
        members = Ticket.objects.filter(project_incident__isnull=False)
        self.assertEqual(members.count(), 2)
        for ticket in members:
            self.assertEqual({(r.category, r.value) for r in ticket.iocs.all()},
                             {('hash', HASH), ('domain', 'example.org')})

    def test_report_context_aggregates_iocs_into_rows(self):
        ticket = Ticket.objects.create(created_by=self.soc, ioc_details='legacy note')
        for category, value in [('hash', HASH), ('ip', '203.0.113.1'),
                                ('domain', 'example.org'), ('url', 'https://bad.example.com/x'),
                                ('file_name', 'invoice.exe'), ('file_path', r'C:\tmp\a.exe')]:
            TicketIOC.objects.create(ticket=ticket, category=category, value=value)
        report = build_ticket_report_context(ticket)
        self.assertEqual(report['ioc_hash'], HASH)
        self.assertEqual(report['ioc_ip'], '203.0.113.1')
        self.assertEqual(report['ioc_domain'], 'example.org')
        self.assertEqual(report['ioc_url'], 'https://bad.example.com/x')
        for value in ('invoice.exe', r'C:\tmp\a.exe', 'legacy note'):
            self.assertIn(value, report['ioc_process'])

    def test_global_search_finds_ticket_by_ioc(self):
        ticket = Ticket.objects.create(created_by=self.soc, device_name='private-host')
        TicketIOC.objects.create(ticket=ticket, category='hash', value=HASH)
        TicketIOC.objects.create(ticket=ticket, category='ip', value='203.0.113.1')
        self.client.force_login(self.soc)
        response = self.client.get(reverse('global_search'), {'q': HASH})
        self.assertEqual(response.context['ticket_total'], 1)
        self.assertContains(response, 'private-host')
        response = self.client.get(reverse('global_search'), {'q': '203[.]0[.]113[.]1'})
        self.assertEqual(response.context['ticket_total'], 1)

    def test_ticket_forms_expose_six_fields_and_add_button(self):
        self.client.force_login(self.soc)
        ticket = Ticket.objects.create(created_by=self.soc)
        for route in (reverse('create_ticket'), reverse('create_project_incident'),
                      reverse('edit_ticket', args=[ticket.pk])):
            response = self.client.get(route)
            for name in ('ioc_file_name', 'ioc_hash', 'ioc_domain', 'ioc_ip', 'ioc_url', 'ioc_file_path'):
                self.assertContains(response, f'name="{name}"')
            self.assertContains(response, 'ioc-add')
