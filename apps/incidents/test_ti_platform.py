"""IOC Database: manual entry, the two-source unified view, per-indicator
annotations (status + note), edit/remove, access boundaries and ticket integration."""

import re

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.http import QueryDict
from django.urls import NoReverseMatch, reverse

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase
from .forms import ProjectIncidentForm, TicketEditForm, TicketForm
from .models import AnalystIOC, IOCReviewStatus, Ticket, TicketIOC
from .reports import build_ticket_report_context
from .tests import _pi_post_data, _ticket_post_data
from .ticket_updates import save_ticket_edit
from .ti_platform import build_ioc_database, create_manual_iocs

HASH = 'ab' * 32
OTHER_HASH = 'cd' * 32


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


def entry_post(entries, **extra):
    """Build a POST payload for the manual-entry formset."""
    data = {
        'form-TOTAL_FORMS': str(len(entries)), 'form-INITIAL_FORMS': '0',
        'form-MIN_NUM_FORMS': '0', 'form-MAX_NUM_FORMS': '1000',
    }
    for index, entry in enumerate(entries):
        for field in ('category', 'value', 'file_name', 'note'):
            data[f'form-{index}-{field}'] = entry.get(field, '')
    data.update(extra)
    return data


class IOCDatabaseTests(MFATestCase):
    @classmethod
    def setUpTestData(cls):
        cls.forensic = user('ti-forensic', UserProfile.ROLE_FORENSIC)
        cls.soc = user('ti-soc', UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T1)
        cls.admin = user('ti-admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _rows(self, **kwargs):
        return {row['value']: row for row in build_ioc_database(**kwargs)[0]}

    def add_manual(self, **entry):
        entry.setdefault('file_name', '')
        entry.setdefault('note', '')
        return create_manual_iocs([entry], self.forensic)[0][1]

    # ── Manual entry ───────────────────────────────────────────────────── #

    def test_manual_add_creates_rows_with_generated_ids(self):
        self.client.force_login(self.forensic)
        response = self.client.post(reverse('ioc_manual_add'), entry_post([
            {'category': 'hash', 'value': HASH.upper(), 'file_name': 'invoice.exe', 'note': 'Loader'},
            {'category': 'ip', 'value': '203[.]0[.]113[.]1', 'note': 'C2'},
        ]))
        self.assertRedirects(response, reverse('ioc_database'))
        self.assertEqual(AnalystIOC.objects.count(), 2)
        by_value = {rec.ioc_detail: rec for rec in AnalystIOC.objects.all()}
        self.assertEqual(set(by_value), {HASH, '203.0.113.1'})          # normalized
        self.assertEqual(by_value[HASH].file_name, 'invoice.exe')
        self.assertEqual(by_value[HASH].added_by, self.forensic)
        for rec in by_value.values():
            self.assertRegex(rec.ext_id, r'^MAN-\d{4,}$')
        self.assertEqual(len({rec.ext_id for rec in by_value.values()}), 2)
        # Notes land on the shared annotation and surface on the row.
        self.assertEqual(self._rows()[HASH]['note'], 'Loader')

    def test_file_name_is_ignored_for_non_hash_categories(self):
        self.client.force_login(self.forensic)
        self.client.post(reverse('ioc_manual_add'), entry_post([
            {'category': 'ip', 'value': '198.51.100.7', 'file_name': 'should-be-dropped.exe'},
        ]))
        self.assertEqual(AnalystIOC.objects.get().file_name, '')

    def test_manual_add_reports_an_invalid_value(self):
        self.client.force_login(self.forensic)
        response = self.client.post(reverse('ioc_manual_add'), entry_post([
            {'category': 'hash', 'value': 'not-a-hash'},
        ]))
        self.assertEqual(response.status_code, 400)
        self.assertFalse(AnalystIOC.objects.exists())
        self.assertTrue(response.context['entry_open'])   # section re-opens on errors

    def test_duplicates_blocked_against_ticket_and_manual(self):
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='domain', value='ticket.example')
        self.assertEqual(self.add_manual(category='hash', value=HASH), 'created')
        # Same value as a ticket IOC, and same value as an existing manual one.
        self.assertEqual(self.add_manual(category='domain', value='ticket.example'), 'duplicate')
        self.assertEqual(self.add_manual(category='hash', value=HASH), 'duplicate')
        self.assertEqual(AnalystIOC.objects.count(), 1)

    def test_removed_value_is_restored_when_retyped(self):
        self.add_manual(category='hash', value=HASH)
        rec = AnalystIOC.objects.get()
        original_id = rec.ext_id
        self.client.force_login(self.forensic)
        self.client.post(reverse('analyst_ioc_remove'), {'pk': rec.pk})
        rec.refresh_from_db()
        self.assertFalse(rec.is_active)
        self.assertNotIn(HASH, self._rows())
        self.assertEqual(self.add_manual(category='hash', value=HASH), 'restored')
        rec.refresh_from_db()
        self.assertTrue(rec.is_active)
        self.assertIsNone(rec.removed_by)
        self.assertEqual(rec.ext_id, original_id)          # same record, same id
        self.assertEqual(AnalystIOC.objects.count(), 1)

    # ── Annotations: status + note on any row ──────────────────────────── #

    def test_status_toggle_is_shared_across_sources(self):
        self.add_manual(category='hash', value=HASH)
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='hash', value=HASH)
        self.client.force_login(self.forensic)
        self.client.post(reverse('ioc_status_toggle'),
                         {'category': 'hash', 'value': HASH, 'checked': '1'})
        row = self._rows()[HASH]
        self.assertEqual(row['status'], 'checked')
        self.assertEqual(set(row['sources']), {'ticket', 'analyst'})
        self.client.post(reverse('ioc_status_toggle'), {'category': 'hash', 'value': HASH})
        self.assertEqual(self._rows()[HASH]['status'], 'not_checked')

    def test_note_can_be_saved_on_a_ticket_sourced_row(self):
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='domain', value='only.ticket')
        self.client.force_login(self.forensic)
        response = self.client.post(reverse('ioc_note_save'), {
            'category': 'domain', 'value': 'only.ticket', 'note': 'Seen in phishing kit'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._rows()['only.ticket']['note'], 'Seen in phishing kit')
        self.assertContains(self.client.get(reverse('ioc_database')), 'Seen in phishing kit')

    def test_note_and_status_survive_each_other(self):
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='ip', value='203.0.113.9')
        self.client.force_login(self.forensic)
        self.client.post(reverse('ioc_note_save'),
                         {'category': 'ip', 'value': '203.0.113.9', 'note': 'keep me'})
        self.client.post(reverse('ioc_status_toggle'),
                         {'category': 'ip', 'value': '203.0.113.9', 'checked': '1'})
        annotation = IOCReviewStatus.objects.get(category='ip', value='203.0.113.9')
        self.assertEqual((annotation.note, annotation.checked), ('keep me', True))

    # ── Edit / remove ──────────────────────────────────────────────────── #

    def test_edit_moves_the_annotation_to_the_new_value(self):
        self.add_manual(category='ip', value='203.0.113.1', note='first note')
        rec = AnalystIOC.objects.get()
        self.client.force_login(self.forensic)
        self.client.post(reverse('ioc_status_toggle'),
                         {'category': 'ip', 'value': '203.0.113.1', 'checked': '1'})
        response = self.client.post(reverse('ioc_manual_edit'), {
            'pk': rec.pk, 'category': 'ip', 'value': '203.0.113.2', 'file_name': ''})
        self.assertEqual(response.status_code, 302)
        rec.refresh_from_db()
        self.assertEqual(rec.ioc_detail, '203.0.113.2')
        row = self._rows()['203.0.113.2']
        self.assertEqual((row['note'], row['status']), ('first note', 'checked'))
        self.assertFalse(IOCReviewStatus.objects.filter(value='203.0.113.1').exists())

    def test_edit_rejects_a_duplicate_value(self):
        self.add_manual(category='ip', value='203.0.113.1')
        self.add_manual(category='ip', value='203.0.113.2')
        rec = AnalystIOC.objects.get(ioc_detail='203.0.113.1')
        self.client.force_login(self.forensic)
        self.client.post(reverse('ioc_manual_edit'), {
            'pk': rec.pk, 'category': 'ip', 'value': '203.0.113.2', 'file_name': ''})
        rec.refresh_from_db()
        self.assertEqual(rec.ioc_detail, '203.0.113.1')    # unchanged

    def test_remove_keeps_a_ticket_twin(self):
        self.add_manual(category='hash', value=HASH)
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='hash', value=HASH)
        rec = AnalystIOC.objects.get()
        self.client.force_login(self.forensic)
        self.client.post(reverse('analyst_ioc_remove'), {'pk': rec.pk})
        rec.refresh_from_db()
        self.assertFalse(rec.is_active)
        self.assertEqual(rec.removed_by, self.forensic)
        self.assertEqual(self._rows()[HASH]['sources'], ['ticket'])

    # ── View, filters, access ──────────────────────────────────────────── #

    def test_filters_status_source_category(self):
        self.add_manual(category='hash', value=HASH)
        ticket = Ticket.objects.create(created_by=self.soc)
        TicketIOC.objects.create(ticket=ticket, category='domain', value='only.ticket')
        IOCReviewStatus.objects.create(category='hash', value=HASH, checked=True)
        self.assertEqual(list(self._rows(status='checked')), [HASH])
        self.assertEqual(list(self._rows(status='not_checked')), ['only.ticket'])
        self.assertEqual(list(self._rows(source='analyst')), [HASH])
        self.assertEqual(list(self._rows(source='ticket')), ['only.ticket'])
        self.assertEqual(list(self._rows(category='domain')), ['only.ticket'])

    def test_page_shows_entry_section_note_column_and_manual_badge(self):
        self.add_manual(category='hash', value=HASH, note='a note')
        self.client.force_login(self.forensic)
        page = self.client.get(reverse('ioc_database'))
        self.assertContains(page, reverse('ioc_manual_add'))     # entry form present
        self.assertContains(page, 'form-0-category')             # formset row rendered
        self.assertContains(page, 'data-entry-add')              # + row button
        self.assertContains(page, 'a note')                      # Note column
        self.assertContains(page, '>Manual<')                    # source badge relabelled
        self.assertRegex(page.content.decode(), r'MAN-\d{4,}')

    def test_database_restricted_to_forensic_and_superuser(self):
        self.add_manual(category='hash', value=HASH)
        rec = AnalystIOC.objects.get()
        for account in [self.soc, self.admin,
                        user('ti-owner', UserProfile.ROLE_SYSTEM_OWNER),
                        user('ti-redteam', UserProfile.ROLE_REDTEAM_MANAGER),
                        user('ti-exec', UserProfile.ROLE_EXECUTIVE),
                        User.objects.create_user('ti-no-profile')]:
            with self.subTest(account=account.username):
                self.client.force_login(account)
                self.assertEqual(self.client.get(reverse('ioc_database')).status_code, 403)
                self.assertEqual(self.client.post(reverse('ioc_manual_add'), entry_post([])).status_code, 403)
                self.assertEqual(self.client.post(reverse('ioc_note_save'), {
                    'category': 'hash', 'value': HASH, 'note': 'x'}).status_code, 403)
                self.assertEqual(self.client.post(reverse('ioc_manual_edit'), {
                    'pk': rec.pk, 'category': 'hash', 'value': OTHER_HASH}).status_code, 403)
                self.assertEqual(self.client.post(reverse('ioc_status_toggle'), {
                    'category': 'hash', 'value': HASH}).status_code, 403)
                self.assertEqual(self.client.post(reverse('analyst_ioc_remove'), {
                    'pk': rec.pk}).status_code, 403)
                self.assertNotContains(self.client.get(reverse('global_search')), 'data-label="IOC Database"')

    def test_login_required(self):
        self.assertEqual(self.client.get(reverse('ioc_database')).status_code, 302)

    def test_removed_routes_are_gone(self):
        for name in ('ti_platform', 'ti_platform_status', 'ti_platform_mark', 'ioc_check',
                     'ioc_database_import', 'ioc_database_template', 'analyst_ioc_download'):
            with self.subTest(name=name), self.assertRaises(NoReverseMatch):
                reverse(name)

    # ── Ticket IOC integration (unchanged behaviour) ───────────────────── #

    def test_create_ticket_saves_multi_value_structured_iocs(self):
        self.client.force_login(self.soc)
        data = _ticket_post_data()
        data['ioc_ip'] = ['203[.]0[.]113[.]1', '10.0.0.5']
        data['ioc_hash'] = [HASH.upper()]
        data['ioc_url'] = ['https://bad.example.com/x']
        response = self.client.post(reverse('create_ticket'), data)
        self.assertEqual(response.status_code, 302)
        ticket = Ticket.objects.latest('id')
        self.assertEqual({(r.category, r.value) for r in ticket.iocs.all()}, {
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

    def test_project_incident_copies_iocs_to_all_members(self):
        self.client.force_login(self.soc)
        data = _pi_post_data(self.admin, self.admin)
        data['ioc_hash'] = [HASH]
        data['ioc_domain'] = ['example.org']
        self.assertEqual(self.client.post(reverse('create_project_incident'), data).status_code, 302)
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
        # File Name now has its own Section-4 row; File Path + legacy notes
        # remain folded into 'Process/File Path'.
        self.assertEqual(report['ioc_file_name'], 'invoice.exe')
        for value in (r'C:\tmp\a.exe', 'legacy note'):
            self.assertIn(value, report['ioc_process'])
        self.assertNotIn('invoice.exe', report['ioc_process'])

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
