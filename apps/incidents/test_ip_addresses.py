from django.core.exceptions import ValidationError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import SimpleTestCase, TransactionTestCase
from django.urls import reverse

from apps.accounts.testing import MFATestCase

from .forms import ProjectIncidentTargetForm, TicketEditForm, TicketForm, TicketReviewForm
from .ip_addresses import IPAddressListField, normalize_ip_addresses
from .models import Ticket
from .reports import build_ticket_report_context
from .tests import _make_t1, _ticket_post_data
from .ticket_updates import save_ticket_edit


class IPAddressValidationTest(SimpleTestCase):
    def test_accepts_mixed_separators_and_deduplicates_normalized_addresses(self):
        self.assertEqual(
            normalize_ip_addresses(
                '192.0.2.10,192.0.2.11\r\n2001:0DB8:0:0::1; 2001:db8::1 192.0.2.10'
            ),
            '192.0.2.10, 192.0.2.11, 2001:db8::1',
        )

    def test_rejects_invalid_member_and_non_address_values(self):
        for invalid in ('999.1.1.1', 'host.example', '192.0.2.0/24', 'bad::ip', 'fe80::1%eth0'):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                IPAddressListField().clean(f'192.0.2.10, {invalid}')

    def test_required_and_optional_empty_values(self):
        for blank in ('', None, '  '):
            with self.subTest(blank=blank):
                with self.assertRaises(ValidationError):
                    IPAddressListField().clean(blank)
                self.assertIsNone(IPAddressListField(required=False).clean(blank))
        with self.assertRaises(ValidationError):
            IPAddressListField().clean(', ; ,')

    def test_model_validates_each_address(self):
        field = Ticket._meta.get_field('ip_address')
        field.clean('192.0.2.10, 2001:db8::1', None)
        with self.assertRaises(ValidationError):
            field.clean('192.0.2.10, invalid', None)


class TicketMultipleIPTest(MFATestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = _make_t1('multiple-ip-t1')

    def test_create_persists_all_addresses_and_displays_them(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse('create_ticket'), _ticket_post_data(
            ip_address='192.0.2.10\n192.0.2.11, 2001:0db8::1',
        ))
        self.assertEqual(response.status_code, 302)
        ticket = Ticket.objects.get()
        expected = '192.0.2.10, 192.0.2.11, 2001:db8::1'
        self.assertEqual(ticket.ip_address, expected)
        self.assertContains(self.client.get(reverse('ticket_detail', args=[ticket.pk])), expected)
        self.assertEqual(build_ticket_report_context(ticket)['ip_address'], expected)
        self.assertTrue(Ticket.objects.filter(ip_address__icontains='192.0.2.11').exists())

    def test_forms_reject_an_invalid_address(self):
        for form_class in (TicketForm, TicketEditForm, TicketReviewForm, ProjectIncidentTargetForm):
            with self.subTest(form=form_class.__name__):
                form = form_class(data=_ticket_post_data(ip_address='192.0.2.10, invalid'))
                self.assertFalse(form.is_valid())
                self.assertIn('ip_address', form.errors)

    def test_edit_and_review_round_trip_with_history(self):
        create_form = TicketForm(data=_ticket_post_data())
        self.assertTrue(create_form.is_valid(), create_form.errors)
        ticket = create_form.save()
        expected = '192.0.2.10, 2001:db8::2'
        edit_form = TicketEditForm(
            instance=ticket, data=_ticket_post_data(ip_address='192.0.2.10\n2001:db8::2'),
        )
        self.assertTrue(edit_form.is_valid(), edit_form.errors)
        save_ticket_edit(ticket=ticket, actor=self.user, edit_form=edit_form, reason='Added IPv6')
        ticket.refresh_from_db()
        self.assertEqual(ticket.ip_address, expected)
        change = ticket.field_changes.get(field_name='ip_address')
        self.assertEqual(change.old_value, '192.0.2.10')
        self.assertEqual(change.new_value, expected)
        review_form = TicketReviewForm(instance=ticket, data=_ticket_post_data(ip_address=expected))
        self.assertTrue(review_form.is_valid(), review_form.errors)
        review_form.save()
        ticket.refresh_from_db()
        self.assertEqual(ticket.ip_address, expected)
        self.assertEqual(TicketEditForm(instance=ticket)['ip_address'].value(), expected)

    def test_project_target_supports_multiple_or_no_addresses(self):
        for value, expected in (('192.0.2.1\n2001:db8::1', '192.0.2.1, 2001:db8::1'), ('', None)):
            with self.subTest(value=value):
                form = ProjectIncidentTargetForm(data={
                    'device_name': 'service', 'ip_address': value,
                    't1_route': Ticket.T1_ROUTE_OWNER,
                })
                self.assertTrue(form.is_valid(), form.errors)
                ticket = form.save()
                ticket.refresh_from_db()
                self.assertEqual(ticket.ip_address, expected)


class TicketIPMigrationTest(TransactionTestCase):
    def test_existing_ipv4_ipv6_and_null_survive_migration(self):
        previous = [('incidents', '0068_tiplatformioc_added_by_and_more')]
        latest = [('incidents', '0069_ticket_multiple_ip_addresses')]
        executor = MigrationExecutor(connection)
        executor.migrate(previous)
        try:
            old_ticket = executor.loader.project_state(previous).apps.get_model('incidents', 'Ticket')
            ids = []
            for index, value in enumerate(('192.0.2.10', '2001:db8::1', None)):
                ticket = old_ticket.objects.create(
                    ticket_id=f'IP-MIGRATION-{index}', device_name='existing',
                    issue_description='Existing ticket', ip_address=value,
                )
                ids.append((ticket.pk, value))
            executor = MigrationExecutor(connection)
            executor.migrate(latest)
            # Read with the model at 0069, not today's model: later migrations
            # may add columns that deliberately do not exist at this point.
            migrated_ticket = executor.loader.project_state(latest).apps.get_model('incidents', 'Ticket')
            for ticket_id, expected in ids:
                self.assertEqual(migrated_ticket.objects.get(pk=ticket_id).ip_address, expected)
        finally:
            # Restore to the ACTUAL latest (leaf nodes), not the hardcoded target
            # above — otherwise migrations added after 0069 leave the schema behind
            # the models and TransactionTestCase's flush fails on an orphaned table.
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes())
