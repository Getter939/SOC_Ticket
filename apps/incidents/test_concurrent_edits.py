"""A workflow action never silently overwrites a save that landed after its copy
of the ticket (or response request) was loaded."""

from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase
from apps.incidents.forms import SubtaskUpdateForm
from apps.incidents.models import Ticket, TicketSubtask
from apps.incidents.ticket_updates import save_subtask_update
from apps.incidents.tests import _make_forensic, _make_t1, _make_ticket, _make_user


class TransitionLostUpdateTest(TestCase):
    def setUp(self):
        self.t1 = _make_t1('race_t1')
        self.admin = _make_user('race_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        self.ticket = _make_ticket(
            created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=Ticket.T1_ROUTE_ADMIN,
            assigned_admin=self.admin,
        )

    def test_refuses_to_overwrite_a_newer_save(self):
        stale = Ticket.objects.get(pk=self.ticket.pk)
        editor = Ticket.objects.get(pk=self.ticket.pk)
        editor.issue_description = 'corrected by someone else'
        editor.save()

        with self.assertRaises(ValidationError):
            stale.transition_to(Ticket.STATUS_PENDING_MGR_TRIAGE, self.t1, 'submit')

        fresh = Ticket.objects.get(pk=self.ticket.pk)
        self.assertEqual(fresh.issue_description, 'corrected by someone else')
        self.assertEqual(fresh.status, Ticket.STATUS_NEW)

    def test_unchanged_row_transitions_and_keeps_update_only_stamps(self):
        """Stamps written with queryset .update() (claims, "seen" markers, report
        exports) don't bump updated_at; the transition's full save must carry
        them through instead of rolling them back."""
        loaded = Ticket.objects.get(pk=self.ticket.pk)
        seen_at = timezone.now()
        Ticket.objects.filter(pk=self.ticket.pk).update(
            creator_seen_at=seen_at, report_sha256='abc123',
        )

        loaded.transition_to(Ticket.STATUS_PENDING_MGR_TRIAGE, self.t1, 'submit')

        fresh = Ticket.objects.get(pk=self.ticket.pk)
        self.assertEqual(fresh.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(fresh.creator_seen_at, seen_at)
        self.assertEqual(fresh.report_sha256, 'abc123')


class SubtaskLostUpdateTest(TestCase):
    def setUp(self):
        self.forensic = _make_forensic('race_forensic')
        self.manager = _make_user('race_mgr', UserProfile.ROLE_SOC_MANAGER)
        self.ticket = _make_ticket(classification=Ticket.CLASSIFICATION_INCIDENT)
        self.subtask = TicketSubtask.objects.create(
            ticket=self.ticket, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='RCA', assigned_to=self.forensic,
        )

    def _submit(self, instance, notes, actor):
        form = SubtaskUpdateForm(
            {'status': instance.status, 'result_notes': notes, 'report_number': ''},
            instance=instance,
        )
        self.assertTrue(form.is_valid(), form.errors)
        return save_subtask_update(
            ticket=self.ticket, actor=actor, update_form=form,
            previous_status=instance.status, previous_notes=instance.result_notes,
            was_done=False,
        )

    def test_second_writer_on_a_stale_copy_is_refused(self):
        stale = TicketSubtask.objects.get(pk=self.subtask.pk)
        self._submit(TicketSubtask.objects.get(pk=self.subtask.pk), 'assignee findings',
                     self.forensic)

        with self.assertRaises(ValidationError):
            self._submit(stale, 'manager note typed on an old page', self.manager)

        self.assertEqual(
            TicketSubtask.objects.get(pk=self.subtask.pk).result_notes, 'assignee findings',
        )

    def test_fresh_copy_saves(self):
        self._submit(TicketSubtask.objects.get(pk=self.subtask.pk), 'first', self.forensic)
        self._submit(TicketSubtask.objects.get(pk=self.subtask.pk), 'second', self.manager)
        self.assertEqual(TicketSubtask.objects.get(pk=self.subtask.pk).result_notes, 'second')
