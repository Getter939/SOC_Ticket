import tempfile
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from apps.accounts.testing import MFATestCase as TestCase

from apps.accounts.models import UserProfile

from .models import Ticket, TicketAttachment, TicketLog, TicketSubtask
from .ticket_updates import save_subtask_update, save_ticket_edit


def _user(username, role, *, tier=''):
    user = User.objects.create_user(username=username, password='testpass123')
    UserProfile.objects.create(
        user=user,
        role=role,
        tier=tier,
        department='Test',
        phone='000',
    )
    return user


def _ticket(**overrides):
    values = {
        'device_name': 'updates-original-host',
        'ip_address': '192.0.2.175',
        'issue_description': 'Ticket update service contract',
        'classification': Ticket.CLASSIFICATION_INCIDENT,
    }
    values.update(overrides)
    return Ticket.objects.create(**values)


class _TicketEditForm:
    def __init__(self, ticket, device_name):
        self.ticket = ticket
        self.device_name = device_name

    def save(self):
        self.ticket.device_name = self.device_name
        self.ticket.save()
        return self.ticket


class _SubtaskUpdateForm:
    def __init__(self, subtask, status, result_notes):
        self.subtask = subtask
        self.status = status
        self.result_notes = result_notes

    def save(self):
        self.subtask.status = self.status
        self.subtask.result_notes = self.result_notes
        self.subtask.save()
        return self.subtask


@override_settings(MEDIA_ROOT=tempfile.mkdtemp(prefix='soc_ticket_updates_media_'))
class TicketUpdatesServiceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user(
            'ticket-updates-t1',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.forensic = _user('ticket-updates-forensic', UserProfile.ROLE_FORENSIC)

    def test_ticket_edit_uses_saved_snapshot_and_creates_both_audit_types(self):
        ticket = _ticket(created_by=self.t1)

        result = save_ticket_edit(
            ticket=ticket,
            actor=self.t1,
            edit_form=_TicketEditForm(ticket, 'updates-corrected-host'),
            reason='Corrected the hostname from the asset inventory.',
        )

        ticket.refresh_from_db()
        self.assertEqual(ticket.device_name, 'updates-corrected-host')
        self.assertEqual(len(result.changes), 1)
        self.assertEqual(ticket.field_changes.get().field_name, 'device_name')
        self.assertTrue(TicketLog.objects.filter(
            ticket=ticket,
            author=self.t1,
            note__contains='Corrected the hostname from the asset inventory.',
        ).exists())

    @patch('apps.incidents.ticket_updates.notify_response_request_completed', return_value=True)
    def test_subtask_update_audits_status_notes_and_notifies_once(self, notify_completed):
        ticket = _ticket(created_by=self.t1)
        subtask = TicketSubtask.objects.create(
            ticket=ticket,
            subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='Forensic RCA',
            assigned_to=self.forensic,
        )
        result = save_subtask_update(
            ticket=ticket,
            actor=self.forensic,
            update_form=_SubtaskUpdateForm(
                subtask,
                TicketSubtask.STATUS_DONE,
                'Confirmed credential theft and preserved the disk image.',
            ),
            previous_status=TicketSubtask.STATUS_OPEN,
            previous_notes='',
            was_done=False,
            result_upload=SimpleUploadedFile('rca.log', b'forensic findings'),
            result_description='Final RCA attachment',
        )

        subtask.refresh_from_db()
        self.assertEqual(subtask.status, TicketSubtask.STATUS_DONE)
        self.assertEqual(result.attachments[0].subtask, subtask)
        self.assertEqual(TicketAttachment.objects.filter(ticket=ticket).count(), 1)
        self.assertTrue(ticket.field_changes.filter(
            subtask=subtask,
            field_name='status',
        ).exists())
        self.assertTrue(ticket.field_changes.filter(
            subtask=subtask,
            field_name='result_notes',
        ).exists())
        self.assertTrue(result.completion_notified)
        notify_completed.assert_called_once_with(subtask)

    @patch('apps.incidents.ticket_updates.notify_response_request_completed')
    def test_already_done_subtask_does_not_notify_a_second_time(self, notify_completed):
        ticket = _ticket(created_by=self.t1)
        subtask = TicketSubtask.objects.create(
            ticket=ticket,
            subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='Forensic RCA',
            assigned_to=self.forensic,
            status=TicketSubtask.STATUS_DONE,
            result_notes='Initial report.',
        )

        result = save_subtask_update(
            ticket=ticket,
            actor=self.forensic,
            update_form=_SubtaskUpdateForm(
                subtask,
                TicketSubtask.STATUS_DONE,
                'Clarified the initial report.',
            ),
            previous_status=TicketSubtask.STATUS_DONE,
            previous_notes='Initial report.',
            was_done=True,
        )

        self.assertFalse(result.completion_notified)
        self.assertTrue(ticket.field_changes.filter(
            subtask=subtask,
            field_name='result_notes',
        ).exists())
        notify_completed.assert_not_called()
