import tempfile

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from apps.accounts.testing import MFATestCase as TestCase

from apps.accounts.models import UserProfile

from .models import Ticket, TicketAttachment, TicketLog, TicketSubtask
from .ticket_evidence import (
    add_ticket_attachments,
    delete_ticket_attachment,
    restore_ticket_attachment,
)


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
        'device_name': 'evidence-workflow-host',
        'ip_address': '192.0.2.155',
        'issue_description': 'Ticket evidence service contract',
        'classification': Ticket.CLASSIFICATION_INCIDENT,
    }
    values.update(overrides)
    return Ticket.objects.create(**values)


@override_settings(MEDIA_ROOT=tempfile.mkdtemp(prefix='soc_ticket_evidence_media_'))
class TicketEvidenceServiceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user(
            'ticket-evidence-t1',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.manager = _user('ticket-evidence-manager', UserProfile.ROLE_SOC_MANAGER)

    def test_adds_a_batch_and_response_subtask_deliverable(self):
        ticket = _ticket(created_by=self.t1)
        batch = add_ticket_attachments(
            ticket=ticket,
            actor=self.t1,
            uploads=(
                SimpleUploadedFile('first.log', b'first evidence'),
                SimpleUploadedFile('second.txt', b'second evidence'),
            ),
            description='Collected during investigation',
        )
        subtask = TicketSubtask.objects.create(
            ticket=ticket,
            subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='Forensic RCA',
            assigned_to=self.manager,
        )
        deliverable = add_ticket_attachments(
            ticket=ticket,
            actor=self.manager,
            uploads=(SimpleUploadedFile('rca.log', b'findings'),),
            description='Final RCA',
            subtask=subtask,
        )

        self.assertEqual(len(batch.attachments), 2)
        self.assertEqual([item.original_name for item in batch.attachments], [
            'first.log', 'second.txt',
        ])
        self.assertEqual(deliverable.attachments[0].subtask, subtask)
        self.assertEqual(TicketAttachment.objects.filter(ticket=ticket).count(), 3)
        self.assertFalse(TicketLog.objects.filter(ticket=ticket).exists())

    def test_soft_delete_retains_file_and_audits_the_full_reason(self):
        ticket = _ticket(created_by=self.t1)
        attachment = add_ticket_attachments(
            ticket=ticket,
            actor=self.t1,
            uploads=(SimpleUploadedFile('retain.log', b'keep the bytes'),),
        ).attachments[0]
        file_name = attachment.file.name
        reason = 'r' * 300

        result = delete_ticket_attachment(
            attachment=attachment,
            actor=self.t1,
            reason=reason,
        )

        retained = TicketAttachment.all_objects.get(pk=attachment.pk)
        self.assertEqual(result.ticket, ticket)
        self.assertEqual(retained.deleted_by, self.t1)
        self.assertEqual(retained.deleted_reason, reason[:255])
        self.assertTrue(retained.file.storage.exists(file_name))
        self.assertFalse(TicketAttachment.objects.filter(pk=attachment.pk).exists())
        self.assertTrue(TicketLog.objects.filter(
            ticket=ticket,
            author=self.t1,
            note__contains=reason,
        ).exists())

    def test_restore_clears_deletion_data_even_after_ticket_closes(self):
        ticket = _ticket(created_by=self.t1)
        attachment = add_ticket_attachments(
            ticket=ticket,
            actor=self.t1,
            uploads=(SimpleUploadedFile('restore.log', b'restore me'),),
        ).attachments[0]
        delete_ticket_attachment(
            attachment=attachment,
            actor=self.t1,
            reason='Wrong case',
        )
        Ticket.objects.filter(pk=ticket.pk).update(status=Ticket.STATUS_APPROVED)

        restore_ticket_attachment(attachment=attachment, actor=self.manager)

        attachment.refresh_from_db()
        self.assertIsNone(attachment.deleted_at)
        self.assertIsNone(attachment.deleted_by)
        self.assertEqual(attachment.deleted_reason, '')
        self.assertTrue(TicketAttachment.objects.filter(pk=attachment.pk).exists())
        self.assertTrue(TicketLog.objects.filter(
            ticket=ticket,
            author=self.manager,
            note__contains='Attachment restored: restore.log',
        ).exists())
