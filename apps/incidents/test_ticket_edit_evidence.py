import tempfile
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from apps.accounts.testing import MFATestCase as TestCase

from .models import ProjectIncident, StagedAttachment, Ticket, TicketAttachment, TicketLog
from .tests import _make_t1, _make_t2, _make_ticket


class TicketEditEvidenceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.creator = _make_t1('edit_evidence_creator')
        cls.other = _make_t1('edit_evidence_other')

    def setUp(self):
        media = tempfile.TemporaryDirectory(prefix='soc_edit_evidence_')
        self.addCleanup(media.cleanup)
        settings = override_settings(MEDIA_ROOT=media.name)
        settings.enable()
        self.addCleanup(settings.disable)
        self.ticket = _make_ticket(
            created_by=self.creator, status=Ticket.STATUS_NEW,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            device_name='original', issue_description='Evidence test',
            ip_address='192.0.2.1', incident_datetime=timezone.now().replace(second=0, microsecond=0),
            severity='High', ncsa_severity=Ticket.NCSA_SEVERITY_SEVERE,
            log_source='Wazuh', issue_type='SIEM',
            detailed_issue='Investigating', detailed_issue2='Investigating Other',
        )
        self.url = reverse('edit_ticket', args=[self.ticket.pk])
        self.client.force_login(self.creator)

    def payload(self, **overrides):
        fields = (
            'classification', 'incident_name', 'severity', 'ncsa_severity',
            'log_source', 'issue_type', 'detailed_issue', 'detailed_issue2',
            'device_name', 'issue_description', 'ip_address',
        )
        data = {field: getattr(self.ticket, field) or '' for field in fields}
        data['incident_datetime'] = timezone.localtime(
            self.ticket.incident_datetime,
        ).strftime('%Y-%m-%dT%H:%M')
        data['reason'] = 'Additional investigation evidence'
        data.update(overrides)
        return data

    def upload(self, name='evidence.log'):
        return SimpleUploadedFile(name, b'investigation evidence')

    def test_picker_matches_create_form_and_follows_upload_permission(self):
        response = self.client.get(self.url)
        self.assertContains(response, 'enctype="multipart/form-data"')
        self.assertContains(response, 'แนบไฟล์หลักฐาน (รูปภาพ / เอกสาร)')
        self.assertContains(response, 'name="evidence_files"')
        self.assertContains(response, 'attachment-limits-data')
        self.client.force_login(self.other)
        response = self.client.get(self.url)
        self.assertNotContains(response, 'name="evidence_files"')
        self.assertContains(response, 'ยังไม่มีสิทธิ์แนบไฟล์')

    def test_saves_multiple_files_and_content_with_audit(self):
        existing = TicketAttachment.objects.create(
            ticket=self.ticket, file=self.upload('existing.log'),
            original_name='existing.log', uploaded_by=self.creator,
        )
        response = self.client.post(self.url, self.payload(
            device_name='corrected', evidence_files=[self.upload(), self.upload('second.txt')],
        ))
        self.assertRedirects(response, reverse('ticket_detail', args=[self.ticket.pk]))
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.device_name, 'corrected')
        self.assertEqual(self.ticket.status, Ticket.STATUS_NEW)
        self.assertEqual(self.ticket.attachments.count(), 3)
        self.assertTrue(self.ticket.attachments.filter(pk=existing.pk).exists())
        self.assertEqual(self.ticket.attachments.filter(uploaded_by=self.creator).count(), 3)
        self.assertFalse(StagedAttachment.objects.exists())
        log = TicketLog.objects.get(ticket=self.ticket, note__contains='แนบไฟล์หลักฐาน')
        self.assertIn('evidence.log', log.note)
        self.assertIn('Additional investigation evidence', log.note)
        self.assertEqual(log.author, self.creator)

    def test_attachment_only_edit_reports_success(self):
        response = self.client.post(
            self.url, self.payload(evidence_files=[self.upload()]), follow=True,
        )
        self.assertContains(response, 'แนบไฟล์หลักฐาน 1 ไฟล์เรียบร้อยแล้ว')
        self.assertNotContains(response, 'ไม่มีข้อมูลที่เปลี่ยนแปลง')

    def test_member_editor_and_project_uploads_keep_evidence_separate(self):
        project = ProjectIncident.objects.create(title='Two affected systems', created_by=self.creator)
        self.ticket.project_incident = project
        self.ticket.bundle_suffix = 'A'
        self.ticket.save(update_fields=['project_incident', 'bundle_suffix'])
        sibling = _make_ticket(
            created_by=self.creator, status=Ticket.STATUS_NEW,
            project_incident=project, bundle_suffix='B',
        )
        sibling_file = TicketAttachment.objects.create(
            ticket=sibling, file=self.upload('system-b.log'),
            original_name='system-b.log', uploaded_by=self.creator,
        )
        editor = self.client.get(self.url)
        self.assertContains(editor, f'หลักฐานเฉพาะ Ticket #{self.ticket.ticket_id}')
        response = self.client.post(self.url, self.payload(
            evidence_files=[self.upload('system-a.log')],
        ))
        self.assertRedirects(response, reverse('ticket_detail', args=[self.ticket.pk]))
        self.assertEqual(self.ticket.attachments.get().original_name, 'system-a.log')
        self.assertEqual(sibling.attachments.get(), sibling_file)
        self.assertFalse(project.attachments.exists())

        # Uploading central evidence later does not copy it into either member.
        tier2 = _make_t2('shared_evidence_tier2')
        self.client.force_login(tier2)
        response = self.client.post(
            reverse('upload_project_attachment', args=[project.pk]),
            {'file': self.upload('shared-case.log')},
        )
        self.assertRedirects(response, reverse('project_incident_detail', args=[project.pk]))
        self.assertEqual(project.attachments.get().original_name, 'shared-case.log')
        self.assertEqual(self.ticket.attachments.count(), 1)
        self.assertEqual(sibling.attachments.count(), 1)

        pages = (
            ('ticket_detail', self.ticket.pk, 'system-a.log'),
            ('ticket_detail', sibling.pk, 'system-b.log'),
            ('project_incident_detail', project.pk, 'shared-case.log'),
        )
        for route, pk, own_file in pages:
            with self.subTest(route=route, pk=pk):
                page = self.client.get(reverse(route, args=[pk]))
                self.assertContains(page, own_file)
                for other_file in ('system-a.log', 'system-b.log', 'shared-case.log'):
                    if other_file != own_file:
                        self.assertNotContains(page, other_file)

    def test_validation_errors_preserve_uploads_and_reason_until_retry(self):
        for overrides in ({'device_name': ''}, {'reason': ''}):
            with self.subTest(overrides=overrides):
                response = self.client.post(self.url, self.payload(
                    evidence_files=[self.upload()], **overrides,
                ))
                self.assertEqual(response.status_code, 200)
                token = response.context['evidence_token']
                self.assertContains(response, 'ไฟล์ที่ระบบเก็บไว้ให้แล้ว')
                self.assertEqual(response.context['reason'], overrides.get(
                    'reason', 'Additional investigation evidence',
                ))
                staged = StagedAttachment.objects.get(token=token)
                self.assertTrue(staged.file.storage.exists(staged.file.name))
                count = self.ticket.attachments.count()
                response = self.client.post(self.url, self.payload(evidence_token=token))
                self.assertEqual(response.status_code, 302)
                self.assertEqual(self.ticket.attachments.count(), count + 1)
                self.assertFalse(StagedAttachment.objects.filter(token=token).exists())

    def test_invalid_file_blocks_edit_but_keeps_valid_file_for_retry(self):
        response = self.client.post(self.url, self.payload(
            device_name='must not save', evidence_files=[self.upload(), self.upload('bad.exe')],
        ))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'bad.exe')
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.device_name, 'original')
        self.assertFalse(self.ticket.attachments.exists())
        self.assertEqual(StagedAttachment.objects.get().original_name, 'evidence.log')

    def test_file_size_and_batch_limits_block_edit(self):
        for limit in ('apps.incidents.models.attachments.MAX_ATTACHMENT_SIZE',
                      'apps.incidents.staging.MAX_ATTACHMENT_BATCH_SIZE',
                      'apps.incidents.staging.MAX_ATTACHMENT_COUNT'):
            with self.subTest(limit=limit), patch(limit, 0):
                response = self.client.post(self.url, self.payload(evidence_files=[self.upload()]))
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.context['form'].non_field_errors())
                self.assertFalse(self.ticket.attachments.exists())

    def test_creator_can_append_evidence_while_an_active_ticket_is_out_of_court(self):
        Ticket.objects.filter(pk=self.ticket.pk).update(status=Ticket.STATUS_AWAITING_CONTAINMENT)
        response = self.client.post(
            self.url,
            self.payload(device_name='corrected', evidence_files=[self.upload()]),
        )
        self.assertEqual(response.status_code, 302)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.device_name, 'corrected')
        attachment = self.ticket.attachments.get()
        self.assertEqual(attachment.uploaded_by, self.creator)

    def test_cannot_adopt_another_users_staged_files(self):
        staged = StagedAttachment.objects.create(
            token='a' * 32, file=self.upload(), original_name='private.log', uploaded_by=self.other,
        )
        response = self.client.post(self.url, self.payload(evidence_token=staged.token))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(self.ticket.attachments.exists())
        self.assertTrue(StagedAttachment.objects.filter(pk=staged.pk).exists())

    def test_even_superuser_cannot_upload_to_closed_ticket(self):
        self.creator.is_superuser = True
        self.creator.save(update_fields=['is_superuser'])
        for status in (Ticket.STATUS_APPROVED, Ticket.STATUS_CLOSED_EVENT, Ticket.STATUS_CANCELLED):
            with self.subTest(status=status):
                Ticket.objects.filter(pk=self.ticket.pk).update(status=status)
                self.client.post(self.url, self.payload(evidence_files=[self.upload()]))
                self.assertFalse(self.ticket.attachments.exists())
                self.assertFalse(StagedAttachment.objects.exists())

    def test_attachment_failure_rolls_back_content_edit(self):
        with patch('apps.incidents.ticket_updates.adopt_staged', side_effect=ValidationError('failed')):
            response = self.client.post(self.url, self.payload(
                device_name='must roll back', evidence_files=[self.upload()],
            ))
        self.assertEqual(response.status_code, 302)
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.device_name, 'original')
        self.assertFalse(self.ticket.field_changes.exists())
        self.assertFalse(self.ticket.attachments.exists())
