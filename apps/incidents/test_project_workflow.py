import tempfile
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from apps.accounts.models import UserProfile

from .models import ProjectIncident, ProjectIncidentLog, Ticket, TicketLog
from .project_workflow import (
    add_shared_attachments,
    delete_shared_attachment,
    forward_project_review,
    reassess_project_emergency,
    restore_shared_attachment,
)


def _user(username, role, *, tier='', email=''):
    user = User.objects.create_user(username=username, password='testpass123', email=email)
    UserProfile.objects.create(
        user=user,
        role=role,
        tier=tier,
        department='Test',
        phone='000',
    )
    return user


def _member(project, **overrides):
    values = {
        'project_incident': project,
        'device_name': 'project-workflow-host',
        'ip_address': '192.0.2.101',
        'issue_description': 'Project workflow service contract',
        'classification': Ticket.CLASSIFICATION_INCIDENT,
        'status': Ticket.STATUS_PENDING_MGR_TRIAGE,
        't1_route': Ticket.T1_ROUTE_ADMIN,
    }
    values.update(overrides)
    return Ticket.objects.create(**values)


@override_settings(MEDIA_ROOT=tempfile.mkdtemp(prefix='soc_project_workflow_media_'))
class ProjectWorkflowServiceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user(
            'project-workflow-t1',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.manager = _user('project-workflow-manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _user(
            'project-workflow-admin',
            UserProfile.ROLE_SYSTEM_ADMIN,
            email='admin@example.com',
        )
        cls.owner = _user(
            'project-workflow-owner',
            UserProfile.ROLE_SYSTEM_OWNER,
            email='owner@example.com',
        )

    def _project(self, **overrides):
        values = {'title': 'Project workflow service contract', 'created_by': self.t1}
        values.update(overrides)
        return ProjectIncident.objects.create(**values)

    @patch('apps.incidents.project_workflow.notify_containment_alert', return_value=False)
    def test_forward_records_one_group_verdict_and_routes_each_member(self, notify_containment):
        project = self._project()
        admin_member = _member(project, assigned_admin=self.admin)
        owner_member = _member(
            project,
            ip_address='192.0.2.102',
            t1_route=Ticket.T1_ROUTE_OWNER,
            system_owner=self.owner,
        )

        result = forward_project_review(
            project=project,
            actor=self.manager,
            want_emergency=True,
            note='Shared urgent response.',
        )

        project.refresh_from_db()
        admin_member.refresh_from_db()
        owner_member.refresh_from_db()
        self.assertTrue(project.is_emergency)
        self.assertEqual(project.emergency_decided_by, self.manager)
        self.assertEqual(admin_member.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertEqual(owner_member.status, Ticket.STATUS_AWAITING_OWNER)
        self.assertTrue(admin_member.is_emergency)
        self.assertTrue(owner_member.is_emergency)
        self.assertEqual(len(result.warnings), 1)
        self.assertTrue(ProjectIncidentLog.objects.filter(
            project=project,
            note__contains='Project Review: Emergency',
        ).exists())
        notify_containment.assert_called_once_with(admin_member, reason=None)

    def test_forward_requires_at_least_one_pending_member(self):
        project = self._project()
        _member(project, status=Ticket.STATUS_AWAITING_CONTAINMENT)

        with self.assertRaisesMessage(ValidationError, 'ไม่มี Member Ticket ที่รอ Project Review'):
            forward_project_review(
                project=project,
                actor=self.manager,
                want_emergency=False,
                note='Nothing is waiting.',
            )

        project.refresh_from_db()
        self.assertIsNone(project.emergency_decided_at)
        self.assertFalse(ProjectIncidentLog.objects.filter(project=project).exists())

    def test_reassessment_updates_only_active_members_and_audits_changes(self):
        project = self._project(is_emergency=True, emergency_decided_by=self.manager)
        project.emergency_decided_at = project.created_at
        project.save(update_fields=('emergency_decided_at', 'updated_at'))
        active = _member(
            project,
            status=Ticket.STATUS_AWAITING_CONTAINMENT,
            is_emergency=True,
        )
        terminal = _member(
            project,
            ip_address='192.0.2.102',
            status=Ticket.STATUS_APPROVED,
            is_emergency=True,
        )
        pending = _member(
            project,
            ip_address='192.0.2.103',
            is_emergency=True,
        )
        event = _member(
            project,
            ip_address='192.0.2.104',
            classification=Ticket.CLASSIFICATION_EVENT,
            status=Ticket.STATUS_ESCALATED_T2,
        )

        result = reassess_project_emergency(
            project=project,
            actor=self.manager,
            value=False,
            reason='Scope reduced after validation.',
        )

        project.refresh_from_db()
        active.refresh_from_db()
        terminal.refresh_from_db()
        pending.refresh_from_db()
        event.refresh_from_db()
        self.assertFalse(project.is_emergency)
        self.assertFalse(active.is_emergency)
        self.assertTrue(terminal.is_emergency)
        self.assertTrue(pending.is_emergency)
        self.assertFalse(event.is_emergency)
        self.assertEqual(result.tickets, (active,))
        self.assertTrue(TicketLog.objects.filter(
            ticket=active,
            note__contains='Project Reassess Emergency',
        ).exists())

    def test_shared_attachment_lifecycle_keeps_recovery_audit_history(self):
        project = self._project()
        upload = SimpleUploadedFile('evidence.txt', b'evidence', content_type='text/plain')

        added = add_shared_attachments(
            project=project,
            actor=self.t1,
            uploads=[upload],
            description='Initial shared evidence',
        )
        attachment = added.attachments[0]
        delete_shared_attachment(
            attachment=attachment,
            actor=self.t1,
            reason='Incorrect export',
        )
        attachment.refresh_from_db()
        self.assertEqual(attachment.deleted_by, self.t1)
        self.assertEqual(attachment.deleted_reason, 'Incorrect export')

        restore_shared_attachment(attachment=attachment, actor=self.manager)
        attachment.refresh_from_db()
        self.assertIsNone(attachment.deleted_at)
        self.assertEqual(attachment.deleted_reason, '')
        self.assertTrue(ProjectIncidentLog.objects.filter(
            project=project,
            note__contains='กู้คืนหลักฐานส่วนกลาง: evidence.txt',
        ).exists())
