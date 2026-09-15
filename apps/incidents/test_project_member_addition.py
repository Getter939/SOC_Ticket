from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase

from .forms import ProjectIncidentTargetForm
from .models import ProjectIncident, ProjectIncidentLog, Ticket, TicketLog
from .policies import can_add_project_member
from .project_workflow import add_project_member


def _user(username, role, *, tier='', email=''):
    user = User.objects.create_user(
        username=username,
        password='testpass123',
        email=email,
    )
    UserProfile.objects.create(
        user=user,
        role=role,
        tier=tier,
        department='Test',
        phone='000',
    )
    return user


class ProjectMemberAdditionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.creator = _user(
            'member-add-creator',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.other_t1 = _user(
            'member-add-other',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.manager = _user('member-add-manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _user(
            'member-add-admin',
            UserProfile.ROLE_SYSTEM_ADMIN,
            email='member-admin@example.com',
        )

    def _project(self, *, reviewed=False, emergency=False, lead_status=None):
        project = ProjectIncident.objects.create(
            title='Late spread across systems',
            summary='Shared incident summary',
            created_by=self.creator,
            is_emergency=emergency,
            emergency_decided_by=self.manager if reviewed else None,
            emergency_decided_at=timezone.now() if reviewed else None,
        )
        lead = Ticket.objects.create(
            project_incident=project,
            bundle_suffix='A',
            incident_name=project.title,
            device_name='Original host',
            system_detail='Original host detail',
            ip_address='192.0.2.10',
            severity='High',
            ncsa_severity=Ticket.NCSA_SEVERITY_SEVERE,
            incident_datetime=timezone.now(),
            log_source='Wazuh',
            issue_type='SIEM',
            detailed_issue='Malicious Logic',
            detailed_issue2='C2 Server',
            issue_description=project.summary,
            action_required='Isolate affected systems.',
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=Ticket.T1_ROUTE_ADMIN,
            status=lead_status or (
                Ticket.STATUS_AWAITING_CONTAINMENT
                if reviewed else Ticket.STATUS_PENDING_MGR_TRIAGE
            ),
            created_by=self.creator,
            assigned_to=self.creator,
            assigned_admin=self.admin,
            is_emergency=emergency,
        )
        lead.iocs.create(category='DOMAIN', value='malicious.example', order=0)
        return project, lead

    def _form(self, route=Ticket.T1_ROUTE_ADMIN, **overrides):
        data = {
            'device_name': 'Newly reported host',
            'system_detail': 'Reported after the original ticket was opened',
            'ip_address': '192.0.2.20',
            'asset_type': 'Server',
            'operating_system': 'Windows Server 2022',
            'asset_owner': 'Infrastructure',
            'asset_owner_name': 'Example Owner',
            'assigned_admin': str(self.admin.pk),
            't1_route': route,
        }
        data.update(overrides)
        form = ProjectIncidentTargetForm(data=data)
        self.assertTrue(form.is_valid(), form.errors)
        return form

    def _post_data(self, route=Ticket.T1_ROUTE_ADMIN, **overrides):
        data = {
            'action': 'add_project_member',
            'member-device_name': 'Newly reported host',
            'member-system_detail': 'Reported after project creation',
            'member-ip_address': '192.0.2.20',
            'member-asset_type': 'Server',
            'member-operating_system': 'Windows Server 2022',
            'member-asset_owner': 'Infrastructure',
            'member-asset_owner_name': 'Example Owner',
            'member-assigned_admin': str(self.admin.pk),
            'member-t1_route': route,
        }
        data.update(overrides)
        return data

    def test_permission_is_limited_to_creator_and_manager_while_active(self):
        project, lead = self._project()

        self.assertTrue(can_add_project_member(project, self.creator))
        self.assertTrue(can_add_project_member(project, self.manager))
        self.assertFalse(can_add_project_member(project, self.other_t1))

        lead.status = Ticket.STATUS_APPROVED
        lead.save(update_fields=('status', 'updated_at'))
        self.assertFalse(can_add_project_member(project, self.creator))
        self.assertFalse(can_add_project_member(project, self.manager))

    @patch('apps.incidents.project_workflow.notify_containment_alert', return_value=True)
    def test_reviewed_project_inherits_decision_and_routes_directly(self, notify_admin):
        project, lead = self._project(reviewed=True, emergency=True)

        result = add_project_member(
            project=project,
            target_form=self._form(),
            actor=self.manager,
        )

        ticket = result.tickets[0]
        self.assertEqual(ticket.bundle_suffix, 'B')
        self.assertEqual(ticket.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertTrue(ticket.is_emergency)
        self.assertEqual(ticket.emergency_decided_by, self.manager)
        self.assertEqual(ticket.emergency_decided_at, project.emergency_decided_at)
        self.assertEqual(ticket.created_by, self.creator)
        self.assertEqual(ticket.severity, lead.severity)
        self.assertEqual(ticket.incident_datetime, lead.incident_datetime)
        self.assertEqual(ticket.issue_description, lead.issue_description)
        self.assertEqual(
            list(ticket.iocs.values_list('category', 'value')),
            [('DOMAIN', 'malicious.example')],
        )
        self.assertIsNotNone(ticket.report_issued_at)
        self.assertTrue(TicketLog.objects.filter(ticket=ticket, author=self.manager).exists())
        self.assertTrue(ProjectIncidentLog.objects.filter(
            project=project,
            author=self.manager,
            note__contains=ticket.bundle_ref,
        ).exists())
        notify_admin.assert_called_once_with(ticket, reason=None)

    @patch('apps.incidents.project_workflow.notify_manager_triage_pending')
    def test_unreviewed_incident_waits_for_existing_project_review(self, notify_manager):
        project, _lead = self._project()

        ticket = add_project_member(
            project=project,
            target_form=self._form(),
            actor=self.creator,
        ).tickets[0]

        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertFalse(ticket.is_emergency)
        notify_manager.assert_called_once_with(ticket)

    def test_event_goes_to_tier2_and_does_not_keep_admin_assignment(self):
        project, _lead = self._project(reviewed=True, emergency=True)

        ticket = add_project_member(
            project=project,
            target_form=self._form(ProjectIncidentTargetForm.ROUTE_EVENT),
            actor=self.manager,
        ).tickets[0]

        self.assertEqual(ticket.classification, Ticket.CLASSIFICATION_EVENT)
        self.assertEqual(ticket.status, Ticket.STATUS_ESCALATED_T2)
        self.assertEqual(ticket.classification_at_escalation, Ticket.CLASSIFICATION_EVENT)
        self.assertFalse(ticket.is_emergency)
        self.assertIsNone(ticket.assigned_admin)

    def test_reviewed_owner_decision_proceeds_directly_to_owner_route(self):
        project, _lead = self._project(reviewed=True)

        ticket = add_project_member(
            project=project,
            target_form=self._form(Ticket.T1_ROUTE_OWNER),
            actor=self.creator,
        ).tickets[0]

        self.assertEqual(ticket.status, Ticket.STATUS_AWAITING_OWNER)
        self.assertTrue(ticket.direct_owner_remediation)
        self.assertIsNotNone(ticket.owner_contacted_at)
        self.assertIsNone(ticket.assigned_admin)

    def test_creator_can_add_from_detail_page_and_invalid_form_reopens_modal(self):
        project, _lead = self._project(reviewed=True)
        self.client.login(username=self.creator.username, password='testpass123')

        page = self.client.get(reverse('project_incident_detail', args=[project.pk]))
        self.assertContains(page, 'เพิ่มระบบที่ได้รับผลกระทบ')

        invalid = self.client.post(
            reverse('project_incident_detail', args=[project.pk]),
            self._post_data(**{
                'member-device_name': '',
                'member-assigned_admin': '',
            }),
        )
        self.assertEqual(invalid.status_code, 200)
        self.assertContains(invalid, 'window.bootstrap.Modal.getOrCreateInstance')
        self.assertEqual(project.member_count, 1)

        response = self.client.post(
            reverse('project_incident_detail', args=[project.pk]),
            self._post_data(),
        )
        self.assertRedirects(
            response,
            reverse('project_incident_detail', args=[project.pk]),
        )
        self.assertEqual(project.member_count, 2)

    def test_service_rejects_addition_after_every_member_is_closed(self):
        project, _lead = self._project(lead_status=Ticket.STATUS_APPROVED)

        with self.assertRaisesMessage(ValidationError, 'ปิดครบทุก Ticket'):
            add_project_member(
                project=project,
                target_form=self._form(),
                actor=self.manager,
            )

    def test_unrelated_tier1_cannot_see_or_submit_the_add_control(self):
        project, _lead = self._project()
        self.client.login(username=self.other_t1.username, password='testpass123')

        page = self.client.get(reverse('project_incident_detail', args=[project.pk]))
        self.assertNotContains(page, 'data-bs-target="#addProjectMemberModal"')

        response = self.client.post(
            reverse('project_incident_detail', args=[project.pk]),
            self._post_data(),
            follow=True,
        )
        self.assertContains(response, 'เฉพาะผู้เปิด Project Incident หรือผู้จัดการ SOC')
        self.assertEqual(project.member_count, 1)
