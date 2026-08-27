from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.wazuh_ingest.models import WazuhAlert

from .case_creation import (
    BUNDLE_SHARED_FIELDS,
    create_project_incident_from_forms,
    create_ticket_from_form,
    load_alert_bundle,
)
from .forms import TicketForm
from .models import ProjectIncident, Ticket, TriageRecord


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


class _TicketForm:
    def __init__(self, ticket, route):
        self.ticket = ticket
        self.cleaned_data = {'t1_route': route}

    def save(self, commit=False):
        assert commit is False
        return self.ticket


class _ProjectForm:
    def __init__(self, shared):
        self.cleaned_data = shared


class _TargetForm:
    def __init__(self, ticket, route=Ticket.T1_ROUTE_ADMIN):
        self.ticket = ticket
        self.cleaned_data = {'t1_route': route}

    def save(self, commit=False):
        assert commit is False
        return self.ticket


class CaseCreationServiceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user(
            'creation-t1',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.other_t1 = _user(
            'creation-other-t1',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.admin_a = _user('creation-admin-a', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b = _user('creation-admin-b', UserProfile.ROLE_SYSTEM_ADMIN)

    def _alert(self, suffix, *, owner=None):
        return WazuhAlert.objects.create(
            opensearch_id=f'case-creation-{suffix}',
            timestamp=timezone.now(),
            rule_level=12,
            rule_description=f'Alert {suffix}',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=owner or self.t1,
            claimed_at=timezone.now(),
        )

    def _ticket(self, **overrides):
        values = {
            'device_name': 'creation-host',
            'ip_address': '192.0.2.45',
            'issue_description': 'Creation service contract',
            'classification': Ticket.CLASSIFICATION_INCIDENT,
        }
        values.update(overrides)
        return Ticket(**values)

    def _shared_data(self):
        template = self._ticket(
            log_source='Wazuh',
            issue_type='SIEM',
            detailed_issue='Malicious Logic',
            detailed_issue2='C2 Server',
            severity='High',
            ncsa_severity=Ticket.NCSA_SEVERITY_SEVERE,
        )
        shared = {field_name: getattr(template, field_name) for field_name in BUNDLE_SHARED_FIELDS}
        shared.update(
            title='Creation service Project Incident',
            issue_description='Shared incident facts',
            actions_taken_summary='Initial isolation complete',
            next_steps_summary='Await manager review',
        )
        return shared

    @patch('apps.incidents.case_creation.notify_manager_triage_pending')
    @patch('apps.incidents.case_creation.adopt_staged')
    def test_single_ticket_consumes_triage_and_alert_bundle(self, adopt_staged, notify_manager):
        primary = self._alert('primary')
        supporting = self._alert('supporting')
        triage = TriageRecord.objects.create(
            source=TriageRecord.SOURCE_EMAIL,
            alert_description='Reported suspicious activity',
            claimed_by=self.t1,
            claimed_at=timezone.now(),
        )
        form = _TicketForm(
            self._ticket(wazuh_alert=primary),
            TicketForm.ROUTE_ESCALATE_T2,
        )

        result = create_ticket_from_form(
            form=form,
            actor=self.t1,
            triage=triage,
            alert_bundle_ids=(primary.pk, supporting.pk),
            evidence_token='a' * 32,
        )

        ticket = result.ticket
        self.assertEqual(ticket.status, Ticket.STATUS_ESCALATED_T2)
        self.assertEqual(ticket.created_by, self.t1)
        self.assertEqual(
            {link.alert_id: link.role for link in ticket.alert_links.all()},
            {primary.pk: 'PRIMARY', supporting.pk: 'SUPPORTING'},
        )
        triage.refresh_from_db()
        primary.refresh_from_db()
        supporting.refresh_from_db()
        self.assertEqual(triage.ticket, ticket)
        self.assertEqual(triage.decision, TriageRecord.DECISION_TP)
        self.assertEqual(primary.triage_status, WazuhAlert.TRIAGE_TRUE_POSITIVE)
        self.assertEqual(supporting.triage_status, WazuhAlert.TRIAGE_TRUE_POSITIVE)
        self.assertTrue(ticket.logs.filter(note__contains='Alert Bundle').exists())
        adopt_staged.assert_called_once_with('a' * 32, self.t1, ticket=ticket)
        notify_manager.assert_not_called()

    @patch('apps.incidents.case_creation.notify_manager_triage_pending')
    @patch('apps.incidents.case_creation.adopt_staged')
    def test_single_incident_admin_route_notifies_manager(self, adopt_staged, notify_manager):
        form = _TicketForm(
            self._ticket(assigned_admin=self.admin_a),
            TicketForm.ROUTE_ASSIGN_ADMIN,
        )

        result = create_ticket_from_form(form=form, actor=self.t1)

        ticket = result.ticket
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(ticket.t1_route, Ticket.T1_ROUTE_ADMIN)
        notify_manager.assert_called_once_with(ticket)
        adopt_staged.assert_called_once_with('', self.t1, ticket=ticket)

    @patch('apps.incidents.case_creation.notify_manager_triage_pending')
    @patch('apps.incidents.case_creation.adopt_staged')
    def test_project_bundle_consumes_both_source_types_and_adopts_shared_evidence(
        self,
        adopt_staged,
        notify_manager,
    ):
        alert = self._alert('project-alert')
        triage = TriageRecord.objects.create(
            source=TriageRecord.SOURCE_PHONE,
            alert_description='Multi-system incident report',
            claimed_by=self.t1,
            claimed_at=timezone.now(),
        )
        targets = (
            _TargetForm(self._ticket(device_name='host-a', assigned_admin=self.admin_a)),
            _TargetForm(self._ticket(device_name='host-b', assigned_admin=self.admin_b)),
        )

        result = create_project_incident_from_forms(
            shared_form=_ProjectForm(self._shared_data()),
            target_formset=targets,
            actor=self.t1,
            source_alert=alert,
            source_triage=triage,
            evidence_token='b' * 32,
        )

        project = result.project
        self.assertEqual(len(result.tickets), 2)
        self.assertEqual([ticket.bundle_suffix for ticket in result.tickets], ['A', 'B'])
        self.assertTrue(all(ticket.project_incident_id == project.pk for ticket in result.tickets))
        self.assertTrue(
            all(ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE for ticket in result.tickets)
        )
        alert.refresh_from_db()
        triage.refresh_from_db()
        self.assertEqual(alert.project_incident, project)
        self.assertEqual(triage.project_incident, project)
        adopt_staged.assert_called_once_with('b' * 32, self.t1, project=project)
        notify_manager.assert_called_once_with(result.tickets[0])

    @patch('apps.incidents.case_creation.adopt_staged')
    def test_project_bundle_rolls_back_when_fewer_than_two_members(self, adopt_staged):
        target = _TargetForm(self._ticket(assigned_admin=self.admin_a))

        with self.assertRaisesMessage(ValidationError, 'อย่างน้อย 2 ระบบ'):
            create_project_incident_from_forms(
                shared_form=_ProjectForm(self._shared_data()),
                target_formset=(target,),
                actor=self.t1,
            )

        self.assertFalse(ProjectIncident.objects.exists())
        self.assertFalse(Ticket.objects.exists())
        adopt_staged.assert_not_called()

    def test_alert_bundle_rejects_records_owned_by_another_tier1(self):
        owned = self._alert('owned')
        other = self._alert('other', owner=self.other_t1)

        with self.assertRaisesMessage(ValidationError, str(other.pk)):
            load_alert_bundle((owned.pk, other.pk), self.t1)
