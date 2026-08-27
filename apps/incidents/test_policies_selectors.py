from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.wazuh_ingest.models import WazuhAlert

from .models import (
    Ticket,
    TicketAttachment,
    TicketFieldChange,
    TicketLog,
    TicketLogRevision,
    TicketSubtask,
    TriageRecord,
)
from .policies import (
    can_access_ticket_report,
    can_create_ticket_from_triage,
    can_create_ticket_from_wazuh,
    can_delete_ticket_attachment,
    can_edit_ticket,
    can_restore_ticket_attachment,
    can_upload_subtask_result,
    can_upload_ticket_attachment,
    holds_ticket_court,
    is_soc,
    is_soc_manager,
    user_can_drive,
)
from .selectors import get_ticket_detail_read_model


def _profile(**overrides):
    values = {
        'is_soc': False,
        'is_soc_manager': False,
        'is_tier1': False,
        'is_tier2': False,
        'is_system_admin': False,
        'is_system_owner': False,
        'tier': '',
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _user(pk, *, profile=None, is_superuser=False):
    values = {'pk': pk, 'id': pk, 'is_superuser': is_superuser}
    if profile is not None:
        values['profile'] = profile
    return SimpleNamespace(**values)


def _ticket(status, *, creator=1, admin=4, owner=5, claim_blocks=False):
    return SimpleNamespace(
        status=status,
        created_by_id=creator,
        assigned_admin_id=admin,
        system_owner_id=owner,
        t2_claim_blocks=lambda user: claim_blocks,
    )


class IncidentPolicyMatrixTest(SimpleTestCase):
    def setUp(self):
        self.t1 = _user(1, profile=_profile(is_soc=True, is_tier1=True, tier='T1'))
        self.t2 = _user(2, profile=_profile(is_soc=True, is_tier2=True, tier='T2'))
        self.manager = _user(3, profile=_profile(is_soc=True, is_soc_manager=True))
        self.admin = _user(4, profile=_profile(is_system_admin=True))
        self.owner = _user(5, profile=_profile(is_system_owner=True))
        self.outsider = _user(6)
        self.superuser = _user(7, is_superuser=True)

    def test_soc_role_and_report_policy_matrix(self):
        cases = (
            (self.t1, True, False),
            (self.t2, True, False),
            (self.manager, True, True),
            (self.admin, False, False),
            (self.owner, False, False),
            (self.outsider, False, False),
            (self.superuser, True, True),
        )
        for user, expected_soc, expected_manager in cases:
            with self.subTest(user=user.pk):
                self.assertEqual(is_soc(user), expected_soc)
                self.assertEqual(can_access_ticket_report(user), expected_soc)
                self.assertEqual(is_soc_manager(user), expected_manager)
                self.assertEqual(can_restore_ticket_attachment(user), expected_manager)

    def test_transition_permission_matrix(self):
        ticket = _ticket(Ticket.STATUS_NEW)
        cases = (
            (self.t1, 'TIER1_CREATOR', True),
            (self.t2, 'TIER2', True),
            (self.manager, 'MANAGER', True),
            (self.admin, 'TIER2', False),
            (self.superuser, 'UNKNOWN', True),
            (self.outsider, 'MANAGER', False),
        )
        for user, permission, expected in cases:
            with self.subTest(user=user.pk, permission=permission):
                self.assertEqual(user_can_drive(ticket, user, permission), expected)

    def test_ticket_court_matrix(self):
        cases = (
            (Ticket.STATUS_NEW, self.t1, True),
            (Ticket.STATUS_NEW, self.t2, False),
            (Ticket.STATUS_ESCALATED_T2, self.t2, True),
            (Ticket.STATUS_PENDING_MGR_TRIAGE, self.manager, True),
            (Ticket.STATUS_AWAITING_CONTAINMENT, self.admin, True),
            (Ticket.STATUS_AWAITING_OWNER, self.owner, True),
            (Ticket.STATUS_AWAITING_OWNER, self.t1, True),
            (Ticket.STATUS_AWAITING_OWNER, self.manager, False),
        )
        for status, user, expected in cases:
            with self.subTest(status=status, user=user.pk):
                self.assertEqual(holds_ticket_court(_ticket(status), user), expected)

    def test_attachment_policy_freezes_terminal_tickets(self):
        terminal = _ticket(Ticket.STATUS_APPROVED)
        attachment = SimpleNamespace(uploaded_by_id=self.superuser.pk, subtask_id=None)
        self.assertFalse(can_upload_ticket_attachment(terminal, self.superuser))
        self.assertFalse(
            can_delete_ticket_attachment(terminal, attachment, self.superuser)
        )

    def test_response_assignee_can_manage_only_their_deliverable(self):
        ticket = _ticket(Ticket.STATUS_PENDING_MGR_TRIAGE)
        subtask = SimpleNamespace(
            assigned_to_id=self.admin.pk,
            is_response_request=True,
        )
        attachment = SimpleNamespace(
            uploaded_by_id=self.t1.pk,
            subtask_id=10,
            subtask=subtask,
        )
        self.assertTrue(can_upload_subtask_result(subtask, self.admin))
        self.assertTrue(can_delete_ticket_attachment(ticket, attachment, self.admin))
        self.assertFalse(can_upload_subtask_result(subtask, self.t2))

    def test_edit_policy_respects_terminal_and_tier2_claims(self):
        self.assertTrue(can_edit_ticket(_ticket(Ticket.STATUS_NEW), self.t1))
        self.assertFalse(
            can_edit_ticket(
                _ticket(Ticket.STATUS_ESCALATED_T2, claim_blocks=True),
                self.t2,
            )
        )
        self.assertFalse(can_edit_ticket(_ticket(Ticket.STATUS_APPROVED), self.superuser))

    def test_manual_triage_conversion_policy_matrix(self):
        claimed = SimpleNamespace(
            ticket_id=None,
            project_incident_id=None,
            decision='',
            final_decision='',
            claimed_by_id=self.t1.pk,
            analyst_id=None,
            t2_decision='',
            escalated_to_id=None,
        )
        self.assertTrue(can_create_ticket_from_triage(claimed, self.t1))
        self.assertFalse(can_create_ticket_from_triage(claimed, self.t2))

        escalated_true_positive = SimpleNamespace(
            ticket_id=None,
            project_incident_id=None,
            decision=TriageRecord.DECISION_ESCALATED,
            final_decision=TriageRecord.DECISION_TP,
            claimed_by_id=None,
            analyst_id=self.t1.pk,
            t2_decision=TriageRecord.DECISION_TP,
            escalated_to_id=self.t2.pk,
        )
        self.assertTrue(
            can_create_ticket_from_triage(escalated_true_positive, self.t2)
        )
        self.assertTrue(
            can_create_ticket_from_triage(escalated_true_positive, self.superuser)
        )

    def test_wazuh_conversion_policy_matrix(self):
        alert = SimpleNamespace(
            claimed_by_id=self.t2.pk,
            project_incident_id=None,
            triage_status=WazuhAlert.TRIAGE_ESCALATED,
            escalated_to_tier=WazuhAlert.TIER_T2,
        )
        self.assertTrue(can_create_ticket_from_wazuh(alert, self.t2))
        self.assertFalse(can_create_ticket_from_wazuh(alert, self.t1))

        alert.claimed_by_id = self.superuser.pk
        self.assertTrue(can_create_ticket_from_wazuh(alert, self.superuser))

    def test_view_compatibility_imports_reference_shared_policies(self):
        from .views import (
            _can_access_ticket_report,
            _can_create_ticket_from_triage,
            _can_upload_ticket_attachment,
        )

        self.assertIs(_can_access_ticket_report, can_access_ticket_report)
        self.assertIs(_can_create_ticket_from_triage, can_create_ticket_from_triage)
        self.assertIs(_can_upload_ticket_attachment, can_upload_ticket_attachment)


class TicketDetailSelectorTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.manager = User.objects.create_user('selector-manager')
        UserProfile.objects.create(
            user=cls.manager,
            role=UserProfile.ROLE_SOC_MANAGER,
            department='SOC',
            phone='000',
        )
        cls.forensic = User.objects.create_user('selector-forensic')
        UserProfile.objects.create(
            user=cls.forensic,
            role=UserProfile.ROLE_FORENSIC,
            department='IR',
            phone='000',
        )
        cls.ticket = Ticket.objects.create(
            device_name='selector-host',
            ip_address='192.0.2.20',
            issue_description='Selector contract',
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            created_by=cls.manager,
        )
        cls.log = TicketLog.objects.create(
            ticket=cls.ticket,
            author=cls.manager,
            note='Original timeline note',
            status_at_time=Ticket.STATUS_PENDING_MGR_TRIAGE,
        )
        TicketLogRevision.objects.create(
            log=cls.log,
            previous_note='Earlier timeline note',
            edited_by=cls.manager,
        )
        cls.subtask = TicketSubtask.objects.create(
            ticket=cls.ticket,
            subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='Investigate endpoint',
            assigned_to=cls.forensic,
            created_by=cls.manager,
        )
        cls.standalone = TicketAttachment.all_objects.create(
            ticket=cls.ticket,
            file='ticket_attachments/selector/standalone.txt',
            original_name='standalone.txt',
            uploaded_by=cls.forensic,
        )
        cls.deliverable = TicketAttachment.all_objects.create(
            ticket=cls.ticket,
            subtask=cls.subtask,
            file='ticket_attachments/selector/deliverable.txt',
            original_name='deliverable.txt',
            uploaded_by=cls.forensic,
        )
        cls.deleted = TicketAttachment.all_objects.create(
            ticket=cls.ticket,
            file='ticket_attachments/selector/deleted.txt',
            original_name='deleted.txt',
            uploaded_by=cls.forensic,
            deleted_by=cls.manager,
            deleted_at=timezone.now(),
        )
        cls.direct_change = TicketFieldChange.objects.create(
            ticket=cls.ticket,
            field_name='issue_description',
            field_label='Issue description',
            old_value='Before',
            new_value='After',
            changed_by=cls.manager,
        )
        cls.subtask_status_change = TicketFieldChange.objects.create(
            ticket=cls.ticket,
            subtask=cls.subtask,
            field_name='status',
            field_label='Status',
            old_value=TicketSubtask.STATUS_OPEN,
            new_value=TicketSubtask.STATUS_IN_PROGRESS,
            changed_by=cls.manager,
        )
        cls.subtask_note_change = TicketFieldChange.objects.create(
            ticket=cls.ticket,
            subtask=cls.subtask,
            field_name='result_notes',
            field_label='Result notes',
            old_value='',
            new_value='Analysis complete',
            changed_by=cls.forensic,
        )

    def test_read_model_preserves_detail_page_query_contract(self):
        read_model = get_ticket_detail_read_model(
            ticket=self.ticket,
            user=self.manager,
            can_submit_containment=False,
            can_request_response=True,
        )

        self.assertEqual(
            [attachment.pk for attachment in read_model['attachments']],
            [self.standalone.pk],
        )
        self.assertTrue(read_model['attachments'][0].can_delete)

        subtasks = list(read_model['subtasks'])
        self.assertEqual([subtask.pk for subtask in subtasks], [self.subtask.pk])
        deliverables = list(subtasks[0].attachments.all())
        self.assertEqual([attachment.pk for attachment in deliverables], [self.deliverable.pk])
        self.assertTrue(deliverables[0].can_delete)

        self.assertEqual(
            {change.pk for change in read_model['field_changes']},
            {self.direct_change.pk, self.subtask_note_change.pk},
        )
        self.assertEqual(
            [attachment.pk for attachment in read_model['deleted_attachments']],
            [self.deleted.pk],
        )
        self.assertTrue(read_model['can_restore_attachment'])
        self.assertEqual(
            read_model['response_member_roles'][str(self.forensic.pk)],
            UserProfile.ROLE_FORENSIC,
        )
        self.assertEqual(
            list(read_model['logs'])[0].revisions.all()[0].previous_note,
            'Earlier timeline note',
        )

    def test_read_model_skips_privileged_optional_queries_when_not_authorized(self):
        read_model = get_ticket_detail_read_model(
            ticket=self.ticket,
            user=self.forensic,
            can_submit_containment=False,
            can_request_response=False,
        )

        self.assertFalse(read_model['can_restore_attachment'])
        self.assertEqual(read_model['deleted_attachments'], [])
        self.assertEqual(read_model['response_routing'], {})
        self.assertEqual(read_model['response_member_roles'], {})
