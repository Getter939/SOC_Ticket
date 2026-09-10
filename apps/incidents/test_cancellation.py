from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone

from apps.accounts.testing import MFATestCase
from apps.accounts.models import UserProfile
from .cancellation import can_request_cancellation
from .models import Ticket, TicketCancellationRequest, TicketSubtask, ProjectIncident
from .test_ticket_workflow import _ticket, _user
from .ticket_workflow import cancellation_action


class CancellationTests(MFATestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user('cancel-t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.other = _user('cancel-other', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.t2 = _user('cancel-t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.manager = _user('cancel-manager', UserProfile.ROLE_SOC_MANAGER, email='manager@example.test')
        cls.admin = _user('cancel-admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.forensic = _user('cancel-forensic', UserProfile.ROLE_FORENSIC)

    def setUp(self):
        self.ticket = _ticket(created_by=self.t1, assigned_admin=self.admin,
                              status=Ticket.STATUS_AWAITING_CONTAINMENT,
                              severity='High', ola_contain_deadline=timezone.now() + timedelta(hours=1))

    def request_cancel(self, ticket=None, actor=None, **kwargs):
        return cancellation_action(ticket=ticket or self.ticket, actor=actor or self.t1,
                                   action='request', reason='CREATED_IN_ERROR',
                                   explanation='สร้างรายการผิดระบบ', **kwargs)

    def approve(self, record, **kwargs):
        return cancellation_action(ticket=self.ticket, actor=self.manager, action='approve',
                                   request_id=record.pk, decision_note='ตรวจสอบแล้ว อนุมัติยกเลิก', **kwargs)

    def test_request_preserves_stage_clock_and_history(self):
        before = self.ticket.status_changed_at, self.ticket.ola_contain_deadline
        record = self.request_cancel()
        self.ticket.refresh_from_db()
        self.assertEqual(record.status, 'PENDING')
        self.assertEqual(self.ticket.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertEqual(before, (self.ticket.status_changed_at, self.ticket.ola_contain_deadline))
        self.assertIn('ขอยกเลิก', self.ticket.logs.first().note)

    def test_manager_approval_is_distinct_from_resolution(self):
        self.approve(self.request_cancel())
        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.status, Ticket.STATUS_CANCELLED)
        self.assertIsNotNone(self.ticket.closed_at)
        self.assertIsNone(self.ticket.approved_by)
        self.assertIsNone(self.ticket.verified_by)
        self.assertIsNone(self.ticket.t2_claimed_by)
        self.assertFalse(self.ticket.is_ola_breached)

    def test_creator_can_cancel_only_new_ticket(self):
        for ticket, allowed in ((self.ticket, False), (_ticket(created_by=self.t1), True)):
            args = dict(ticket=ticket, actor=self.t1, action='direct',
                        reason='OTHER', explanation='เปิดผิดรายการ')
            if allowed:
                record = cancellation_action(**args)
                self.assertEqual(record.mode, 'CREATOR')
            else:
                with self.assertRaises(ValidationError):
                    cancellation_action(**args)

    def test_current_admin_can_request_but_cannot_approve(self):
        record = self.request_cancel(actor=self.admin)
        with self.assertRaises(ValidationError):
            cancellation_action(ticket=self.ticket, actor=self.admin, action='approve',
                                request_id=record.pk, decision_note='ลองอนุมัติ')

    def test_unrelated_analyst_and_response_team_cannot_request(self):
        for user in (self.other, self.forensic):
            with self.assertRaises(ValidationError):
                self.request_cancel(actor=user)

    def test_t2_claim_blocks_another_analyst(self):
        ticket = _ticket(status=Ticket.STATUS_ESCALATED_T2, created_by=self.t1,
                         t2_claimed_by=self.t2, t2_claimed_at=timezone.now())
        other_t2 = _user('cancel-other-t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        self.assertFalse(can_request_cancellation(ticket, other_t2))
        self.assertTrue(can_request_cancellation(ticket, self.t2))

    def test_rejection_preserves_current_stage_and_allows_new_request(self):
        record = self.request_cancel()
        self.ticket.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin, 'รายงานผล')
        cancellation_action(ticket=self.ticket, actor=self.manager, action='reject',
                            request_id=record.pk, decision_note='ยังต้องดำเนินการต่อ')
        self.assertEqual(self.ticket.status, Ticket.STATUS_CONTAINMENT_REPORTED)
        self.request_cancel()
        self.assertEqual(self.ticket.cancellation_requests.count(), 2)

    def test_withdraw_is_requester_only(self):
        record = self.request_cancel()
        with self.assertRaises(ValidationError):
            cancellation_action(ticket=self.ticket, actor=self.manager, action='withdraw', request_id=record.pk)
        cancellation_action(ticket=self.ticket, actor=self.t1, action='withdraw', request_id=record.pk)
        record.refresh_from_db()
        self.assertEqual(record.status, 'WITHDRAWN')

    def test_only_one_pending_request_and_repeat_decisions_rejected(self):
        record = self.request_cancel()
        with self.assertRaises(ValidationError):
            self.request_cancel()
        with self.assertRaises(IntegrityError), transaction.atomic():
            TicketCancellationRequest.objects.create(ticket=self.ticket, reason='OTHER', explanation='ซ้ำ')
        self.approve(record)
        with self.assertRaises(ValidationError):
            self.approve(record)

    def test_duplicate_requires_accessible_other_ticket(self):
        for duplicate in (None, self.ticket):
            with self.assertRaises(ValidationError):
                cancellation_action(ticket=self.ticket, actor=self.t1, action='request',
                                    reason='DUPLICATE', explanation='รายการซ้ำ', duplicate_of=duplicate)
        original = _ticket(created_by=self.t1)
        record = cancellation_action(ticket=self.ticket, actor=self.t1, action='request',
                                     reason='DUPLICATE', explanation='รายการซ้ำ', duplicate_of=original)
        self.approve(record)
        self.assertEqual(record.duplicate_of_id, original.pk)

    def test_duplicate_target_revalidated_at_approval(self):
        original = _ticket(created_by=self.t1)
        record = cancellation_action(ticket=self.ticket, actor=self.t1, action='request',
                                     reason='DUPLICATE', explanation='ซ้ำ', duplicate_of=original)
        cancellation_action(ticket=original, actor=self.manager, action='direct',
                            reason='OTHER', explanation='ต้นฉบับเปิดผิดเช่นกัน')
        with self.assertRaises(ValidationError):
            self.approve(record)

    def test_all_outstanding_work_requires_explicit_selection(self):
        task = TicketSubtask.objects.create(ticket=self.ticket, title='ตรวจสอบหลักฐาน',
                                           subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
                                           assigned_to=self.forensic)
        record = self.request_cancel()
        with self.assertRaises(ValidationError):
            self.approve(record)
        task.refresh_from_db()
        self.assertEqual(task.status, TicketSubtask.STATUS_OPEN)
        self.approve(record, cancel_subtask_ids=[task.pk])
        task.refresh_from_db()
        self.assertEqual(task.status, TicketSubtask.STATUS_CANCELLED)
        self.assertFalse(task.is_done)
        self.assertTrue(self.ticket.field_changes.exists())

    def test_cancellation_cannot_be_posted_as_normal_transition(self):
        with self.assertRaises(ValidationError):
            self.ticket.transition_to(Ticket.STATUS_CANCELLED, self.manager, 'ข้ามขั้นตอน')
        with self.assertRaises(ValidationError):
            _ticket(pk=999999, status=Ticket.STATUS_CANCELLED)

    def test_stale_ticket_and_subtask_writes_cannot_resurrect_cancelled_work(self):
        stale = Ticket.objects.get(pk=self.ticket.pk)
        task = TicketSubtask.objects.create(ticket=self.ticket, title='ตรวจสอบ', subtask_type=TicketSubtask.TYPE_INVESTIGATION)
        self.approve(self.request_cancel(), cancel_subtask_ids=[task.pk])
        with self.assertRaises(ValidationError):
            stale.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin, 'หน้าจอเก่า')
        with self.assertRaises(ValidationError):
            stale.save()
        with self.assertRaises(ValidationError):
            task.save()

    def test_normal_closure_supersedes_pending_request(self):
        record = self.request_cancel()
        self.ticket.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin, 'รายงานผล')
        self.ticket.transition_to(Ticket.STATUS_APPROVED, self.t2, 'แก้ไขแล้ว')
        record.refresh_from_db()
        self.assertEqual(record.status, 'SUPERSEDED')

    def test_admin_status_save_also_supersedes_pending_request(self):
        record = self.request_cancel()
        self.ticket.status = Ticket.STATUS_APPROVED
        self.ticket.save(update_fields=['status'])
        record.refresh_from_db()
        self.assertEqual(record.status, 'SUPERSEDED')

    def test_project_member_cancellation_retains_group_and_other_member(self):
        project = ProjectIncident.objects.create(title='กลุ่มเหตุการณ์', created_by=self.t1)
        self.ticket.project_incident = project
        self.ticket.save()
        other = _ticket(created_by=self.t1, project_incident=project)
        self.approve(self.request_cancel())
        self.assertEqual(project.member_count, 2)
        self.assertEqual(project.open_member_count, 1)
        self.assertFalse(project.all_closed)
        other.refresh_from_db()
        self.assertEqual(other.status, Ticket.STATUS_NEW)

    @patch('apps.incidents.notifications.notify_ticket_cancellation')
    def test_notifications_are_dispatched_only_after_commit(self, notify):
        with self.captureOnCommitCallbacks(execute=True):
            record = self.request_cancel()
            notify.assert_not_called()
        notify.assert_called_once_with(record.pk, 'request')

    def test_thai_ui_manager_queue_and_history(self):
        self.client.force_login(self.t1)
        detail = reverse('ticket_detail', args=[self.ticket.pk])
        self.assertContains(self.client.get(detail), 'ส่งคำขอยกเลิกให้ผู้จัดการ SOC')
        endpoint = reverse('ticket_cancellation', args=[self.ticket.pk])
        self.assertEqual(self.client.get(endpoint).status_code, 405)
        self.client.post(endpoint, {'action': 'request', 'reason': 'CREATED_IN_ERROR', 'explanation': 'เปิดผิดระบบ'})
        self.client.force_login(self.manager)
        self.assertContains(self.client.get(reverse('manager_queue')), self.ticket.ticket_id)
        self.assertContains(self.client.get(detail), 'อนุมัติยกเลิกรายการ')
        record = self.ticket.cancellation_requests.get()
        response = self.client.post(endpoint, {'action': 'approve', 'request_id': record.pk, 'decision_note': 'ตรวจสอบแล้ว'}, follow=True)
        self.assertContains(response, 'รายการนี้ยกเลิกแล้ว')
        self.assertNotContains(response, 'Incident ผ่านการตรวจสอบแล้ว')
        self.assertContains(self.client.get(reverse('ticket_history'), {'status': 'CANCELLED', 'all_time': '1'}), self.ticket.ticket_id)

    def test_cancellation_is_excluded_from_resolution_metrics(self):
        self.approve(self.request_cancel())
        self.client.force_login(self.manager)
        response = self.client.get(reverse('home'))
        self.assertEqual(response.context['stats']['cancelled'], 1)
        self.assertEqual(response.context['stats']['mttr_n'], 0)
        self.assertEqual(response.context['stats']['active'], 0)

    def test_reporting_fact_and_aggregate_exclude_cancellation_from_success(self):
        from django.core.management import call_command
        from io import StringIO
        from apps.reporting.models import FactTicket, AggTicketDaily
        self.approve(self.request_cancel())
        fact = FactTicket.objects.get(pk=self.ticket.pk)
        self.assertTrue(fact.is_closed)
        self.assertTrue(fact.is_cancelled)
        self.assertFalse(fact.contain_ola_applicable)
        self.assertFalse(fact.contain_ola_met)
        self.assertIsNone(fact.time_to_resolve)
        call_command('refresh_reporting', skip_detection=True, skip_snapshot=True,
                     no_concurrently=True, stdout=StringIO())
        self.assertEqual(sum(AggTicketDaily.objects.values_list('closed_count', flat=True)), 0)

    def test_report_exports_include_thai_reason_and_cancellation_signoff(self):
        from .reports import build_ticket_report_context, build_ticket_report_sections
        for classification in (Ticket.CLASSIFICATION_EVENT, Ticket.CLASSIFICATION_INCIDENT):
            ticket = _ticket(created_by=self.t1, classification=classification)
            cancellation_action(ticket=ticket, actor=self.manager, action='direct',
                                reason='CREATED_IN_ERROR', explanation='สร้างรายการผิดระบบ')
            context = build_ticket_report_context(ticket)
            self.assertIn('สร้างรายการผิดระบบ', context['status'])
            self.assertIn('cancel-manager', context['status'])
            self.assertEqual(context['signoff_approver'], '-')
            self.assertIn('ยกเลิกรายการแล้ว', str(build_ticket_report_sections(context, ticket)))

    def test_cancellation_preserves_historical_breach_and_stops_live_clock(self):
        self.ticket.ola_triage_deadline = timezone.now() - timedelta(days=1)
        self.ticket.save()
        self.assertTrue(self.ticket.is_ola_triage_breached)
        deadline = self.ticket.ola_contain_deadline
        self.approve(self.request_cancel())
        self.assertTrue(self.ticket.is_ola_triage_breached)
        self.assertEqual(self.ticket.ola_contain_deadline, deadline)
        self.assertIsNone(self.ticket.ola_badge)

    def test_stale_evidence_operations_cannot_modify_cancelled_ticket(self):
        from .models import TicketAttachment
        from .ticket_evidence import add_ticket_attachments, delete_ticket_attachment
        attachment = TicketAttachment.objects.create(ticket=self.ticket, file='evidence/example.txt', original_name='หลักฐาน.txt')
        stale = Ticket.objects.get(pk=self.ticket.pk)
        self.approve(self.request_cancel())
        with self.assertRaises(ValidationError):
            delete_ticket_attachment(attachment=attachment, actor=self.manager, reason='หน้าจอเก่า')
        with self.assertRaises(ValidationError):
            add_ticket_attachments(ticket=stale, actor=self.manager, uploads=[])
        self.assertTrue(self.ticket.attachments.filter(pk=attachment.pk).exists())

    def test_superuser_override_still_requires_reason_and_records_manager_decision(self):
        from django.contrib.auth.models import User
        root = User.objects.create_superuser('cancellation-root', password='test-only')
        with self.assertRaises(ValidationError):
            cancellation_action(ticket=self.ticket, actor=root, action='direct', reason='OTHER', explanation=' ')
        record = cancellation_action(ticket=self.ticket, actor=root, action='direct', reason='OTHER', explanation='ตรวจสอบรายการผิดแล้ว')
        self.assertEqual(record.mode, 'MANAGER')
        self.assertEqual(record.decided_by, root)


from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from django.db import connection, connections
from django.test import TransactionTestCase
from unittest import skipUnless


@skipUnless(connection.vendor == 'postgresql', 'Row-lock races require PostgreSQL')
class CancellationConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.manager = _user('race-manager', UserProfile.ROLE_SOC_MANAGER)
        self.t2 = _user('race-t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        self.ticket = _ticket(created_by=self.t2, status=Ticket.STATUS_CONTAINMENT_REPORTED)
        self.record = cancellation_action(ticket=self.ticket, actor=self.t2, action='request',
                                          reason='OTHER', explanation='ตรวจสอบการยกเลิก')

    def race(self, actions):
        barrier = Barrier(2)

        def run(action):
            try:
                ticket = Ticket.objects.get(pk=self.ticket.pk)
                barrier.wait(timeout=10)
                action(ticket)
                return True
            except ValidationError:
                return False
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run, action) for action in actions]
            return [future.result(timeout=20) for future in futures]

    def approve(self, ticket):
        cancellation_action(ticket=ticket, actor=self.manager, action='approve',
                            request_id=self.record.pk, decision_note='อนุมัติยกเลิก')

    def test_two_approvals_have_one_winner(self):
        self.assertEqual(sorted(self.race([self.approve, self.approve])), [False, True])
        self.assertEqual(self.ticket.logs.filter(status_at_time=Ticket.STATUS_CANCELLED).count(), 1)

    def test_normal_closure_and_cancellation_cannot_overwrite_each_other(self):
        result = self.race([
            self.approve,
            lambda ticket: ticket.transition_to(Ticket.STATUS_APPROVED, self.t2, 'แก้ไขแล้ว'),
        ])
        self.assertEqual(sorted(result), [False, True])
        self.ticket.refresh_from_db()
        self.record.refresh_from_db()
        expected = 'APPROVED' if self.ticket.status == Ticket.STATUS_CANCELLED else 'SUPERSEDED'
        self.assertEqual(self.record.status, expected)

    def test_new_subtask_and_cancellation_cannot_leave_orphan_work(self):
        result = self.race([
            self.approve,
            lambda ticket: TicketSubtask.objects.create(
                ticket=ticket, title='งานใหม่', subtask_type=TicketSubtask.TYPE_INVESTIGATION,
            ),
        ])
        self.assertEqual(sorted(result), [False, True])
        self.ticket.refresh_from_db()
        if self.ticket.status == Ticket.STATUS_CANCELLED:
            self.assertFalse(self.ticket.subtasks.exists())
