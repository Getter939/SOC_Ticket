"""
UI smoke tests — render every core page through the real views/templates
so template regressions (broken includes, missing context, bad filters)
fail loudly in CI instead of in front of an analyst.

Run with:  py manage.py test apps.incidents.test_ui_smoke
"""

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketLog, TicketSubtask
from apps.incidents.tests import _make_user, _make_ticket


class UiSmokeTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff   = _make_user('ui_soc',     UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.soc_staff2  = _make_user('ui_soc2',    UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.soc_manager = _make_user('ui_manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin       = _make_user('ui_admin',   UserProfile.ROLE_SYSTEM_ADMIN)

        cls.ticket = _make_ticket(
            severity='Critical',
            assigned_admin=cls.admin,
            created_by=cls.soc_staff,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        cls.log = TicketLog.objects.create(
            ticket=cls.ticket, note='first note',
            status_at_time=cls.ticket.status, author=cls.soc_staff,
        )
        TicketSubtask.objects.create(
            ticket=cls.ticket, subtask_type=TicketSubtask.TYPE_INVESTIGATION,
            title='check logs', created_by=cls.soc_staff,
        )

    # ── Page rendering ────────────────────────────────────────────────── #

    def test_login_page_renders(self):
        resp = self.client.get(reverse('login'))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'no-sidebar')

    def test_ticket_list_renders_with_filters(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.get(reverse('ticket_list'), {
            'q': 'Test', 'severity': 'Critical', 'sort': 'sla',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.ticket.ticket_id)

    def test_ticket_list_status_filter(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.get(reverse('ticket_list'), {'status': 'AWAITING_CONTAINMENT'})
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, f'#{self.ticket.ticket_id}')  # ticket is NEW

    def test_ticket_detail_renders_for_soc(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.get(reverse('ticket_detail', args=[self.ticket.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Critical')           # severity badge
        self.assertContains(resp, 'แจ้งเหตุใหม่')        # status label, not raw code

    def test_ticket_detail_renders_for_assigned_admin(self):
        self.ticket.transition_to(
            Ticket.STATUS_AWAITING_CONTAINMENT, self.soc_staff, 'route',
        )
        self.client.force_login(self.admin)
        resp = self.client.get(reverse('ticket_detail', args=[self.ticket.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Return to Tier 1')
        self.assertContains(resp, 'Investigation findings')
        self.assertContains(resp, 'Countermeasure')

    def test_dashboard_renders(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.get(reverse('home'))
        self.assertEqual(resp.status_code, 200)

    def test_ticket_history_renders(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.get(reverse('ticket_history'))
        self.assertEqual(resp.status_code, 200)

    # ── edit_log permission rules ─────────────────────────────────────── #

    def test_author_can_edit_own_log(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.post(
            reverse('edit_log', args=[self.log.pk]), {'note': 'edited'},
        )
        self.assertRedirects(resp, reverse('ticket_detail', args=[self.ticket.pk]))
        self.log.refresh_from_db()
        self.assertEqual(self.log.note, 'edited')

    def test_non_author_staff_cannot_edit_log(self):
        self.client.force_login(self.soc_staff2)
        resp = self.client.post(
            reverse('edit_log', args=[self.log.pk]), {'note': 'hijacked'},
        )
        self.assertRedirects(resp, reverse('ticket_detail', args=[self.ticket.pk]))
        self.log.refresh_from_db()
        self.assertNotEqual(self.log.note, 'hijacked')

    def test_manager_can_edit_any_log(self):
        self.client.force_login(self.soc_manager)
        self.client.post(
            reverse('edit_log', args=[self.log.pk]), {'note': 'manager edit'},
        )
        self.log.refresh_from_db()
        self.assertEqual(self.log.note, 'manager edit')

    def test_empty_note_rejected(self):
        self.client.force_login(self.soc_staff)
        self.client.post(reverse('edit_log', args=[self.log.pk]), {'note': '   '})
        self.log.refresh_from_db()
        self.assertEqual(self.log.note, 'first note')


class WorkflowUiContractTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_user('contract_t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.t2 = _make_user('contract_t2', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2)
        cls.manager = _make_user('contract_manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('contract_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def make_ticket(self, status, **kwargs):
        return _make_ticket(
            status=status,
            created_by=self.t1,
            assigned_admin=self.admin,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            severity=kwargs.pop('severity', 'High'),
            **kwargs,
        )

    def test_tier2_sees_exactly_two_decisions_and_no_forbidden_actions(self):
        ticket = self.make_ticket(
            Ticket.STATUS_ESCALATED_T2, escalated_to_t2_at=timezone.now(),
        )
        self.client.force_login(self.t2)
        response = self.client.get(reverse('ticket_detail', args=[ticket.pk]))
        self.assertContains(response, 'Mark as Event -&gt; Close')
        self.assertContains(response, 'Mark as Incident -&gt; Return to Tier 1')
        self.assertNotContains(response, 'Send to System Admin')
        self.assertNotContains(response, 'Create Ticket')

    def test_tier2_can_edit_and_return_incident_to_tier1(self):
        ticket = self.make_ticket(
            Ticket.STATUS_ESCALATED_T2, escalated_to_t2_at=timezone.now(),
        )
        self.client.force_login(self.t2)
        response = self.client.post(reverse('ticket_detail', args=[ticket.pk]), {
            'action': 't2_review',
            'status': Ticket.STATUS_T1_REVIEW,
            'classification': Ticket.CLASSIFICATION_INCIDENT,
            'severity': 'High',
            'category': 'Cyber Event',
            'issue_type': 'SIEM',
            'detailed_issue': 'Investigating',
            'detailed_issue2': 'Investigating Other',
            'device_name': 'EDITED-BY-T2',
            'issue_description': 'Tier 2 confirmed the incident.',
            'ip_address': '192.0.2.20',
            'decision_note': 'Confirmed incident.',
        })
        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_T1_REVIEW)
        self.assertEqual(ticket.device_name, 'EDITED-BY-T2')

    def test_t1_emergency_is_disabled_before_and_enabled_after_escalation(self):
        direct = self.make_ticket(Ticket.STATUS_AWAITING_CONTAINMENT)
        escalated = self.make_ticket(
            Ticket.STATUS_T1_REVIEW, escalated_to_t2_at=timezone.now(),
        )
        self.client.force_login(self.t1)
        before = self.client.get(reverse('ticket_detail', args=[direct.pk]))
        after = self.client.get(reverse('ticket_detail', args=[escalated.pk]))
        reason = 'Tier 1 เปิดใช้ Emergency ได้หลังจาก Ticket เคยส่งต่อให้ Tier 2 แล้วเท่านั้น'
        self.assertContains(before, reason)
        self.assertNotContains(after, reason)

    def test_t1_review_admin_and_verification_actions_match_routing(self):
        review = self.make_ticket(Ticket.STATUS_T1_REVIEW, escalated_to_t2_at=timezone.now())
        high = self.make_ticket(Ticket.STATUS_CONTAINMENT_REPORTED, containment_report='done')
        critical = self.make_ticket(
            Ticket.STATUS_CONTAINMENT_REPORTED, containment_report='done', severity='Critical',
        )
        self.client.force_login(self.t1)
        self.assertContains(
            self.client.get(reverse('ticket_detail', args=[review.pk])),
            'Send to System Admin',
        )
        high_response = self.client.get(reverse('ticket_detail', args=[high.pk]))
        self.assertContains(high_response, 'Return to System Admin (not contained)')
        self.assertContains(high_response, 'Close case')
        self.assertNotContains(high_response, 'Send to SOC Manager')
        critical_response = self.client.get(reverse('ticket_detail', args=[critical.pk]))
        self.assertContains(critical_response, 'Send to SOC Manager')
        self.assertNotContains(critical_response, '>Close case<')

    def test_manager_list_and_detail_only_show_manager_verification_work(self):
        pending = self.make_ticket(Ticket.STATUS_PENDING_MANAGER, severity='Critical')
        other = self.make_ticket(Ticket.STATUS_AWAITING_CONTAINMENT)
        self.client.force_login(self.manager)
        listing = self.client.get(reverse('ticket_list'))
        self.assertContains(listing, pending.ticket_id)
        self.assertNotContains(listing, other.ticket_id)
        detail = self.client.get(reverse('ticket_detail', args=[pending.pk]))
        self.assertContains(detail, 'Verify -&gt; Close')
        self.assertNotContains(detail, 'Send to System Admin')

    def test_ticket_list_exposes_emergency_filter_and_sort(self):
        self.make_ticket(Ticket.STATUS_AWAITING_CONTAINMENT, is_emergency=True)
        self.client.force_login(self.t1)
        response = self.client.get(reverse('ticket_list'), {'emergency': '1', 'sort': 'emergency'})
        self.assertContains(response, 'Emergency only')
        self.assertContains(response, 'EMERGENCY')
