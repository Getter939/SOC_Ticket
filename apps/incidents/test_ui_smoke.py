"""
UI smoke tests — render every core page through the real views/templates
so template regressions (broken includes, missing context, bad filters)
fail loudly in CI instead of in front of an analyst.

Run with:  py manage.py test apps.incidents.test_ui_smoke
"""

from django.test import TestCase
from django.urls import reverse

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketLog, TicketSubtask
from apps.incidents.tests import _make_user, _make_ticket


class UiSmokeTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff   = _make_user('ui_soc',     UserProfile.ROLE_SOC_STAFF)
        cls.soc_staff2  = _make_user('ui_soc2',    UserProfile.ROLE_SOC_STAFF)
        cls.soc_manager = _make_user('ui_manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin       = _make_user('ui_admin',   UserProfile.ROLE_SYSTEM_ADMIN)

        cls.ticket = _make_ticket(
            severity='Critical',
            assigned_admin=cls.admin,
            created_by=cls.soc_staff,
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
        self.assertContains(resp, 'ส่งรายงานการควบคุม')   # containment form shown

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
