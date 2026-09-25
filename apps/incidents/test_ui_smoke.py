"""
UI smoke tests — render every core page through the real views/templates
so template regressions (broken includes, missing context, bad filters)
fail loudly in CI instead of in front of an analyst.

Run with:  py manage.py test apps.incidents.test_ui_smoke
"""

from apps.accounts.testing import MFATestCase as TestCase
from django.urls import reverse
from django.utils import timezone

from django.core import mail

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketLog, TicketSubtask
from apps.incidents.tests import (
    _make_user, _make_ticket, _make_forensic, _make_redteam_manager, _make_t2,
)


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

    def test_base_renders_accessible_theme_switch(self):
        resp = self.client.get(reverse('login'))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'id="theme-toggle"')
        self.assertContains(resp, 'role="switch"')
        self.assertContains(resp, 'aria-label="สลับเป็น Dark Mode"')
        self.assertContains(resp, "prefers-color-scheme: dark")
        self.assertContains(resp, "localStorage.setItem(storageKey, theme)")

    def test_ticket_list_renders_with_filters(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.get(reverse('ticket_list'), {
            'q': 'Test', 'severity': 'Critical', 'sort': 'ola',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.ticket.ticket_id)
        self.assertContains(resp, 'ผู้ดูแลระบบ')
        self.assertContains(resp, 'Tier 1 ผู้รับเรื่อง')
        self.assertContains(resp, self.admin.username)
        self.assertContains(resp, self.soc_staff.username)

    def test_ticket_list_status_filter(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.get(reverse('ticket_list'), {'status': 'AWAITING_CONTAINMENT'})
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, f'#{self.ticket.ticket_id}')  # ticket is NEW

    def test_ticket_list_displays_and_filters_event_incident_classification(self):
        event = _make_ticket(
            ticket_id='UI-ACTIVE-EVENT',
            created_by=self.soc_staff,
            classification=Ticket.CLASSIFICATION_EVENT,
        )
        self.client.force_login(self.soc_staff)

        response = self.client.get(reverse('ticket_list'), {
            'classification': Ticket.CLASSIFICATION_EVENT,
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="classification"')
        self.assertContains(response, event.ticket_id)
        self.assertNotContains(response, self.ticket.ticket_id)
        self.assertEqual(response.context['classification_filter'], Ticket.CLASSIFICATION_EVENT)

    def test_manager_queue_is_distinct_from_active_incidents(self):
        manager_ticket = _make_ticket(
            ticket_id='UI-MANAGER-QUEUE',
            created_by=self.soc_staff,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
        )
        self.client.force_login(self.soc_manager)

        queue = self.client.get(reverse('manager_queue'))
        active = self.client.get(reverse('ticket_list'))

        self.assertEqual(queue.status_code, 200)
        self.assertContains(queue, manager_ticket.ticket_id)
        self.assertNotContains(queue, self.ticket.ticket_id)
        self.assertContains(active, manager_ticket.ticket_id)
        self.assertContains(active, self.ticket.ticket_id)

    def test_manager_queue_denies_non_managers(self):
        self.client.force_login(self.soc_staff)
        response = self.client.get(reverse('manager_queue'))
        self.assertEqual(response.status_code, 403)

    def test_ticket_detail_renders_for_soc(self):
        self.client.force_login(self.soc_staff)
        resp = self.client.get(reverse('ticket_detail', args=[self.ticket.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Critical')           # severity badge
        self.assertContains(resp, 'กำลังจัดเตรียม')      # status label, not raw code
        self.assertContains(resp, 'สรุปเหตุการณ์')
        self.assertContains(resp, 'ขอบเขตและข้อมูลทางเทคนิค')
        self.assertContains(resp, 'ประวัติการดำเนินการ')
        self.assertContains(resp, 'data-section-nav')
        self.assertContains(resp, 'href="#evidence"')
        self.assertContains(resp, 'hero-operational')
        self.assertContains(resp, 'workflow-column')

    def test_ticket_detail_renders_for_assigned_admin(self):
        self.ticket.t1_route = Ticket.T1_ROUTE_ADMIN
        self.ticket.transition_to(
            Ticket.STATUS_PENDING_MGR_TRIAGE, self.soc_staff, 'route',
        )
        self.ticket.transition_to(
            Ticket.STATUS_AWAITING_CONTAINMENT, self.soc_manager, 'forward',
        )
        self.client.force_login(self.admin)
        resp = self.client.get(reverse('ticket_detail', args=[self.ticket.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'ส่งให้ Tier 2 ตรวจสอบ')
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
        self.assertNotContains(resp, 'text-truncate needs a block box')

    def test_ticket_history_displays_and_filters_event_incident_classification(self):
        incident = _make_ticket(
            ticket_id='UI-HISTORY-INCIDENT',
            created_by=self.soc_staff,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_APPROVED,
        )
        event = _make_ticket(
            ticket_id='UI-HISTORY-EVENT',
            created_by=self.soc_staff,
            classification=Ticket.CLASSIFICATION_EVENT,
            status=Ticket.STATUS_CLOSED_EVENT,
        )
        self.client.force_login(self.soc_staff)

        response = self.client.get(reverse('ticket_history'), {
            'all_time': '1',
            'classification': Ticket.CLASSIFICATION_EVENT,
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="classification"')
        self.assertContains(response, event.ticket_id)
        self.assertNotContains(response, incident.ticket_id)
        self.assertEqual(response.context['classification_filter'], Ticket.CLASSIFICATION_EVENT)

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
            classification=kwargs.pop('classification', Ticket.CLASSIFICATION_INCIDENT),
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
        self.assertContains(response, 'Mark as Incident -&gt; SOC Manager review')
        # The Incident decision carries the lane picker on the same form.
        self.assertContains(response, 'name="t1_route"')
        self.assertNotContains(response, 'Send to System Admin')
        self.assertNotContains(response, 'Create Ticket')

    def _t2_incident_post(self, ticket, **lane):
        return self.client.post(reverse('ticket_detail', args=[ticket.pk]), {
            'action': 't2_review',
            'status': Ticket.STATUS_PENDING_MGR_TRIAGE,
            'classification': Ticket.CLASSIFICATION_INCIDENT,
            'severity': 'High',
            'ncsa_severity': Ticket.NCSA_SEVERITY_SEVERE,
            'importance': Ticket.IMPORTANCE_IMPORTANT,
            'log_source': 'Wazuh',
            'issue_type': 'SIEM',
            'detailed_issue': 'Investigating',
            'detailed_issue2': 'Investigating Other',
            'device_name': 'EDITED-BY-T2',
            'issue_description': 'Tier 2 confirmed the incident.',
            'ip_address': '192.0.2.20',
            'decision_note': 'Confirmed incident.',
            **lane,
        })

    def test_tier2_incident_without_lane_stays_with_tier2(self):
        ticket = self.make_ticket(
            Ticket.STATUS_ESCALATED_T2, escalated_to_t2_at=timezone.now(),
        )
        self.client.force_login(self.t2)
        self._t2_incident_post(ticket, t1_route=Ticket.T1_ROUTE_ADMIN)  # no admin
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_ESCALATED_T2)
        self.assertNotEqual(ticket.device_name, 'EDITED-BY-T2')

    def test_tier2_owner_lane_routes_to_manager_and_marks_creator(self):
        ticket = self.make_ticket(
            Ticket.STATUS_ESCALATED_T2, escalated_to_t2_at=timezone.now(),
        )
        self.client.force_login(self.t2)
        self._t2_incident_post(ticket, t1_route=Ticket.T1_ROUTE_OWNER)
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(ticket.t1_route, Ticket.T1_ROUTE_OWNER)
        self.assertTrue(ticket.has_unseen_t2_changes)

        # The creator sees it in My Queue's passive list — not in the sidebar
        # needs-action count — and opening the ticket clears it.
        self.client.force_login(self.t1)
        queue = self.client.get(reverse('triage_list'))
        self.assertEqual(queue.context['t2_changed_count'], 1)
        before_badge = queue.context['my_queue_count']
        detail = self.client.get(reverse('ticket_detail', args=[ticket.pk]))
        self.assertContains(detail, 'Tier 2 แก้ไขข้อมูลใน Ticket นี้')
        queue = self.client.get(reverse('triage_list'))
        self.assertEqual(queue.context['t2_changed_count'], 0)
        self.assertEqual(queue.context['my_queue_count'], before_badge)
        self.assertNotContains(
            self.client.get(reverse('ticket_detail', args=[ticket.pk])),
            'Tier 2 แก้ไขข้อมูลใน Ticket นี้',
        )

    def test_tier2_can_edit_and_route_incident_to_manager(self):
        ticket = self.make_ticket(
            Ticket.STATUS_ESCALATED_T2, escalated_to_t2_at=timezone.now(),
        )
        self.client.force_login(self.t2)
        response = self.client.post(reverse('ticket_detail', args=[ticket.pk]), {
            'action': 't2_review',
            't1_route': Ticket.T1_ROUTE_ADMIN,
            'assigned_admin': self.admin.pk,
            'status': Ticket.STATUS_PENDING_MGR_TRIAGE,
            'classification': Ticket.CLASSIFICATION_INCIDENT,
            'severity': 'High',
            'ncsa_severity': Ticket.NCSA_SEVERITY_SEVERE,
            'importance': Ticket.IMPORTANCE_IMPORTANT,
            'log_source': 'Wazuh',
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
        self.assertEqual(ticket.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(ticket.t1_route, Ticket.T1_ROUTE_ADMIN)
        self.assertEqual(ticket.assigned_admin, self.admin)
        self.assertEqual(ticket.device_name, 'EDITED-BY-T2')
        # The manager can forward it immediately — no Tier 1 step in between.
        self.assertTrue(ticket.can_transition_to(Ticket.STATUS_AWAITING_CONTAINMENT))

    def test_reassess_emergency_control_is_manager_only(self):
        """Only the SOC Manager sees the Reassess Emergency control at an active
        post-review stage; Tier 1 / Tier 2 see the read-only status only."""
        ticket = self.make_ticket(
            Ticket.STATUS_ESCALATED_T2, escalated_to_t2_at=timezone.now(),
        )
        control = 'value="reassess_emergency"'
        self.client.force_login(self.t1)
        self.assertNotContains(
            self.client.get(reverse('ticket_detail', args=[ticket.pk])), control,
        )
        self.client.force_login(self.t2)
        self.assertNotContains(
            self.client.get(reverse('ticket_detail', args=[ticket.pk])), control,
        )
        self.client.force_login(self.manager)
        self.assertContains(
            self.client.get(reverse('ticket_detail', args=[ticket.pk])), control,
        )

    def test_t2_cannot_reassess_emergency_via_post(self):
        ticket = self.make_ticket(Ticket.STATUS_AWAITING_CONTAINMENT)
        self.client.force_login(self.t2)
        self.client.post(reverse('ticket_detail', args=[ticket.pk]), {
            'action': 'reassess_emergency', 'emergency_value': '1',
            'emergency_reason': 'sneaky escalation',
        })
        ticket.refresh_from_db()
        self.assertFalse(ticket.is_emergency)

    def test_no_editable_emergency_control_at_pending_mgr_triage(self):
        """No standalone Emergency toggle on the pre-containment review screen —
        the initial assessment lives in the forward form, not a duplicate."""
        ticket = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.manager)
        detail = self.client.get(reverse('ticket_detail', args=[ticket.pk]))
        # The reassess control must NOT appear here…
        self.assertNotContains(detail, 'value="reassess_emergency"')
        # …but the required two-option initial assessment must.
        self.assertContains(detail, 'name="emergency_assessment"')

    def test_t2_verification_actions_match_routing(self):
        normal = self.make_ticket(Ticket.STATUS_CONTAINMENT_REPORTED, containment_report='done')
        emergency = self.make_ticket(
            Ticket.STATUS_CONTAINMENT_REPORTED, containment_report='done', is_emergency=True,
        )
        self.client.force_login(self.t1)
        # Containment verification belongs to Tier 2 now — Tier 1 gets no actions.
        t1_response = self.client.get(reverse('ticket_detail', args=[normal.pk]))
        self.assertNotContains(t1_response, 'Return to System Admin (not contained)')

        self.client.force_login(self.t2)
        normal_response = self.client.get(reverse('ticket_detail', args=[normal.pk]))
        self.assertContains(normal_response, 'Return to System Admin (not contained)')
        self.assertContains(normal_response, 'Verify -&gt; Close')
        self.assertNotContains(normal_response, 'Send to SOC Manager')
        emergency_response = self.client.get(reverse('ticket_detail', args=[emergency.pk]))
        self.assertContains(emergency_response, 'Send to SOC Manager')
        self.assertNotContains(emergency_response, 'Verify -&gt; Close')

    def test_manager_list_and_detail_only_show_manager_verification_work(self):
        pending = self.make_ticket(Ticket.STATUS_PENDING_MANAGER, severity='Critical')
        triage = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        other = self.make_ticket(Ticket.STATUS_AWAITING_CONTAINMENT)
        self.client.force_login(self.manager)
        listing = self.client.get(reverse('manager_queue'))
        self.assertContains(listing, pending.ticket_id)
        self.assertContains(listing, triage.ticket_id)   # pre-containment review queue
        self.assertNotContains(listing, other.ticket_id)  # not the manager's work
        detail = self.client.get(reverse('ticket_detail', args=[pending.pk]))
        self.assertContains(detail, 'Verify -&gt; Close')
        self.assertNotContains(detail, 'Send to System Admin')

    def test_manager_review_panel_shows_forward_and_emergency_assessment(self):
        triage = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.manager)
        detail = self.client.get(reverse('ticket_detail', args=[triage.pk]))
        self.assertContains(detail, 'การตรวจสอบโดยผู้จัดการ SOC')
        self.assertContains(detail, 'mgr_forward')
        self.assertContains(detail, 'name="emergency_assessment"')
        self.assertContains(detail, 'การดำเนินการเพิ่มเติม')
        self.assertContains(detail, 'id="new-response-request"')
        # Collapsed by default (no Bootstrap "show" class on the panel).
        self.assertNotContains(detail, 'show" id="new-response-request"')

    def test_manager_forward_requires_an_explicit_assessment(self):
        triage = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.manager)
        # No emergency_assessment → rejected, ticket stays put.
        self.client.post(reverse('ticket_detail', args=[triage.pk]), {
            'action': 'mgr_forward',
            'decision_note': 'Forgot to assess.',
        })
        triage.refresh_from_db()
        self.assertEqual(triage.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertIsNone(triage.emergency_decided_by)

    def test_manager_forward_emergency_assessment_moves_to_containment(self):
        triage = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.manager)
        resp = self.client.post(reverse('ticket_detail', args=[triage.pk]), {
            'action': 'mgr_forward', 'emergency_assessment': 'emergency',
            'decision_note': 'Reviewed, flagged emergency, forwarding.',
        })
        self.assertRedirects(resp, reverse('ticket_detail', args=[triage.pk]))
        triage.refresh_from_db()
        self.assertEqual(triage.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertTrue(triage.is_emergency)
        self.assertEqual(triage.emergency_decided_by, self.manager)

    def test_manager_forward_normal_assessment_records_metadata(self):
        triage = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.manager)
        self.client.post(reverse('ticket_detail', args=[triage.pk]), {
            'action': 'mgr_forward', 'emergency_assessment': 'normal',
            'decision_note': 'Reviewed, not an emergency, forwarding.',
        })
        triage.refresh_from_db()
        self.assertEqual(triage.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertFalse(triage.is_emergency)
        # "Normal" is still a recorded decision, not an unchecked box.
        self.assertEqual(triage.emergency_decided_by, self.manager)
        self.assertIsNotNone(triage.emergency_decided_at)

    def test_t1_cannot_forward_from_mgr_triage_via_ui(self):
        triage = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.t1)
        resp = self.client.post(reverse('ticket_detail', args=[triage.pk]), {
            'action': 'mgr_forward', 'decision_note': 'sneaky',
        })
        triage.refresh_from_db()
        self.assertEqual(triage.status, Ticket.STATUS_PENDING_MGR_TRIAGE)

    def test_t2_reclassify_event_closes_from_containment(self):
        contained = self.make_ticket(
            Ticket.STATUS_CONTAINMENT_REPORTED, containment_report='done',
            is_emergency=True,
        )
        self.client.force_login(self.t2)
        detail = self.client.get(reverse('ticket_detail', args=[contained.pk]))
        self.assertContains(detail, 't2_reclassify_event')
        resp = self.client.post(reverse('ticket_detail', args=[contained.pk]), {
            'action': 't2_reclassify_event',
            'decision_note': 'Benign after review.',
        })
        self.assertRedirects(resp, reverse('ticket_detail', args=[contained.pk]))
        contained.refresh_from_db()
        self.assertEqual(contained.status, Ticket.STATUS_CLOSED_EVENT)
        self.assertEqual(contained.classification, Ticket.CLASSIFICATION_EVENT)

    def test_manager_return_label_names_the_target(self):
        escalated = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
            escalated_to_t2_at=timezone.now(),
        )
        direct = self.make_ticket(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1_route=Ticket.T1_ROUTE_ADMIN,
        )
        self.client.force_login(self.manager)
        self.assertContains(
            self.client.get(reverse('ticket_detail', args=[escalated.pk])), 'ส่งกลับ Tier 2',
        )
        self.assertContains(
            self.client.get(reverse('ticket_detail', args=[direct.pk])),
            'ส่งกลับผู้เปิด (จัดเตรียมใหม่)',
        )
        self.client.post(reverse('ticket_detail', args=[escalated.pk]), {
            'action': 'return_for_completion', 'return_reason': 'Recheck scope.',
        })
        escalated.refresh_from_db()
        self.assertEqual(escalated.status, Ticket.STATUS_ESCALATED_T2)

    def test_conclude_monitoring_as_incident_requires_a_lane(self):
        watched = self.make_ticket(
            Ticket.STATUS_MONITORING, escalated_to_t2_at=timezone.now(),
            classification=Ticket.CLASSIFICATION_EVENT, has_been_monitored=True,
            monitor_until=timezone.now(),
        )
        self.client.force_login(self.t2)
        post = {'action': 'conclude_monitoring', 'monitoring_outcome': 'incident',
                'decision_note': 'Beacon observed.'}
        self.client.post(reverse('ticket_detail', args=[watched.pk]), post)
        watched.refresh_from_db()
        self.assertEqual(watched.status, Ticket.STATUS_MONITORING)

        self.client.post(reverse('ticket_detail', args=[watched.pk]),
                         {**post, 't1_route': Ticket.T1_ROUTE_OWNER})
        watched.refresh_from_db()
        self.assertEqual(watched.status, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self.assertEqual(watched.t1_route, Ticket.T1_ROUTE_OWNER)

    def test_ticket_list_exposes_emergency_filter_and_sort(self):
        self.make_ticket(Ticket.STATUS_AWAITING_CONTAINMENT, is_emergency=True)
        self.client.force_login(self.t1)
        response = self.client.get(reverse('ticket_list'), {'emergency': '1', 'sort': 'emergency'})
        self.assertContains(response, 'เฉพาะเคสฉุกเฉิน')
        self.assertContains(response, '>ฉุกเฉิน<')


class ResponseTeamUiTest(TestCase):
    """Session 2 UI: manager spawn, responder controls, queue page, nav."""

    @classmethod
    def setUpTestData(cls):
        cls.t1       = _make_user('rt_ui_t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.manager  = _make_user('rt_ui_mgr', UserProfile.ROLE_SOC_MANAGER)
        cls.admin    = _make_user('rt_ui_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.forensic = _make_forensic('rt_ui_forensic')
        cls.forensic.email = 'f@example.com'
        cls.forensic.save(update_fields=['email'])
        cls.redteam  = _make_redteam_manager('rt_ui_redteam')
        cls.redteam.profile.redteam_function = UserProfile.REDTEAM_PENTEST
        cls.redteam.profile.save(update_fields=['redteam_function'])

    def _ticket(self, status=Ticket.STATUS_AWAITING_CONTAINMENT, **kwargs):
        return _make_ticket(
            status=status, created_by=self.t1, assigned_admin=self.admin,
            classification=Ticket.CLASSIFICATION_INCIDENT, severity='High', **kwargs,
        )

    # ── Manager spawn card ────────────────────────────────────────────── #

    def test_manager_sees_response_spawn_card(self):
        t = self._ticket()
        self.client.force_login(self.manager)
        resp = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertContains(resp, 'id="new-response-request"')
        self.assertContains(resp, reverse('create_response_request', args=[t.pk]))

    def test_non_manager_does_not_see_spawn_card(self):
        t = self._ticket()
        self.client.force_login(self.t1)
        resp = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertNotContains(resp, 'id="new-response-request"')

    def test_spawn_card_emits_assignee_filter_data(self):
        # The client-side per-type assignee filter needs the routing map, each
        # member's role, and the two stable select ids.
        t = self._ticket()
        self.client.force_login(self.manager)
        resp = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertContains(resp, 'resp-type-select')
        self.assertContains(resp, 'resp-assignee-select')
        self.assertContains(resp, 'resp-eligible-assignees-data')
        # The picker must carry the new request types and eligible manager.
        self.assertContains(resp, TicketSubtask.TYPE_FORENSIC_RCA)
        self.assertContains(resp, TicketSubtask.TYPE_PENTEST)

    def test_manager_spawn_auto_assigns_sole_role_holder(self):
        t = self._ticket()
        self.client.force_login(self.manager)
        resp = self.client.post(reverse('create_response_request', args=[t.pk]), {
            'subtask_type': TicketSubtask.TYPE_FORENSIC_RCA,
            'title': 'Collect memory image', 'description': 'full RAM dump',
        })
        self.assertRedirects(resp, reverse('ticket_detail', args=[t.pk]))
        st = t.subtasks.get()
        self.assertEqual(st.assigned_to, self.forensic)
        self.assertEqual(st.created_by, self.manager)
        # Responder got an email.
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['f@example.com'])

    def test_spawn_blocked_when_no_role_holder(self):
        # No Red Team Manager with a routed request exists? There IS one
        # (self.redteam), so remove them to prove the guard.
        self.redteam.is_active = False
        self.redteam.save(update_fields=['is_active'])
        t = self._ticket()
        self.client.force_login(self.manager)
        resp = self.client.post(reverse('create_response_request', args=[t.pk]), {
            'subtask_type': TicketSubtask.TYPE_PENTEST, 'title': 'Pentest',
        }, follow=True)
        self.assertEqual(t.subtasks.count(), 0)
        self.assertContains(resp, 'ยังไม่มีบัญชีผู้ใช้ในบทบาท')

    def test_non_manager_cannot_spawn_via_post(self):
        t = self._ticket()
        self.client.force_login(self.t1)
        self.client.post(reverse('create_response_request', args=[t.pk]), {
            'subtask_type': TicketSubtask.TYPE_FORENSIC_RCA, 'title': 'x',
        })
        self.assertEqual(t.subtasks.count(), 0)

    # ── Responder controls ────────────────────────────────────────────── #

    def test_assignee_sees_update_form_and_can_complete(self):
        # An accepted VA/PT request is completed from the assignee's
        # "งานของคุณ" card on the ticket page.
        t = self._ticket()
        st = TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_VA_PT,
            title='Pentest', assigned_to=self.redteam, created_by=self.manager,
            status=TicketSubtask.STATUS_IN_PROGRESS,
        )
        self.client.force_login(self.redteam)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertEqual(detail.status_code, 200)
        self.assertContains(detail, reverse('update_subtask', args=[st.pk]))
        # Mark DONE with result notes → managers notified.
        mail.outbox = []
        self.manager.email = 'm@example.com'
        self.manager.save(update_fields=['email'])
        resp = self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': TicketSubtask.STATUS_DONE,
            'result_notes': 'Root cause: phishing.',
            'report_number': 'SOC-VAPT-202609-0001',
        })
        self.assertRedirects(resp, reverse('ticket_detail', args=[t.pk]))
        st.refresh_from_db()
        self.assertTrue(st.is_done)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['m@example.com'])

    def test_forensic_gets_a_my_request_card_at_the_top_of_the_action_column(self):
        # The analyst's own request is pinned into the action column (which sits
        # beside the case on desktop and first on mobile), instead of the old
        # "no step for your role" message and a form at the bottom of the page.
        t = self._ticket()
        st = self._rca(t)
        self.client.force_login(self.forensic)
        body = self.client.get(reverse('ticket_detail', args=[t.pk])).content.decode()
        self.assertIn('id="my-request"', body)
        self.assertNotIn('ยังไม่มีขั้นตอนที่ต้องดำเนินการสำหรับบทบาทของคุณ', body)
        card = body.index('id="my-request"')
        self.assertLess(card, body.index('id="overview"'))
        self.assertLess(body.index(reverse('accept_subtask', args=[st.pk])), body.index('id="overview"'))
        # The list row points back to the card instead of duplicating its form.
        self.assertIn('href="#my-request"', body)
        self.assertNotIn(f'id="update-subtask-{st.pk}"', body)
        self.assertNotIn('/rca/', body)

    def test_in_progress_rca_card_asks_for_the_report_number_and_no_file(self):
        t = self._ticket()
        st = self._rca(t, status=TicketSubtask.STATUS_IN_PROGRESS)
        self.client.force_login(self.forensic)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertContains(detail, f'id="my-report-number-{st.pk}"')
        self.assertTrue(st.expected_report_number.startswith('SOC-RCA-'))
        self.assertContains(detail, f'value="{st.expected_report_number}"')
        self.assertContains(detail, 'ส่งงาน · เสร็จสิ้น')
        self.assertNotContains(detail, 'name="result_file"')

    def test_done_card_shows_the_delivered_report_number(self):
        t = self._ticket()
        self._rca(t, status=TicketSubtask.STATUS_DONE, report_number='SOC-RCA-202609-0042')
        self.client.force_login(self.forensic)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertContains(detail, 'ส่งงานแล้ว')
        self.assertContains(detail, 'SOC-RCA-202609-0042')
        self.assertNotContains(detail, 'ส่งงาน · เสร็จสิ้น')

    def test_in_progress_pentest_card_has_manual_number_and_no_file(self):
        t = self._ticket()
        st = TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_PENTEST, title='Pentest',
            assigned_to=self.redteam, created_by=self.manager,
            status=TicketSubtask.STATUS_IN_PROGRESS,
        )
        self.client.force_login(self.redteam)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertNotContains(detail, 'name="result_file"')
        # The PenTest manager enters the report number rather than receiving
        # a case-derived value.
        self.assertContains(detail, f'id="my-report-number-{st.pk}"')
        self.assertEqual(st.expected_report_number, 'PT-YYYY-NNNN')
        self.assertNotContains(detail, f'value="{st.expected_report_number}"')

    def test_manager_sees_no_my_request_card(self):
        t = self._ticket()
        st = self._rca(t, status=TicketSubtask.STATUS_IN_PROGRESS)
        self.client.force_login(self.manager)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertNotContains(detail, 'id="my-request"')
        # The manager still gets the inline update form in the list.
        self.assertContains(detail, f'id="update-subtask-{st.pk}"')

    def test_queue_links_the_assignee_to_their_card(self):
        t = self._ticket()
        self._rca(t)
        self.client.force_login(self.forensic)
        resp = self.client.get(reverse('response_request_queue'))
        self.assertContains(resp, f"{reverse('ticket_detail', args=[t.pk])}#my-request")

    # ── Accept (รับงาน) ───────────────────────────────────────────────── #

    def _rca(self, t, **kwargs):
        return TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='RCA', assigned_to=self.forensic, created_by=self.manager, **kwargs,
        )

    def test_assignee_sees_accept_and_accepting_starts_the_request(self):
        t = self._ticket()
        st = self._rca(t)
        self.client.force_login(self.forensic)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertContains(detail, reverse('accept_subtask', args=[st.pk]))
        mail.outbox = []
        resp = self.client.post(reverse('accept_subtask', args=[st.pk]))
        self.assertRedirects(
            resp, f"{reverse('ticket_detail', args=[t.pk])}#my-request",
            fetch_redirect_response=False,
        )
        st.refresh_from_db()
        self.assertEqual(st.status, TicketSubtask.STATUS_IN_PROGRESS)
        self.assertEqual(len(mail.outbox), 0)
        self.assertTrue(
            st.field_changes.filter(field_name='status', changed_by=self.forensic).exists()
        )
        # Once accepted the button is gone.
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertNotContains(detail, reverse('accept_subtask', args=[st.pk]))

    def test_accept_from_queue_returns_to_the_queue(self):
        t = self._ticket()
        st = self._rca(t)
        self.client.force_login(self.forensic)
        queue = reverse('response_request_queue')
        self.assertContains(self.client.get(queue), reverse('accept_subtask', args=[st.pk]))
        resp = self.client.post(reverse('accept_subtask', args=[st.pk]), {'next': queue})
        self.assertRedirects(resp, queue, fetch_redirect_response=False)

    def test_accept_ignores_an_offsite_next(self):
        t = self._ticket()
        st = self._rca(t)
        self.client.force_login(self.forensic)
        resp = self.client.post(
            reverse('accept_subtask', args=[st.pk]), {'next': 'https://evil.example/'},
        )
        self.assertRedirects(
            resp, f"{reverse('ticket_detail', args=[t.pk])}#my-request",
            fetch_redirect_response=False,
        )

    def test_only_the_assignee_can_accept(self):
        t = self._ticket()
        st = self._rca(t)
        self.client.force_login(self.manager)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertNotContains(detail, reverse('accept_subtask', args=[st.pk]))
        self.client.post(reverse('accept_subtask', args=[st.pk]))
        st.refresh_from_db()
        self.assertEqual(st.status, TicketSubtask.STATUS_OPEN)

    def test_accept_needs_an_open_request(self):
        t = self._ticket()
        st = self._rca(t, status=TicketSubtask.STATUS_IN_PROGRESS)
        self.client.force_login(self.forensic)
        self.client.post(reverse('accept_subtask', args=[st.pk]))
        st.refresh_from_db()
        self.assertEqual(st.status, TicketSubtask.STATUS_IN_PROGRESS)
        self.assertFalse(st.field_changes.filter(field_name='status').exists())

    def test_accept_rejects_get(self):
        t = self._ticket()
        st = self._rca(t)
        self.client.force_login(self.forensic)
        self.assertEqual(self.client.get(reverse('accept_subtask', args=[st.pk])).status_code, 405)

    def test_redteam_can_accept_va_pt(self):
        t = self._ticket()
        st = TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_VA_PT,
            title='Pentest', assigned_to=self.redteam, created_by=self.manager,
        )
        self.client.force_login(self.redteam)
        self.client.post(reverse('accept_subtask', args=[st.pk]))
        st.refresh_from_db()
        self.assertEqual(st.status, TicketSubtask.STATUS_IN_PROGRESS)

    # ── RCA completion: report number mandatory, note optional, no file ── #

    def test_rca_done_without_report_number_is_rejected(self):
        t = self._ticket()
        st = self._rca(t, status=TicketSubtask.STATUS_IN_PROGRESS)
        self.client.force_login(self.forensic)
        resp = self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': TicketSubtask.STATUS_DONE, 'result_notes': 'done', 'report_number': '  ',
        }, follow=True)
        st.refresh_from_db()
        self.assertEqual(st.status, TicketSubtask.STATUS_IN_PROGRESS)
        self.assertContains(resp, 'กรุณาระบุเลขที่รายงาน')

    def test_rca_done_with_number_and_no_note_completes_and_emails(self):
        t = self._ticket()
        st = self._rca(t, status=TicketSubtask.STATUS_IN_PROGRESS)
        self.manager.email = 'm@example.com'
        self.manager.save(update_fields=['email'])
        self.client.force_login(self.forensic)
        mail.outbox = []
        self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': TicketSubtask.STATUS_DONE, 'result_notes': '',
            'report_number': ' SOC-RCA-202609-0015 ',
        })
        st.refresh_from_db()
        self.assertTrue(st.is_done)
        self.assertEqual(st.report_number, 'SOC-RCA-202609-0015')
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('SOC-RCA-202609-0015', mail.outbox[0].body)
        self.assertTrue(st.field_changes.filter(
            field_name='report_number', new_value='SOC-RCA-202609-0015',
        ).exists())

    def test_rca_update_ignores_an_uploaded_file(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        t = self._ticket()
        st = self._rca(t, status=TicketSubtask.STATUS_IN_PROGRESS)
        self.client.force_login(self.forensic)
        self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': TicketSubtask.STATUS_IN_PROGRESS,
            'result_file': SimpleUploadedFile('report.txt', b'x'),
        })
        self.assertFalse(st.attachments.exists())

    def test_red_team_done_also_requires_a_report_number(self):
        t = self._ticket()
        for subtask_type, token in (
            (TicketSubtask.TYPE_VA_PT, 'SOC-VAPT-'),
            (TicketSubtask.TYPE_INFRA_SEC, 'SOC-HARD-'),
        ):
            with self.subTest(subtask_type=subtask_type):
                st = TicketSubtask.objects.create(
                    ticket=t, subtask_type=subtask_type, title=subtask_type,
                    assigned_to=self.redteam, created_by=self.manager,
                    status=TicketSubtask.STATUS_IN_PROGRESS,
                )
                self.assertTrue(st.expected_report_number.startswith(token))
                self.client.force_login(self.redteam)
                self.client.post(reverse('update_subtask', args=[st.pk]), {
                    'status': TicketSubtask.STATUS_DONE, 'result_notes': 'done',
                })
                st.refresh_from_db()
                self.assertEqual(st.status, TicketSubtask.STATUS_IN_PROGRESS)
                self.client.post(reverse('update_subtask', args=[st.pk]), {
                    'status': TicketSubtask.STATUS_DONE,
                    'report_number': st.expected_report_number,
                })
                st.refresh_from_db()
                self.assertTrue(st.is_done)
                self.assertEqual(st.report_number, st.expected_report_number)

    def test_red_team_upload_is_ignored(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        t = self._ticket()
        st = TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_PENTEST, title='Pentest',
            assigned_to=self.redteam, created_by=self.manager,
            status=TicketSubtask.STATUS_IN_PROGRESS,
        )
        self.client.force_login(self.redteam)
        self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': TicketSubtask.STATUS_DONE, 'report_number': 'PT-2026-0001',
            'result_file': SimpleUploadedFile('scan.txt', b'x'),
        })
        st.refresh_from_db()
        self.assertTrue(st.is_done)
        self.assertFalse(st.attachments.exists())

    def test_old_rca_workspace_link_lands_on_the_ticket(self):
        t = self._ticket()
        st = self._rca(t)
        self.client.force_login(self.forensic)
        resp = self.client.get(reverse('legacy_rca_workspace', args=[st.pk]))
        self.assertRedirects(
            resp, f"{reverse('ticket_detail', args=[t.pk])}#my-request",
            fetch_redirect_response=False,
        )

    def test_old_rca_workspace_link_hides_invisible_tickets(self):
        t = self._ticket()
        st = self._rca(t)
        self.client.force_login(self.redteam)
        resp = self.client.get(reverse('legacy_rca_workspace', args=[st.pk]))
        self.assertEqual(resp.status_code, 404)

    def test_nav_badge_counts_only_requests_still_to_be_worked(self):
        t = self._ticket()
        self._rca(t)  # open — counts
        self._rca(t, status=TicketSubtask.STATUS_IN_PROGRESS)  # counts
        self._rca(t, status=TicketSubtask.STATUS_DONE, report_number='SOC-RCA-1')
        cancelled = self._rca(t)
        # Only the manager's cancellation flow may cancel; set it directly here.
        TicketSubtask.objects.filter(pk=cancelled.pk).update(status=TicketSubtask.STATUS_CANCELLED)
        self.client.force_login(self.forensic)
        resp = self.client.get(reverse('response_request_queue'))
        self.assertEqual(resp.context['response_request_queue_count'], 2)
        self.assertEqual(resp.context['open_count'], 2)

    # ── Who may change a request's status / report number ─────────────── #

    def _va_pt(self, t, **kwargs):
        return TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_VA_PT, title='Pentest',
            assigned_to=self.redteam, created_by=self.manager,
            status=TicketSubtask.STATUS_IN_PROGRESS, **kwargs,
        )

    def test_plain_soc_member_cannot_mark_a_request_done(self):
        t = self._ticket()
        st = self._va_pt(t)
        self.client.force_login(self.t1)
        resp = self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': TicketSubtask.STATUS_DONE, 'result_notes': 'closing it',
            'report_number': 'SOC-VAPT-X',
        }, follow=True)
        st.refresh_from_db()
        self.assertEqual(st.status, TicketSubtask.STATUS_IN_PROGRESS)
        # The whole POST is refused, notes included.
        self.assertEqual(st.result_notes, '')
        self.assertEqual(st.report_number, '')
        self.assertContains(resp, 'ได้เฉพาะผู้รับผิดชอบคำขอ')

    def test_plain_soc_member_cannot_change_only_the_report_number(self):
        t = self._ticket()
        st = self._va_pt(t, report_number='SOC-VAPT-1')
        self.client.force_login(self.t1)
        self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': st.status, 'report_number': 'SOC-VAPT-2',
        })
        st.refresh_from_db()
        self.assertEqual(st.report_number, 'SOC-VAPT-1')

    def test_plain_soc_member_can_still_add_notes(self):
        t = self._ticket()
        st = self._va_pt(t)
        self.client.force_login(self.t1)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        # Notes-only form: status is fixed, no report number, no file.
        self.assertContains(detail, f'id="update-subtask-{st.pk}"')
        self.assertContains(detail, f'<input type="hidden" name="status" value="{st.status}">')
        self.assertNotContains(detail, f'id="report-number-{st.pk}"')
        self.assertNotContains(detail, 'name="result_file"')
        self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': st.status, 'result_notes': 'Scope confirmed with owner',
        })
        st.refresh_from_db()
        self.assertEqual(st.result_notes, 'Scope confirmed with owner')
        self.assertEqual(st.status, TicketSubtask.STATUS_IN_PROGRESS)

    def test_soc_manager_can_still_mark_a_request_done(self):
        t = self._ticket()
        st = self._va_pt(t)
        self.client.force_login(self.manager)
        detail = self.client.get(reverse('ticket_detail', args=[t.pk]))
        self.assertContains(detail, f'id="report-number-{st.pk}"')
        self.client.post(reverse('update_subtask', args=[st.pk]), {
            'status': TicketSubtask.STATUS_DONE, 'report_number': 'SOC-VAPT-9',
        })
        st.refresh_from_db()
        self.assertTrue(st.is_done)
        self.assertEqual(st.report_number, 'SOC-VAPT-9')

    # ── My Requests queue ─────────────────────────────────────────────── #

    def test_queue_shows_only_own_requests_for_forensic(self):
        t = self._ticket()
        mine = TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='My RCA', assigned_to=self.forensic, created_by=self.manager,
        )
        theirs = TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_VA_PT,
            title='Their pentest', assigned_to=self.redteam, created_by=self.manager,
        )
        self.client.force_login(self.forensic)
        resp = self.client.get(reverse('response_request_queue'))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'My RCA')
        self.assertNotContains(resp, 'Their pentest')

    def test_queue_rows_link_every_type_to_the_ticket(self):
        t = self._ticket()
        TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='My RCA', assigned_to=self.forensic, created_by=self.manager,
            report_number='SOC-RCA-202609-0001',
        )
        TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_VA_PT,
            title='Their pentest', assigned_to=self.redteam, created_by=self.manager,
        )
        self.client.force_login(self.manager)  # overview sees both
        resp = self.client.get(reverse('response_request_queue'))
        self.assertContains(resp, f"{reverse('ticket_detail', args=[t.pk])}#tasks")
        self.assertContains(resp, 'SOC-RCA-202609-0001')
        self.assertNotContains(resp, '/rca/')

    def test_queue_overview_for_soc_shows_all(self):
        t = self._ticket()
        TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_VA_PT,
            title='Their pentest', assigned_to=self.redteam, created_by=self.manager,
        )
        self.client.force_login(self.manager)
        resp = self.client.get(reverse('response_request_queue'))
        self.assertContains(resp, 'Their pentest')
        self.assertContains(resp, 'ภาพรวมทุกทีม')

    def test_nav_shows_response_queue_for_forensic(self):
        self.client.force_login(self.forensic)
        resp = self.client.get(reverse('response_request_queue'))
        self.assertContains(resp, 'data-label="คำขอตอบสนองเหตุการณ์"')


class TicketTableConsistencyTest(TestCase):
    """The four ticket tables — Active, Manager Queue, Tier 2 Queue, History —
    are one family. These guard the properties they are supposed to share."""

    @classmethod
    def setUpTestData(cls):
        cls.t1      = _make_user('tbl_t1', UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1)
        cls.t2      = _make_t2('tbl_t2')
        cls.manager = _make_user('tbl_manager', UserProfile.ROLE_SOC_MANAGER)

        cls.active = _make_ticket(
            ticket_id='TBL-ACTIVE', created_by=cls.t1,
            incident_name='ชื่อเคสที่กำลังดำเนินการ',
        )
        cls.queued = _make_ticket(
            ticket_id='TBL-T2', created_by=cls.t1,
            incident_name='ชื่อเคสของ Tier 2',
            status=Ticket.STATUS_ESCALATED_T2,
        )
        cls.closed = _make_ticket(
            ticket_id='TBL-CLOSED', created_by=cls.t1,
            incident_name='ชื่อเคสที่ปิดแล้ว',
            status=Ticket.STATUS_APPROVED,
        )
        cls.for_manager = _make_ticket(
            ticket_id='TBL-MGR', created_by=cls.t1,
            incident_name='ชื่อเคสที่รอผู้จัดการ',
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
        )

    def test_every_ticket_table_leads_with_the_case_name(self):
        pages = (
            (self.manager, 'ticket_list',    self.active),
            (self.manager, 'manager_queue',  self.for_manager),
            (self.manager, 'ticket_history', self.closed),
            (self.t2,      'escalation_queue', self.queued),
        )
        for user, url_name, ticket in pages:
            with self.subTest(page=url_name):
                self.client.force_login(user)
                resp = self.client.get(reverse(url_name))
                self.assertEqual(resp.status_code, 200)
                self.assertContains(resp, '>ชื่อเรื่อง<')
                self.assertContains(resp, ticket.incident_name)

    def test_case_name_falls_back_to_the_subcategory_when_unnamed(self):
        """incident_name is optional, so the column must never be blank."""
        unnamed = _make_ticket(
            ticket_id='TBL-UNNAMED', created_by=self.t1,
            detailed_issue='Reconnaissance', detailed_issue2='Port Scanning',
        )
        self.assertEqual(unnamed.incident_name, '')
        self.assertEqual(unnamed.display_name, unnamed.get_detailed_issue2_display())

        self.client.force_login(self.manager)
        resp = self.client.get(reverse('ticket_list'))
        self.assertContains(resp, 'Port scanning')

    def test_manager_queue_clear_filters_stays_on_the_manager_queue(self):
        """It used to hardcode ticket_list, navigating the manager off their queue."""
        self.client.force_login(self.manager)
        resp = self.client.get(reverse('manager_queue'), {'severity': 'Critical'})
        self.assertContains(resp, 'href="%s"' % reverse('manager_queue'))

    def test_active_list_sorts_by_severity_rank_not_alphabetically(self):
        """Ordering on the raw CharField would rank Low above Medium."""
        low = _make_ticket(ticket_id='TBL-LOW', created_by=self.t1, severity='Low')
        medium = _make_ticket(ticket_id='TBL-MED', created_by=self.t1, severity='Medium')
        critical = _make_ticket(ticket_id='TBL-CRIT', created_by=self.t1, severity='Critical')

        self.client.force_login(self.manager)
        resp = self.client.get(reverse('ticket_list'), {'sort': 'severity'})
        ordered = [t.pk for t in resp.context['tickets']]

        self.assertLess(ordered.index(critical.pk), ordered.index(medium.pk))
        self.assertLess(ordered.index(medium.pk), ordered.index(low.pk))

    def test_active_list_is_searchable_by_case_name(self):
        self.client.force_login(self.manager)
        resp = self.client.get(reverse('ticket_list'), {'q': 'ชื่อเคสที่กำลังดำเนินการ'})
        self.assertContains(resp, self.active.ticket_id)
        self.assertNotContains(resp, self.for_manager.ticket_id)

    def test_tier2_queue_uses_the_shared_emergency_styling(self):
        """Not the full-row table-danger flood it used to paint."""
        self.queued.is_emergency = True
        self.queued.save(update_fields=['is_emergency'])
        self.client.force_login(self.t2)
        resp = self.client.get(reverse('escalation_queue'))
        self.assertContains(resp, 'is-emergency')
        self.assertContains(resp, 'emg-flag')
        self.assertNotContains(resp, 'table-danger')

