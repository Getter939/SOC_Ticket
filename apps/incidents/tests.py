"""
Tests for the redesigned SOC ticketing workflow.

Test classes
────────────
1.  TicketVisibilityQuerysetTest  — Ticket.objects.visible_to() queryset scoping
2.  TicketVisibilityViewTest      — HTTP-level visibility enforcement
3.  WorkflowTransitionTest        — Every legal state-machine edge, every illegal edge
4.  WorkflowPermissionTest        — Per-transition role/tier permissions (positive + negative)
5.  T1ClassificationCreateTest    — Tier 1 Event/Incident disposition at creation
6.  Tier2EscalationTest           — Tier 2 return-only constraint (never assign / never create)
7.  ManagerRoutingTest            — requires_manager_verification (emergency flag only)
8.  EmergencyFlagTest             — emergency-flag permissions + audit
9.  AdminFieldAccessTest          — System Admin write access to containment/remediation fields
10. SignOffFieldsTest             — verified_by/at and approved_by/at are write-once
11. NotificationEmailTest         — Email notifications on AWAITING_CONTAINMENT transitions
12. WazuhTriageActionTest         — 2-action Tier 1 triage + required release reason
13. TriageWorkflowIntegrityTest   — manual-triage + wazuh-alert ticket creation
14. SuperuserAccessTest           — superuser bypass across the redesigned flow
15. AttachmentDownloadSecurityTest / AttachmentUploadLimitTest
16. TicketReportExportTest       — preview, DOCX/PDF generation + metadata

Run with:  py manage.py test apps.incidents --settings=config.settings_local
"""

import hashlib
import shutil
import tempfile
from io import BytesIO
from unittest.mock import patch

from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from docx import Document
from pypdf import PdfReader

from apps.accounts.models import UserProfile
from apps.incidents.forms import AttachmentForm, TicketForm, TriageForm
from apps.incidents.models import (
    ProjectIncident, Ticket, TicketAttachment, TicketLog, TriageRecord,
    bundle_suffix_for_index,
)
from apps.incidents.notifications import notify_containment_required
from apps.incidents.reports import REPORT_TEMPLATE_VERSION, generate_ticket_report
from apps.wazuh_ingest.models import WazuhAlert


# ──────────────────────────────────────────────────────────────────────────── #
# Shared helpers                                                               #
# ──────────────────────────────────────────────────────────────────────────── #

def _make_user(username, role, department='Test', phone='000', **kwargs):
    """Create a User + UserProfile in one call. Pass tier='T1'/'T2' via kwargs."""
    user = User.objects.create_user(username=username, password='testpass123')
    UserProfile.objects.create(
        user=user, role=role, department=department, phone=phone, **kwargs
    )
    return user


def _make_t1(username='t1', **kwargs):
    return _make_user(username, UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1, **kwargs)


def _make_t2(username='t2', **kwargs):
    return _make_user(username, UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2, **kwargs)


def _make_ticket(**kwargs):
    """Create a Ticket with sensible defaults (bypasses the state machine)."""
    defaults = dict(
        device_name='10.0.0.1',
        ip_address='192.168.0.1',
        issue_description='Test ticket',
    )
    defaults.update(kwargs)
    return Ticket.objects.create(**defaults)


def _ticket_post_data(**overrides):
    """A valid create_ticket POST payload."""
    data = {
        'classification': Ticket.CLASSIFICATION_INCIDENT,
        't1_route': TicketForm.ROUTE_ESCALATE_T2,
        'severity': 'High',
        'ncsa_severity': Ticket.NCSA_SEVERITY_SEVERE,
        'log_source': 'Wazuh',
        'issue_type': 'SIEM',
        'detailed_issue': 'Investigating',
        'detailed_issue2': 'Investigating Other',
        'device_name': 'TEST-ENDPOINT-01',
        'issue_description': 'Confirmed suspicious activity.',
        'ip_address': '192.0.2.10',
    }
    data.update(overrides)
    return data


def _advance_to(ticket, target_status, t1, admin=None, mgr=None, t2=None):
    """
    Drive a ticket from its current status to target_status along the
    Incident → assign-admin happy path. Tier 2 verifies the containment report;
    the manager step fires automatically when the emergency flag requires it.
    """
    if ticket.created_by_id is None:
        ticket.created_by = t1
    if ticket.classification != Ticket.CLASSIFICATION_INCIDENT:
        ticket.classification = Ticket.CLASSIFICATION_INCIDENT
    ticket.save(update_fields=['created_by', 'classification'])

    path = [
        Ticket.STATUS_NEW,
        Ticket.STATUS_AWAITING_CONTAINMENT,
        Ticket.STATUS_CONTAINMENT_REPORTED,
    ]
    if ticket.requires_manager_verification:
        path += [Ticket.STATUS_PENDING_MANAGER, Ticket.STATUS_APPROVED]
    else:
        path += [Ticket.STATUS_APPROVED]

    i = path.index(ticket.status)
    j = path.index(target_status)
    for step in path[i + 1: j + 1]:
        if step == Ticket.STATUS_CONTAINMENT_REPORTED:
            ticket.containment_report = 'Contained.'
            ticket.transition_to(step, admin, 'containment note')
        elif step == Ticket.STATUS_PENDING_MANAGER:
            ticket.transition_to(step, t2, 'T2 verified — route to manager')
        elif step == Ticket.STATUS_APPROVED:
            actor = mgr if ticket.requires_manager_verification else t2
            ticket.transition_to(step, actor, 'close')
        else:  # AWAITING_CONTAINMENT
            ticket.transition_to(step, t1, 'assign admin')


def _docx_text(content):
    doc = Document(BytesIO(content))
    parts = [p.text for p in doc.paragraphs]
    parts.extend(
        p.text
        for table in doc.tables
        for row in table.rows
        for cell in row.cells
        for p in cell.paragraphs
    )
    return '\n'.join(parts)


# ──────────────────────────────────────────────────────────────────────────── #
# 1. Visibility queryset tests                                                 #
# ──────────────────────────────────────────────────────────────────────────── #

class TicketVisibilityQuerysetTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff   = _make_t1('soc_staff')
        cls.soc_manager = _make_user('soc_manager', UserProfile.ROLE_SOC_MANAGER)
        cls.admin_a     = _make_user('admin_a',     UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b     = _make_user('admin_b',     UserProfile.ROLE_SYSTEM_ADMIN)
        cls.no_profile  = User.objects.create_user(username='noprofile', password='testpass123')

        cls.ticket_a = _make_ticket(assigned_admin=cls.admin_a)
        cls.ticket_b = _make_ticket(assigned_admin=cls.admin_b)
        cls.ticket_unassigned = _make_ticket()

    def test_soc_staff_sees_all_tickets(self):
        self.assertEqual(Ticket.objects.visible_to(self.soc_staff).count(), 3)

    def test_soc_manager_sees_all_tickets(self):
        self.assertEqual(Ticket.objects.visible_to(self.soc_manager).count(), 3)

    def test_system_admin_sees_only_own_ticket(self):
        qs = Ticket.objects.visible_to(self.admin_a)
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), self.ticket_a)

    def test_system_admin_cannot_see_other_admins_ticket(self):
        self.assertNotIn(self.ticket_b, Ticket.objects.visible_to(self.admin_a))

    def test_no_profile_sees_no_tickets(self):
        self.assertEqual(Ticket.objects.visible_to(self.no_profile).count(), 0)


# ──────────────────────────────────────────────────────────────────────────── #
# 2. Visibility view tests                                                     #
# ──────────────────────────────────────────────────────────────────────────── #

class TicketVisibilityViewTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_t1('v_soc_staff')
        cls.admin_a   = _make_user('v_admin_a', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b   = _make_user('v_admin_b', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.ticket_a = _make_ticket(assigned_admin=cls.admin_a)
        cls.ticket_b = _make_ticket(assigned_admin=cls.admin_b)

    def test_admin_a_can_view_own_ticket(self):
        self.client.login(username='v_admin_a', password='testpass123')
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_a.pk})
        self.assertEqual(self.client.get(url).status_code, 200)

    def test_admin_a_gets_404_on_admin_b_ticket(self):
        self.client.login(username='v_admin_a', password='testpass123')
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_b.pk})
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_unauthenticated_user_redirected(self):
        url = reverse('ticket_detail', kwargs={'pk': self.ticket_a.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])


# ──────────────────────────────────────────────────────────────────────────── #
# 3. Workflow transition tests                                                  #
# ──────────────────────────────────────────────────────────────────────────── #

class TicketReportExportTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_t1('report_t1', phone='02-574-8209')
        cls.admin = _make_user('report_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.other_admin = _make_user('report_other_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.ticket = _make_ticket(
            created_by=cls.t1,
            assigned_admin=cls.admin,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            incident_name='Suspicious SoftEther Signed File',
            incident_datetime=timezone.now(),
            reference_id='INC-2026-0001',
            log_source='Wazuh',
            severity='High',
            ncsa_severity=Ticket.NCSA_SEVERITY_SEVERE,
            issue_type='SIEM',
            detailed_issue='Malicious Logic',
            detailed_issue2='Malware EDR',
            device_name='SRV-SQL-01',
            ip_address='192.0.2.10',
            mac_address='AA:BB:CC:DD:EE:FF',
            asset_type='Server',
            operating_system='Windows Server 2019',
            asset_owner='IT Operations',
            spread_to_others=False,
            destination_ip='203.0.113.50',
            ioc_details='203.0.113.50\nsoftether.example',
            mitre_phase='Initial Access,Execution',
            action_required='Block IoC and inspect persistence.',
            action_precautions='Preserve memory and logs before reboot.',
            actions_taken_summary='SOC contacted the owner and blocked the IP.',
            next_steps_summary='Monitor endpoint telemetry for 24 hours.',
            remediation_summary='Unauthorized service removed.',
            containment_report='Host isolated and C2 destination blocked.',
        )
        TicketAttachment.objects.create(
            ticket=cls.ticket,
            file='ticket_attachments/report/evidence.log',
            original_name='evidence.log',
            uploaded_by=cls.t1,
        )

    def test_generate_ticket_report_renders_docx_and_updates_metadata(self):
        snapshot_updated_at = self.ticket.updated_at

        report = generate_ticket_report(self.ticket.pk, generated_by=self.t1)
        content = report.content
        text = _docx_text(content)

        self.assertEqual(report.filename, f'report_{self.ticket.ticket_id}_{REPORT_TEMPLATE_VERSION}.docx')
        self.assertIn('Suspicious SoftEther Signed File', text)
        self.assertIn('SOC contacted the owner and blocked the IP.', text)
        self.assertIn('Host isolated and C2 destination blocked.', text)
        self.assertIn('Initial Access, Execution', text)
        self.assertIn('evidence.log', text)
        self.assertNotIn('{{ticket_id}}', text)

        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.report_template_version, REPORT_TEMPLATE_VERSION)
        self.assertEqual(self.ticket.report_generated_by, self.t1)
        self.assertEqual(self.ticket.report_ticket_updated_at, snapshot_updated_at)
        self.assertEqual(self.ticket.report_sha256, hashlib.sha256(content).hexdigest())
        self.assertIsNotNone(self.ticket.report_generated_at)

    def test_ticket_report_docx_endpoint_streams_authorized_download(self):
        self.client.force_login(self.t1)
        response = self.client.get(reverse('ticket_report_docx', args=[self.ticket.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response['Content-Type'],
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        )
        self.assertIn(f'report_{self.ticket.ticket_id}_{REPORT_TEMPLATE_VERSION}.docx', response['Content-Disposition'])
        content = b''.join(response.streaming_content)
        self.assertIn('Suspicious SoftEther Signed File', _docx_text(content))

        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.report_generated_by, self.t1)
        self.assertEqual(self.ticket.report_sha256, hashlib.sha256(content).hexdigest())

    def test_ticket_report_preview_returns_read_only_html(self):
        self.client.force_login(self.t1)
        response = self.client.get(reverse('ticket_report_preview', args=[self.ticket.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'General Info')
        self.assertContains(response, 'Incident Description')
        self.assertContains(response, 'Scope / Affected Asset')
        self.assertContains(response, 'IoCs / Evidence / MITRE Phases')
        self.assertContains(response, 'Containment / Precautions')
        self.assertContains(response, 'Remediation / Results')
        self.assertContains(response, 'Sign-off')
        self.assertContains(response, 'Appendix')
        self.assertContains(response, 'Suspicious SoftEther Signed File')
        self.assertContains(response, 'SOC contacted the owner and blocked the IP.')
        self.assertContains(response, 'Host isolated and C2 destination blocked.')
        self.assertContains(response, 'Back to ticket edit workspace')

    def test_ticket_report_pdf_endpoint_streams_valid_pdf_and_updates_metadata(self):
        self.client.force_login(self.t1)
        response = self.client.get(reverse('ticket_report_pdf', args=[self.ticket.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn(f'report_{self.ticket.ticket_id}_{REPORT_TEMPLATE_VERSION}.pdf', response['Content-Disposition'])

        content = b''.join(response.streaming_content)
        self.assertTrue(content.startswith(b'%PDF'))
        pdf = PdfReader(BytesIO(content))
        self.assertGreaterEqual(len(pdf.pages), 1)
        text = '\n'.join(page.extract_text() or '' for page in pdf.pages)
        normalized_text = ' '.join(text.split())
        self.assertIn('Suspicious SoftEther Signed File', normalized_text)

        self.ticket.refresh_from_db()
        self.assertEqual(self.ticket.report_template_version, REPORT_TEMPLATE_VERSION)
        self.assertEqual(self.ticket.report_generated_by, self.t1)
        self.assertEqual(self.ticket.report_sha256, hashlib.sha256(content).hexdigest())
        self.assertIsNotNone(self.ticket.report_generated_at)

    def test_ticket_report_docx_endpoint_respects_ticket_visibility(self):
        self.client.force_login(self.other_admin)
        response = self.client.get(reverse('ticket_report_docx', args=[self.ticket.pk]))
        self.assertEqual(response.status_code, 404)


class WorkflowTransitionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('wf_t1')
        cls.t2    = _make_t2('wf_t2')
        cls.mgr   = _make_user('wf_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('wf_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _incident(self, severity='High'):
        return _make_ticket(
            assigned_admin=self.admin, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT, severity=severity,
        )

    # ── Happy path ──────────────────────────────────────────────────────── #

    def test_new_incident_to_awaiting_containment(self):
        t = self._incident()
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'assign')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_new_incident_to_escalated_t2_stamps_escalation(self):
        t = self._incident()
        t.transition_to(Ticket.STATUS_ESCALATED_T2, self.t1, 'escalate')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_ESCALATED_T2)
        self.assertIsNotNone(t.escalated_to_t2_at)
        self.assertTrue(t.was_escalated_to_t2)

    def test_new_event_to_closed_event(self):
        t = _make_ticket(created_by=self.t1, classification=Ticket.CLASSIFICATION_EVENT)
        t.transition_to(Ticket.STATUS_CLOSED_EVENT, self.t1, 'benign')
        self.assertEqual(t.status, Ticket.STATUS_CLOSED_EVENT)

    def test_transition_stamps_status_changed_at(self):
        t = self._incident()
        before = t.status_changed_at
        self.assertIsNotNone(before)  # seeded on creation
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'assign')
        t.refresh_from_db()
        self.assertGreater(t.status_changed_at, before)

    def test_same_status_note_does_not_bump_status_changed_at(self):
        t = self._incident()
        stamp = t.status_changed_at
        # Same-status, note-only update — not a lifecycle move.
        t.transition_to(Ticket.STATUS_NEW, self.t1, 'just a note')
        t.refresh_from_db()
        self.assertEqual(t.status_changed_at, stamp)

    def test_escalated_incident_returns_to_t1_review(self):
        t = self._incident()
        t.transition_to(Ticket.STATUS_ESCALATED_T2, self.t1, 'escalate')
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'confirm incident')
        self.assertEqual(t.status, Ticket.STATUS_T1_REVIEW)

    def test_t1_review_to_awaiting_containment(self):
        t = self._incident()
        t.transition_to(Ticket.STATUS_ESCALATED_T2, self.t1, 'escalate')
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'confirm')
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'assign admin')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_full_happy_path_t2_closes_without_manager(self):
        t = self._incident(severity='High')
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin, t2=self.t2)
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_full_happy_path_emergency_via_manager(self):
        t = self._incident(severity='Critical')
        t.is_emergency = True
        t.save(update_fields=['is_emergency'])
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin,
                    mgr=self.mgr, t2=self.t2)
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_containment_rejection_loop(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_CONTAINMENT_REPORTED, self.t1, self.admin)
        # Tier 2 (not Tier 1) judges the containment report and sends it back.
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t2, 'not contained')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    # ── Illegal transitions ─────────────────────────────────────────────── #

    def test_cannot_skip_states(self):
        t = self._incident()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.t1, 'skip')

    def test_approved_is_terminal(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin, t2=self.t2)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'reopen')

    def test_closed_event_is_terminal(self):
        t = _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_EVENT,
            status=Ticket.STATUS_CLOSED_EVENT,
        )
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'reopen')

    def test_event_cannot_take_incident_path(self):
        """A ticket classified EVENT cannot be assigned to an admin."""
        t = _make_ticket(
            created_by=self.t1, assigned_admin=self.admin,
            classification=Ticket.CLASSIFICATION_EVENT,
        )
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'mismatch')

    def test_incident_cannot_be_closed_as_event(self):
        t = self._incident()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CLOSED_EVENT, self.t1, 'mismatch')

    def test_invalid_status_code_raises(self):
        t = self._incident()
        with self.assertRaises(ValidationError):
            t.transition_to('BOGUS', self.t1, 'bad')


# ──────────────────────────────────────────────────────────────────────────── #
# 4. Permission matrix tests                                                   #
# ──────────────────────────────────────────────────────────────────────────── #

class WorkflowPermissionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1       = _make_t1('pm_t1')
        cls.other_t1 = _make_t1('pm_t1_other')
        cls.t2       = _make_t2('pm_t2')
        cls.mgr      = _make_user('pm_mgr',     UserProfile.ROLE_SOC_MANAGER)
        cls.admin_a  = _make_user('pm_admin_a', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b  = _make_user('pm_admin_b', UserProfile.ROLE_SYSTEM_ADMIN)

    def _ticket_at(self, status, severity='High',
                   classification=Ticket.CLASSIFICATION_INCIDENT, **kwargs):
        opts = dict(
            status=status, severity=severity, classification=classification,
            assigned_admin=self.admin_a, created_by=self.t1,
        )
        opts.update(kwargs)
        return _make_ticket(**opts)

    # NEW → AWAITING_CONTAINMENT  requires TIER1_CREATOR ───────────────────

    def test_creator_t1_can_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_non_creator_t1_cannot_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.other_t1, 'denied')

    def test_t2_cannot_dispatch(self):
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t2, 'denied')

    def test_manager_cannot_dispatch(self):
        """Managers are not Tier 1 and never open/route a fresh ticket."""
        t = self._ticket_at(Ticket.STATUS_NEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.mgr, 'denied')

    # ESCALATED_T2 → T1_REVIEW  requires TIER2 ─────────────────────────────

    def test_t2_can_return_to_t1(self):
        t = self._ticket_at(Ticket.STATUS_ESCALATED_T2)
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_T1_REVIEW)

    def test_t1_cannot_return_to_t1(self):
        t = self._ticket_at(Ticket.STATUS_ESCALATED_T2)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_T1_REVIEW, self.t1, 'denied')

    # AWAITING_CONTAINMENT → CONTAINMENT_REPORTED  requires ASSIGNED_ADMIN ─

    def test_assigned_admin_can_report(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=self.admin_a)
        t.containment_report = 'contained'
        t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin_a, 'ok')
        self.assertEqual(t.status, Ticket.STATUS_CONTAINMENT_REPORTED)

    def test_other_admin_cannot_report(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=self.admin_a)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.admin_b, 'denied')

    def test_t1_cannot_report_containment(self):
        t = self._ticket_at(Ticket.STATUS_AWAITING_CONTAINMENT)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.t1, 'denied')

    # CONTAINMENT_REPORTED close  requires TIER2 ──────────────────────────

    def test_t2_can_verify_and_close_when_no_manager(self):
        t = self._ticket_at(Ticket.STATUS_CONTAINMENT_REPORTED, severity='High')
        t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'verified — close')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_creator_t1_cannot_close_containment(self):
        """Containment verification moved to Tier 2 — even the creator may not close."""
        t = self._ticket_at(Ticket.STATUS_CONTAINMENT_REPORTED, severity='High')
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t1, 'denied')

    def test_t2_must_route_emergency_to_manager(self):
        t = self._ticket_at(
            Ticket.STATUS_CONTAINMENT_REPORTED, severity='High', is_emergency=True,
        )
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'denied — emergency')
        t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t2, 'to manager')
        self.assertEqual(t.status, Ticket.STATUS_PENDING_MANAGER)

    def test_t2_can_reject_containment_back_to_admin(self):
        t = self._ticket_at(Ticket.STATUS_CONTAINMENT_REPORTED, severity='High')
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t2, 'not contained')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)

    def test_t1_cannot_reject_containment(self):
        t = self._ticket_at(Ticket.STATUS_CONTAINMENT_REPORTED, severity='High')
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'denied')

    # PENDING_MANAGER → APPROVED  requires MANAGER ────────────────────────

    def test_manager_can_approve(self):
        t = self._ticket_at(Ticket.STATUS_PENDING_MANAGER, severity='Critical')
        t.transition_to(Ticket.STATUS_APPROVED, self.mgr, 'approved')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_t1_cannot_approve_pending_manager(self):
        t = self._ticket_at(Ticket.STATUS_PENDING_MANAGER, severity='Critical')
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t1, 'denied')


# ──────────────────────────────────────────────────────────────────────────── #
# 5. Tier 1 Event/Incident disposition at creation                             #
# ──────────────────────────────────────────────────────────────────────────── #

class T1ClassificationCreateTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('cc_t1')
        cls.t2    = _make_t2('cc_t2')
        cls.admin = _make_user('cc_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def test_event_creation_closes_ticket(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification=Ticket.CLASSIFICATION_EVENT, t1_route='',
        ))
        self.assertEqual(resp.status_code, 302)
        ticket = Ticket.objects.latest('id')
        self.assertEqual(ticket.classification, Ticket.CLASSIFICATION_EVENT)
        self.assertEqual(ticket.status, Ticket.STATUS_CLOSED_EVENT)

    def test_incident_assign_admin_routes_to_containment(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ASSIGN_ADMIN,
            assigned_admin=self.admin.pk,
        ))
        self.assertEqual(resp.status_code, 302)
        ticket = Ticket.objects.latest('id')
        self.assertEqual(ticket.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertEqual(ticket.assigned_admin, self.admin)

    def test_incident_escalate_routes_to_t2(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ESCALATE_T2,
        ))
        self.assertEqual(resp.status_code, 302)
        ticket = Ticket.objects.latest('id')
        self.assertEqual(ticket.status, Ticket.STATUS_ESCALATED_T2)
        self.assertIsNotNone(ticket.escalated_to_t2_at)

    def test_incident_assign_admin_without_admin_is_invalid(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ASSIGN_ADMIN,
        ))
        self.assertEqual(resp.status_code, 200)  # form re-rendered with errors
        self.assertFalse(Ticket.objects.exists())

    def test_missing_classification_is_invalid(self):
        self.client.login(username='cc_t1', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data(
            classification='', t1_route='',
        ))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Ticket.objects.exists())

    def test_t2_cannot_open_create_ticket_page(self):
        self.client.login(username='cc_t2', password='testpass123')
        resp = self.client.get(reverse('create_ticket'))
        self.assertEqual(resp.status_code, 302)  # redirected — Tier 1 only

    def test_admin_cannot_open_create_ticket_page(self):
        self.client.login(username='cc_admin', password='testpass123')
        resp = self.client.get(reverse('create_ticket'))
        self.assertEqual(resp.status_code, 302)


# ──────────────────────────────────────────────────────────────────────────── #
# 6. Tier 2 return-only constraint                                             #
# ──────────────────────────────────────────────────────────────────────────── #

class Tier2EscalationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('t2t_t1')
        cls.t2    = _make_t2('t2t_t2')
        cls.admin = _make_user('t2t_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _escalated(self):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_ESCALATED_T2, assigned_admin=self.admin,
            escalated_to_t2_at=timezone.now(),
        )

    def test_t2_confirms_incident_returns_to_t1(self):
        t = self._escalated()
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'confirmed incident')
        self.assertEqual(t.status, Ticket.STATUS_T1_REVIEW)

    def test_t2_reclassifies_event_and_closes(self):
        t = self._escalated()
        t.classification = Ticket.CLASSIFICATION_EVENT  # T2 may revise classification
        t.transition_to(Ticket.STATUS_CLOSED_EVENT, self.t2, 'benign on review')
        self.assertEqual(t.status, Ticket.STATUS_CLOSED_EVENT)

    def test_t2_cannot_assign_to_admin(self):
        """No ESCALATED_T2 → AWAITING_CONTAINMENT edge exists at all."""
        t = self._escalated()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t2, 'forbidden')

    def test_t2_cannot_create_ticket(self):
        self.client.login(username='t2t_t2', password='testpass123')
        resp = self.client.post(reverse('create_ticket'), _ticket_post_data())
        self.assertEqual(resp.status_code, 302)  # redirected away, Tier 1 only
        self.assertFalse(Ticket.objects.filter(device_name='TEST-ENDPOINT-01').exists())

    def test_t1_review_then_assign_admin(self):
        t = self._escalated()
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'confirm')
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'assign admin')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)


# ──────────────────────────────────────────────────────────────────────────── #
# 7. Manager routing (requires_manager_verification)                           #
# ──────────────────────────────────────────────────────────────────────────── #

class ManagerRoutingTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('mr_t1')
        cls.t2    = _make_t2('mr_t2')
        cls.mgr   = _make_user('mr_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('mr_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _contained(self, severity='High', is_emergency=False):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            assigned_admin=self.admin, status=Ticket.STATUS_CONTAINMENT_REPORTED,
            severity=severity, is_emergency=is_emergency, containment_report='done',
        )

    def test_critical_does_not_require_manager(self):
        """Severity alone never routes to the manager — only the emergency flag."""
        t = self._contained(severity='Critical')
        self.assertFalse(t.requires_manager_verification)

    def test_high_does_not_require_manager(self):
        t = self._contained(severity='High')
        self.assertFalse(t.requires_manager_verification)

    def test_emergency_forces_manager_even_on_high(self):
        t = self._contained(severity='High', is_emergency=True)
        self.assertTrue(t.requires_manager_verification)

    def test_non_emergency_ticket_t2_closes_directly(self):
        t = self._contained(severity='High')
        t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'verified — closed')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_critical_non_emergency_t2_closes_directly(self):
        t = self._contained(severity='Critical')
        t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'verified — closed')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_non_emergency_ticket_cannot_route_to_manager(self):
        t = self._contained(severity='High')
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t2, 'no need')

    def test_emergency_ticket_t2_cannot_close_directly(self):
        t = self._contained(severity='High', is_emergency=True)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'must go to manager')

    def test_emergency_ticket_routes_to_manager_then_closes(self):
        t = self._contained(severity='High', is_emergency=True)
        t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t2, 'T2 verified')
        t.transition_to(Ticket.STATUS_APPROVED, self.mgr, 'approved')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)


# ──────────────────────────────────────────────────────────────────────────── #
# 7b. Direct-to-Owner fast path (Low/Medium)                                    #
# ──────────────────────────────────────────────────────────────────────────── #

def _owner_payload(severity='Low', **overrides):
    """A valid create_ticket POST payload for the direct-to-owner route.

    Extends _ticket_post_data with the direct-owner route and a lower default
    statutory severity suitable for the owner-remediation fast path.
    """
    data = _ticket_post_data(
        classification=Ticket.CLASSIFICATION_INCIDENT,
        t1_route=TicketForm.ROUTE_DIRECT_OWNER,
        severity=severity,
        ncsa_severity=Ticket.NCSA_SEVERITY_NON_SEVERE,
        log_source='Windows Security Event Log',
    )
    data.update(overrides)
    return data


class DirectToOwnerPathTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('do_t1')
        cls.other = _make_t1('do_other')   # a different Tier 1 (not the creator)
        cls.t2    = _make_t2('do_t2')
        cls.mgr   = _make_user('do_mgr', UserProfile.ROLE_SOC_MANAGER)

    def _owner_case(self, severity='Low', is_emergency=False,
                    status=Ticket.STATUS_AWAITING_OWNER):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            severity=severity, is_emergency=is_emergency, status=status,
        )

    # ── Model FSM: happy path (Low, non-emergency → Tier 2 review) ──────── #
    def test_full_owner_path_low_severity_closes_via_tier2(self):
        t = self._owner_case(status=Ticket.STATUS_NEW)
        t.transition_to(Ticket.STATUS_AWAITING_OWNER, self.t1, 'phoned owner')
        self.assertTrue(t.direct_owner_remediation)
        self.assertIsNotNone(t.owner_contacted_at)

        t.transition_to(Ticket.STATUS_OWNER_REMEDIATED, self.t1, 'owner fixed')
        t.transition_to(Ticket.STATUS_PENDING_T2_REVIEW, self.t1, 'to review')
        self.assertIsNone(t.verified_by)           # verification is T2's act now

        t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'reviewed & closed')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)
        self.assertEqual(t.verified_by, self.t2)   # T2 sign-off stamped at close
        self.assertEqual(t.approved_by, self.t2)
        self.assertIsNotNone(t.closed_at)

    # ── Review split: non-emergency → Tier 2 only (never the manager) ───── #
    def test_non_emergency_routes_to_tier2_not_manager(self):
        t = self._owner_case(status=Ticket.STATUS_OWNER_REMEDIATED)
        self.assertTrue(t.can_transition_to(Ticket.STATUS_PENDING_T2_REVIEW))
        self.assertFalse(t.can_transition_to(Ticket.STATUS_PENDING_MANAGER))
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t1, 'no')

    # ── Review split: emergency passes Tier 2 first, then the Manager ───── #
    def test_emergency_owner_path_passes_t2_then_manager(self):
        t = self._owner_case(is_emergency=True,
                             status=Ticket.STATUS_OWNER_REMEDIATED)
        # Every owner case goes to Tier 2 review — including emergencies.
        t.transition_to(Ticket.STATUS_PENDING_T2_REVIEW, self.t1, 'to review')
        # Tier 2 may not close an emergency directly; it must go to the manager.
        self.assertFalse(t.can_transition_to(Ticket.STATUS_APPROVED))
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'no')
        t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t2, 'to manager')
        t.transition_to(Ticket.STATUS_APPROVED, self.mgr, 'approved')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    # ── Tier 2 reject loops back to the owner ──────────────────────────── #
    def test_tier2_can_reject_back_to_owner(self):
        t = self._owner_case(status=Ticket.STATUS_PENDING_T2_REVIEW)
        t.transition_to(Ticket.STATUS_AWAITING_OWNER, self.t2, 'not actually fixed')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_OWNER)

    # ── Permissions: T1 side is creator-gated; review close is Tier 2 ───── #
    def test_non_creator_t1_cannot_confirm(self):
        t = self._owner_case(status=Ticket.STATUS_AWAITING_OWNER)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_OWNER_REMEDIATED, self.other, 'nope')

    def test_tier2_review_close_requires_tier2(self):
        t = self._owner_case(status=Ticket.STATUS_PENDING_T2_REVIEW)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t1, 'T1 cannot close a T2 review')

    # ── Critical severity alone no longer routes to the SOC Manager ─────── #
    def test_critical_severity_still_closes_via_tier2(self):
        t = self._owner_case(severity='Critical',
                             status=Ticket.STATUS_OWNER_REMEDIATED)
        self.assertTrue(t.can_transition_to(Ticket.STATUS_PENDING_T2_REVIEW))
        t.transition_to(Ticket.STATUS_PENDING_T2_REVIEW, self.t1, 'to review')
        t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'verified — closed')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    # ── Form gating: route valid at any severity ───────────────────────── #
    def test_form_accepts_direct_owner_for_low_severity(self):
        form = TicketForm(data=_owner_payload(severity='Low'), user=self.t1)
        self.assertTrue(form.is_valid(), form.errors)

    def test_form_accepts_direct_owner_for_high_severity(self):
        form = TicketForm(data=_owner_payload(severity='High'), user=self.t1)
        self.assertTrue(form.is_valid(), form.errors)

    # ── Create-flow view: routes to AWAITING_OWNER, sends no admin email ── #
    def test_create_view_routes_to_awaiting_owner_without_email(self):
        self.client.login(username='do_t1', password='testpass123')
        mail.outbox = []
        resp = self.client.post(reverse('create_ticket'), _owner_payload(severity='Low'))
        self.assertEqual(resp.status_code, 302)
        t = Ticket.objects.latest('id')
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_OWNER)
        self.assertTrue(t.direct_owner_remediation)
        self.assertIsNone(t.assigned_admin)
        self.assertEqual(len(mail.outbox), 0)


# ──────────────────────────────────────────────────────────────────────────── #
# 8. Emergency flag permissions + audit                                        #
# ──────────────────────────────────────────────────────────────────────────── #

class EmergencyFlagTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('em_t1')
        cls.t2    = _make_t2('em_t2')
        cls.mgr   = _make_user('em_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('em_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.owner = _make_user('em_owner', UserProfile.ROLE_SYSTEM_OWNER)
        cls.superuser = User.objects.create_superuser('em_super', 'em@x.com', 'testpass123')

    def _direct_admin_ticket(self):
        """Incident handed directly to admin — never escalated to T2."""
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            assigned_admin=self.admin, status=Ticket.STATUS_AWAITING_CONTAINMENT,
        )

    def _escalated_ticket(self):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_ESCALATED_T2, escalated_to_t2_at=timezone.now(),
        )

    # ── Tier 1 gating ───────────────────────────────────────────────────── #

    def test_t1_cannot_set_emergency_on_direct_admin_ticket(self):
        t = self._direct_admin_ticket()
        self.assertFalse(t.can_set_emergency(self.t1))
        with self.assertRaises(ValidationError):
            t.set_emergency(True, self.t1)

    def test_t1_can_set_emergency_on_escalated_ticket(self):
        t = self._escalated_ticket()
        self.assertTrue(t.can_set_emergency(self.t1))
        t.set_emergency(True, self.t1)
        t.refresh_from_db()
        self.assertTrue(t.is_emergency)

    def test_t1_can_set_emergency_after_t2_returned_ticket(self):
        """escalated_to_t2_at survives the return to T1, so the gate stays open."""
        t = self._escalated_ticket()
        t.transition_to(Ticket.STATUS_T1_REVIEW, self.t2, 'returned')
        self.assertTrue(t.can_set_emergency(self.t1))

    # ── Other roles ungated ─────────────────────────────────────────────── #

    def test_t2_can_set_emergency_on_any_ticket(self):
        t = self._direct_admin_ticket()
        self.assertTrue(t.can_set_emergency(self.t2))

    def test_manager_can_set_emergency(self):
        self.assertTrue(self._direct_admin_ticket().can_set_emergency(self.mgr))

    def test_system_admin_can_set_emergency(self):
        self.assertTrue(self._direct_admin_ticket().can_set_emergency(self.admin))

    def test_superuser_can_set_emergency(self):
        t = self._direct_admin_ticket()
        self.assertTrue(t.can_set_emergency(self.superuser))

    # ── Mutable at any stage + audit ────────────────────────────────────── #

    def test_emergency_toggleable_at_terminal_stage(self):
        t = _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            status=Ticket.STATUS_APPROVED,
        )
        t.set_emergency(True, self.mgr)
        t.refresh_from_db()
        self.assertTrue(t.is_emergency)

    def test_setting_emergency_writes_audit_log(self):
        t = self._escalated_ticket()
        before = t.logs.count()
        t.set_emergency(True, self.t1, 'urgent')
        self.assertEqual(t.logs.count(), before + 1)
        log = t.logs.first()
        self.assertEqual(log.author, self.t1)
        self.assertIn('Emergency', log.note)

    def test_no_op_toggle_does_not_log(self):
        t = self._escalated_ticket()
        before = t.logs.count()
        t.set_emergency(False, self.t1)  # already False
        self.assertEqual(t.logs.count(), before)

    def test_clear_emergency_logs(self):
        t = self._escalated_ticket()
        t.set_emergency(True, self.t2)
        t.set_emergency(False, self.t2)
        t.refresh_from_db()
        self.assertFalse(t.is_emergency)


# ──────────────────────────────────────────────────────────────────────────── #
# 9. System Admin field access                                                 #
# ──────────────────────────────────────────────────────────────────────────── #

class AdminFieldAccessTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('af_t1')
        cls.admin = _make_user('af_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _awaiting(self):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            assigned_admin=self.admin, status=Ticket.STATUS_AWAITING_CONTAINMENT,
        )

    def test_admin_writes_containment_and_remediation(self):
        t = self._awaiting()
        self.client.login(username='af_admin', password='testpass123')
        resp = self.client.post(reverse('ticket_detail', args=[t.pk]), {
            'action': 'containment',
            'containment_report': 'Isolated the host and blocked the C2 IP.',
            'remediation_summary': 'Root cause: phishing. Reimaged endpoint.',
            'note': 'done',
        })
        self.assertRedirects(resp, reverse('ticket_detail', args=[t.pk]))
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_CONTAINMENT_REPORTED)
        self.assertIn('blocked the C2 IP', t.containment_report)
        self.assertIn('Reimaged endpoint', t.remediation_summary)

    def test_admin_containment_does_not_set_classification(self):
        t = self._awaiting()
        self.client.login(username='af_admin', password='testpass123')
        self.client.post(reverse('ticket_detail', args=[t.pk]), {
            'action': 'containment',
            'containment_report': 'Contained.',
            'note': 'done',
        })
        t.refresh_from_db()
        # classification stays whatever T1 set — admin never touches it.
        self.assertEqual(t.classification, Ticket.CLASSIFICATION_INCIDENT)


# ──────────────────────────────────────────────────────────────────────────── #
# 10. Sign-off field tests                                                     #
# ──────────────────────────────────────────────────────────────────────────── #

class SignOffFieldsTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('sf_t1')
        cls.t2    = _make_t2('sf_t2')
        cls.t2b   = _make_t2('sf_t2b')
        cls.mgr   = _make_user('sf_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('sf_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def _incident(self, severity='Critical', is_emergency=True):
        # Manager routing now keys off the emergency flag, not severity.
        return _make_ticket(
            assigned_admin=self.admin, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT, severity=severity,
            is_emergency=is_emergency,
        )

    def test_verified_by_set_when_t2_marks_contained(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_PENDING_MANAGER, self.t1, self.admin,
                    mgr=self.mgr, t2=self.t2)
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.t2)
        self.assertIsNotNone(t.verified_at)

    def test_approved_by_set_to_manager(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin,
                    mgr=self.mgr, t2=self.t2)
        t.refresh_from_db()
        self.assertEqual(t.approved_by, self.mgr)

    def test_direct_close_sets_both_signoffs_to_t2(self):
        t = self._incident(severity='High', is_emergency=False)  # no manager needed
        _advance_to(t, Ticket.STATUS_APPROVED, self.t1, self.admin, t2=self.t2)
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.t2)
        self.assertEqual(t.approved_by, self.t2)

    def test_verified_by_write_once(self):
        t = self._incident()
        _advance_to(t, Ticket.STATUS_PENDING_MANAGER, self.t1, self.admin,
                    mgr=self.mgr, t2=self.t2)
        t.refresh_from_db()
        # Force back to CONTAINMENT_REPORTED; a different Tier 2 re-verifies —
        # the original verified_by must hold (write-once).
        Ticket.objects.filter(pk=t.pk).update(
            status=Ticket.STATUS_CONTAINMENT_REPORTED,
        )
        t.refresh_from_db()
        t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t2b, 'again')
        t.refresh_from_db()
        self.assertEqual(t.verified_by, self.t2)


# ──────────────────────────────────────────────────────────────────────────── #
# 11. Email notification tests                                                  #
# ──────────────────────────────────────────────────────────────────────────── #

class NotificationEmailTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1  = _make_t1('ne_t1')
        cls.admin = _make_user('ne_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin.email = 'sysadmin@example.com'
        cls.admin.save()
        cls.admin_no_email = _make_user('ne_admin_noemail', UserProfile.ROLE_SYSTEM_ADMIN)

    def setUp(self):
        mail.outbox = []

    def _routed_ticket(self):
        t = _make_ticket(
            assigned_admin=self.admin, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'routing')
        return t

    def test_routing_sends_one_email_to_admin(self):
        t = self._routed_ticket()
        self.assertTrue(notify_containment_required(t))
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(self.admin.email, mail.outbox[0].to)

    def test_routing_subject_contains_ticket_id(self):
        t = self._routed_ticket()
        notify_containment_required(t)
        self.assertIn(t.ticket_id, mail.outbox[0].subject)

    def test_rejection_loop_body_contains_reason(self):
        t = self._routed_ticket()
        reason = 'Patch description is missing — include the CVE reference.'
        notify_containment_required(t, reason=reason)
        self.assertIn(reason, mail.outbox[0].body)

    def test_no_email_when_admin_has_no_email(self):
        t = _make_ticket(
            assigned_admin=self.admin_no_email, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        self.assertFalse(notify_containment_required(t))
        self.assertEqual(len(mail.outbox), 0)

    def test_transition_succeeds_without_email(self):
        t = _make_ticket(
            assigned_admin=self.admin_no_email, created_by=self.t1,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        t.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.t1, 'routing')
        t.refresh_from_db()
        self.assertEqual(t.status, Ticket.STATUS_AWAITING_CONTAINMENT)


# ──────────────────────────────────────────────────────────────────────────── #
# 12. Wazuh triage: 2-action + required release reason                          #
# ──────────────────────────────────────────────────────────────────────────── #

class WazuhTriageActionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_t1('wz_t1')
        cls.t2 = _make_t2('wz_t2')

    def _claimed_alert(self, claimer):
        return WazuhAlert.objects.create(
            opensearch_id=f'os-{claimer.username}-{timezone.now().timestamp()}',
            timestamp=timezone.now(), rule_level=12,
            rule_description='Suspicious activity',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=claimer, claimed_at=timezone.now(),
        )

    def test_create_ticket_action_redirects_to_create_form(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk, 'action': 'create_ticket',
            'note': 'looks real', 'category': WazuhAlert.CATEGORY_MALWARE,
        })
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse('create_ticket'), resp.url)

    def test_close_fp_action_is_rejected(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk, 'action': 'close_fp', 'note': 'fp',
        })
        self.assertEqual(resp.status_code, 302)
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)  # unchanged

    def test_escalate_action_is_rejected(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk, 'action': 'escalate',
            'note': 'unsure', 'escalate_to': WazuhAlert.TIER_T2,
        })
        self.assertEqual(resp.status_code, 302)
        alert.refresh_from_db()
        self.assertNotEqual(alert.triage_status, WazuhAlert.TRIAGE_ESCALATED)

    def test_release_requires_reason(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('release_alert'), {'alert_id': alert.pk})
        self.assertEqual(resp.status_code, 302)
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)  # not released
        self.assertEqual(alert.release_reason, '')

    def test_release_with_reason_returns_to_pending(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='wz_t1', password='testpass123')
        resp = self.client.post(reverse('release_alert'), {
            'alert_id': alert.pk, 'release_reason': 'Need more context from the host owner.',
        })
        self.assertEqual(resp.status_code, 302)
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_PENDING)
        self.assertIsNone(alert.claimed_by)
        self.assertIn('more context', alert.release_reason)

    def test_tier2_cannot_claim(self):
        alert = WazuhAlert.objects.create(
            opensearch_id='os-pending', timestamp=timezone.now(), rule_level=10,
            triage_status=WazuhAlert.TRIAGE_PENDING,
        )
        self.client.login(username='wz_t2', password='testpass123')
        self.client.post(reverse('claim_alert'), {'alert_id': alert.pk})
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_PENDING)
        self.assertIsNone(alert.claimed_by)


# ──────────────────────────────────────────────────────────────────────────── #
# 13. Triage / wazuh-alert ticket creation integrity                           #
# ──────────────────────────────────────────────────────────────────────────── #

class TriageWorkflowIntegrityTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1       = _make_t1('manual_t1')
        cls.other_t1 = _make_t1('manual_t1_other')
        cls.t2       = _make_t2('manual_t2')

    def test_manual_triage_form_has_no_pre_ticket_decision_or_escalation(self):
        form = TriageForm(user=self.t1)
        self.assertNotIn('decision', form.fields)
        self.assertNotIn('escalated_to', form.fields)

    def test_non_owner_cannot_create_ticket_from_manual_triage(self):
        triage = TriageRecord.objects.create(
            source=TriageRecord.SOURCE_PHONE, analyst=self.t1,
            alert_description='Reported suspicious login.',
            decision=TriageRecord.DECISION_TP, notes='Confirmed by T1.',
        )
        self.client.login(username='manual_t1_other', password='testpass123')
        response = self.client.get(reverse('create_ticket'), {'triage_id': triage.pk})
        self.assertRedirects(response, reverse('triage_list'))
        self.assertFalse(Ticket.objects.exists())

    def test_create_ticket_from_manual_triage_prefills_source(self):
        """The triage source channel auto-fills the ticket's Source (issue_type).

        issue_type and TriageRecord.source share the SOURCE_CHOICES vocabulary,
        so the value carries straight over on the create form's GET.
        """
        triage = TriageRecord.objects.create(
            source=TriageRecord.SOURCE_PHONE, analyst=self.t1,
            alert_description='Reported suspicious login.', source_ip='192.0.2.50',
            decision=TriageRecord.DECISION_TP, notes='Confirmed by T1.',
        )
        self.client.force_login(self.t1)
        response = self.client.get(reverse('create_ticket'), {'triage_id': triage.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context['form'].initial.get('issue_type'),
            TriageRecord.SOURCE_PHONE,
        )

    def test_wazuh_alert_becomes_true_positive_after_ticket_save(self):
        alert = WazuhAlert.objects.create(
            opensearch_id='ticket-finalize-alert', timestamp=timezone.now(),
            rule_level=14, rule_description='Confirmed ransomware behavior',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=self.t1, claimed_at=timezone.now(),
            triage_note='Confirmed malicious.', incident_category=WazuhAlert.CATEGORY_MALWARE,
        )
        self.client.login(username='manual_t1', password='testpass123')
        response = self.client.post(reverse('create_ticket'), _ticket_post_data(
            wazuh_alert=alert.pk,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ESCALATE_T2,
        ))
        self.assertEqual(response.status_code, 302)
        ticket = Ticket.objects.get(wazuh_alert=alert)
        alert.refresh_from_db()
        self.assertEqual(ticket.created_by, self.t1)
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRUE_POSITIVE)
        self.assertIsNone(alert.claimed_by)

    def test_wazuh_event_ticket_is_recorded_as_event_history(self):
        alert = WazuhAlert.objects.create(
            opensearch_id='ticket-event-alert', timestamp=timezone.now(),
            rule_level=10, rule_description='Benign scheduled activity',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=self.t1, claimed_at=timezone.now(),
        )
        self.client.force_login(self.t1)
        self.client.post(reverse('create_ticket'), _ticket_post_data(
            wazuh_alert=alert.pk,
            classification=Ticket.CLASSIFICATION_EVENT,
            t1_route='',
        ))
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_FALSE_POSITIVE)

    def test_manual_triage_claim_and_reason_required_release(self):
        triage = TriageRecord.objects.create(
            source=TriageRecord.SOURCE_PHONE,
            analyst=self.t1,
            alert_description='Manual intake awaiting claim.',
            notes='Caller reported unusual behavior.',
        )
        self.client.force_login(self.t1)
        self.client.post(reverse('claim_manual_triage', args=[triage.pk]))
        triage.refresh_from_db()
        self.assertEqual(triage.claimed_by, self.t1)

        self.client.post(reverse('release_manual_triage', args=[triage.pk]), {
            'release_reason': '   ',
        })
        triage.refresh_from_db()
        self.assertEqual(triage.claimed_by, self.t1)

        self.client.post(reverse('release_manual_triage', args=[triage.pk]), {
            'release_reason': 'Shift handoff.',
        })
        triage.refresh_from_db()
        self.assertIsNone(triage.claimed_by)
        self.assertEqual(triage.release_reason, 'Shift handoff.')

    def test_invalid_ticket_form_keeps_wazuh_alert_in_progress(self):
        alert = WazuhAlert.objects.create(
            opensearch_id='invalid-ticket-alert', timestamp=timezone.now(),
            rule_level=12, rule_description='Suspicious command execution',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=self.t1, claimed_at=timezone.now(),
        )
        self.client.login(username='manual_t1', password='testpass123')
        response = self.client.post(reverse('create_ticket'), {'wazuh_alert': alert.pk})
        self.assertEqual(response.status_code, 200)
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)
        self.assertFalse(Ticket.objects.filter(wazuh_alert=alert).exists())


# ──────────────────────────────────────────────────────────────────────────── #
# 14. Superuser bypass                                                          #
# ──────────────────────────────────────────────────────────────────────────── #

class SuperuserAccessTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.superuser = User.objects.create_superuser(
            username='all_access_superuser', email='superuser@example.com',
            password='testpass123',
        )
        cls.system_admin = _make_user('superuser_target_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.t1 = _make_t1('superuser_t1')
        cls.t2 = _make_t2('superuser_t2')

    def setUp(self):
        self.client.force_login(self.superuser)

    def test_superuser_without_profile_sees_all_tickets(self):
        first = _make_ticket(issue_description='First ticket')
        second = _make_ticket(issue_description='Second ticket', assigned_admin=self.system_admin)
        self.assertFalse(hasattr(self.superuser, 'profile'))
        self.assertQuerySetEqual(
            Ticket.objects.visible_to(self.superuser).order_by('pk'), [first, second],
        )

    def test_superuser_can_access_core_pages(self):
        ticket = _make_ticket()
        urls = [
            reverse('home'), reverse('ticket_list'), reverse('create_ticket'),
            reverse('ticket_detail', args=[ticket.pk]), reverse('ticket_history'),
            reverse('triage_list'), reverse('create_triage'),
            reverse('system_owner_dashboard'),
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_superuser_can_perform_every_ticket_role_transition(self):
        # Emergency flag set so the ticket legally routes through PENDING_MANAGER
        # (severity alone no longer triggers the manager gate).
        ticket = _make_ticket(
            assigned_admin=self.system_admin, severity='Critical',
            classification=Ticket.CLASSIFICATION_INCIDENT, is_emergency=True,
        )
        ticket.transition_to(Ticket.STATUS_AWAITING_CONTAINMENT, self.superuser, 'as t1')
        ticket.containment_report = 'Contained by superuser.'
        ticket.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, self.superuser, 'as admin')
        ticket.transition_to(Ticket.STATUS_PENDING_MANAGER, self.superuser, 'verify')
        ticket.transition_to(Ticket.STATUS_APPROVED, self.superuser, 'as manager')
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_APPROVED)
        self.assertEqual(ticket.verified_by, self.superuser)
        self.assertEqual(ticket.approved_by, self.superuser)

    def test_superuser_can_submit_containment_for_any_ticket(self):
        ticket = _make_ticket(
            assigned_admin=self.system_admin, status=Ticket.STATUS_AWAITING_CONTAINMENT,
            classification=Ticket.CLASSIFICATION_INCIDENT,
        )
        response = self.client.post(reverse('ticket_detail', args=[ticket.pk]), {
            'action': 'containment',
            'containment_report': 'Superuser containment report.',
            'note': 'Completed with all-role access.',
        })
        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.STATUS_CONTAINMENT_REPORTED)


# ──────────────────────────────────────────────────────────────────────────── #
# 15. Attachment download authorization                                         #
# ──────────────────────────────────────────────────────────────────────────── #

@override_settings(MEDIA_ROOT=tempfile.mkdtemp(prefix='soc_test_media_'))
class AttachmentDownloadSecurityTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_t1('att_soc')
        cls.admin_a = _make_user('att_admin_a', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b = _make_user('att_admin_b', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.ticket_a = _make_ticket(assigned_admin=cls.admin_a)
        cls.attachment = TicketAttachment.objects.create(
            ticket=cls.ticket_a,
            file=SimpleUploadedFile(
                'evidence.html', b'<script>alert(document.cookie)</script>',
                content_type='text/html',
            ),
            original_name='evidence.html', uploaded_by=cls.soc_staff,
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(settings.MEDIA_ROOT, ignore_errors=True)

    def _url(self):
        return reverse('download_attachment', args=[self.attachment.pk])

    def test_unauthenticated_redirected_to_login(self):
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response['Location'])

    def test_authorized_user_downloads_with_safe_headers(self):
        self.client.force_login(self.soc_staff)
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response['Content-Disposition'].startswith('attachment'))
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

    def test_admin_cannot_download_attachment_on_unrelated_ticket(self):
        self.client.force_login(self.admin_b)
        self.assertEqual(self.client.get(self._url()).status_code, 404)


# ──────────────────────────────────────────────────────────────────────────── #
# 16. Attachment upload size limit                                              #
# ──────────────────────────────────────────────────────────────────────────── #

class AttachmentUploadLimitTest(TestCase):
    def test_oversize_file_rejected_by_form(self):
        with patch('apps.incidents.models.MAX_ATTACHMENT_SIZE', 10):
            form = AttachmentForm(
                data={'description': ''},
                files={'file': SimpleUploadedFile(
                    'big.bin', b'01234567890', content_type='application/octet-stream',
                )},
            )
            self.assertFalse(form.is_valid())
            self.assertIn('file', form.errors)

    def test_within_limit_file_accepted_by_form(self):
        form = AttachmentForm(
            data={'description': 'ok'},
            files={'file': SimpleUploadedFile('small.txt', b'hello', content_type='text/plain')},
        )
        self.assertTrue(form.is_valid(), msg=form.errors)


# ──────────────────────────────────────────────────────────────────────────── #
# 16b. Attachment upload type / content validation                              #
# ──────────────────────────────────────────────────────────────────────────── #

class AttachmentUploadTypeTest(TestCase):
    def test_disallowed_extension_rejected(self):
        """Active-web content (.html) is not on the evidence allowlist."""
        form = AttachmentForm(
            data={'description': ''},
            files={'file': SimpleUploadedFile(
                'evidence.html', b'<script>alert(1)</script>',
                content_type='text/html',
            )},
        )
        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)

    def test_extensionless_file_rejected(self):
        form = AttachmentForm(
            data={'description': ''},
            files={'file': SimpleUploadedFile('noext', b'data')},
        )
        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)

    def test_spoofed_image_content_rejected(self):
        """An allowed extension whose bytes don't match its type is refused."""
        form = AttachmentForm(
            data={'description': ''},
            files={'file': SimpleUploadedFile(
                'shot.png', b'<svg onload=alert(1)>', content_type='image/png',
            )},
        )
        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)

    def test_valid_png_accepted(self):
        png = b'\x89PNG\r\n\x1a\n' + b'\x00' * 32
        form = AttachmentForm(
            data={'description': 'ok'},
            files={'file': SimpleUploadedFile('shot.png', png, content_type='image/png')},
        )
        self.assertTrue(form.is_valid(), msg=form.errors)

    def test_log_evidence_accepted(self):
        form = AttachmentForm(
            data={'description': 'ok'},
            files={'file': SimpleUploadedFile('firewall.log', b'deny 1.2.3.4')},
        )
        self.assertTrue(form.is_valid(), msg=form.errors)


# ──────────────────────────────────────────────────────────────────────────── #
# 17. 'Unknown' severity (additive, human-assigned)                            #
# ──────────────────────────────────────────────────────────────────────────── #

class UnknownSeverityTest(TestCase):
    """
    'Unknown' is a human-assigned severity for cases the analyst cannot yet
    classify. It is selectable in the manual create + manual triage forms,
    absent from the automated Wazuh mapping, ranks lowest for queue ordering
    (severity never routes to the manager — only the emergency flag), and
    renders a distinct badge.
    """

    @classmethod
    def setUpTestData(cls):
        cls.t1    = _make_t1('uk_t1')
        cls.t2    = _make_t2('uk_t2')
        cls.mgr   = _make_user('uk_mgr',   UserProfile.ROLE_SOC_MANAGER)
        cls.admin = _make_user('uk_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    # ── Model / choices ─────────────────────────────────────────────────── #
    def test_unknown_is_a_model_choice(self):
        self.assertIn(('Unknown', 'Unknown'), Ticket.SEVERITY_CHOICES)

    def test_unknown_ranks_lowest(self):
        ranks = Ticket.SEVERITY_RANK
        self.assertEqual(ranks['Unknown'], 0)
        self.assertLess(ranks['Unknown'], min(
            ranks['Low'], ranks['Medium'], ranks['High'], ranks['Critical']
        ))

    # ── Availability: manual create + manual triage forms ───────────────── #
    def test_unknown_selectable_on_manual_create_form(self):
        values = [v for v, _ in TicketForm().fields['severity'].choices]
        self.assertIn('Unknown', values)

    def test_unknown_selectable_on_manual_triage_create_form(self):
        # A ticket opened from a manual TriageRecord uses the same TicketForm,
        # so 'Unknown' must be offered there too.
        triage = TriageRecord.objects.create(
            source=TriageRecord.SOURCE_PHONE, analyst=self.t1,
            alert_description='Caller reported odd activity, severity unclear.',
            decision=TriageRecord.DECISION_TP, notes='Cannot yet classify.',
        )
        self.client.force_login(self.t1)
        response = self.client.get(reverse('create_ticket'), {'triage_id': triage.pk})
        self.assertEqual(response.status_code, 200)
        values = [v for v, _ in response.context['form'].fields['severity'].choices]
        self.assertIn('Unknown', values)

    def test_unknown_accepted_when_creating_ticket(self):
        self.client.force_login(self.t1)
        response = self.client.post(reverse('create_ticket'), _ticket_post_data(
            severity='Unknown',
            classification=Ticket.CLASSIFICATION_INCIDENT,
            t1_route=TicketForm.ROUTE_ESCALATE_T2,
        ))
        self.assertEqual(response.status_code, 302)
        ticket = Ticket.objects.get(device_name='TEST-ENDPOINT-01')
        self.assertEqual(ticket.severity, 'Unknown')

    # ── Availability: NOT in automated Wazuh ingest mapping ─────────────── #
    def test_unknown_absent_from_wazuh_severity_mapping(self):
        from apps.wazuh_ingest.views import _severity_for_rule_level
        mapped = {_severity_for_rule_level(level) for level in range(0, 20)}
        self.assertNotIn('Unknown', mapped)
        self.assertTrue(mapped <= {'Critical', 'High', 'Medium', 'Low'})

    # ── Routing: emergency flag is the only path to the manager ─────────── #
    def _contained(self, is_emergency=False):
        return _make_ticket(
            created_by=self.t1, classification=Ticket.CLASSIFICATION_INCIDENT,
            assigned_admin=self.admin, status=Ticket.STATUS_CONTAINMENT_REPORTED,
            severity='Unknown', is_emergency=is_emergency, containment_report='done',
        )

    def test_unknown_without_emergency_does_not_require_manager(self):
        self.assertFalse(self._contained().requires_manager_verification)

    def test_unknown_without_emergency_t2_closes_directly(self):
        t = self._contained()
        t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'closed — no manager needed')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    def test_unknown_without_emergency_cannot_route_to_manager(self):
        t = self._contained()
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t2, 'no need')

    def test_unknown_with_emergency_requires_manager(self):
        self.assertTrue(self._contained(is_emergency=True).requires_manager_verification)

    def test_unknown_with_emergency_routes_to_manager(self):
        t = self._contained(is_emergency=True)
        with self.assertRaises(ValidationError):
            t.transition_to(Ticket.STATUS_APPROVED, self.t2, 'blocked by emergency')
        t.transition_to(Ticket.STATUS_PENDING_MANAGER, self.t2, 'route to manager')
        t.transition_to(Ticket.STATUS_APPROVED, self.mgr, 'approved')
        self.assertEqual(t.status, Ticket.STATUS_APPROVED)

    # ── Display: distinct badge ─────────────────────────────────────────── #
    def test_unknown_badge_renders_distinctly(self):
        from django.template.loader import render_to_string
        html = render_to_string('incidents/_severity_badge.html', {'severity': 'Unknown'})
        self.assertIn('Unknown', html)
        self.assertIn('#6f42c1', html)  # distinct colour, not reused by any severity
        # Sanity: the Unknown badge must not borrow an existing severity colour.
        for other_colour in ('bg-danger', '#fd7e14', 'bg-warning', 'bg-success'):
            self.assertNotIn(other_colour, html)


# ──────────────────────────────────────────────────────────────────────────── #
# Threat-type cascade: detailed_issue → detailed_issue2                         #
# ──────────────────────────────────────────────────────────────────────────── #

class DetailedIssueCascadeTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_t1('cascade_t1')

    def test_form_hides_legacy_source_flavoured_categories(self):
        """Only the 10 clean threat categories are offered; leftovers hidden."""
        form = TicketForm(user=self.t1)
        codes = [c for c, _ in form.fields['detailed_issue'].choices]
        self.assertIn('Malicious Logic', codes)
        self.assertNotIn('SIEM Other', codes)
        self.assertNotIn('TI IOC', codes)
        self.assertNotIn('External Other', codes)

    def test_mismatched_detailed_issue_pair_is_rejected(self):
        form = TicketForm(
            data=_ticket_post_data(
                detailed_issue='Malicious Logic',
                detailed_issue2='Port Scanning',  # belongs to Reconnaissance
            ),
            user=self.t1,
        )
        self.assertFalse(form.is_valid())
        self.assertIn('detailed_issue2', form.errors)

    def test_matching_detailed_issue_pair_is_accepted(self):
        form = TicketForm(
            data=_ticket_post_data(
                detailed_issue='Malicious Logic',
                detailed_issue2='Ransomware Behavior',
            ),
            user=self.t1,
        )
        self.assertTrue(form.is_valid(), form.errors)

    def test_create_form_prefills_parent_from_detailed_issue2(self):
        """A detailed_issue2 passed in the URL (e.g. from Wazuh) sets its parent."""
        self.client.force_login(self.t1)
        response = self.client.get(reverse('create_ticket'), {'detailed_issue2': 'Malware EDR'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['form'].initial.get('detailed_issue'), 'Malicious Logic')
        self.assertEqual(response.context['form'].initial.get('detailed_issue2'), 'Malware EDR')

    def test_create_form_renders_cascade_wiring(self):
        """The cascade include renders: JSON payload + the ids the JS targets."""
        self.client.force_login(self.t1)
        html = self.client.get(reverse('create_ticket')).content.decode()
        self.assertIn('id="detailed-issue-cascade"', html)   # json_script payload
        self.assertIn('Malicious Logic', html)               # a hierarchy key is embedded
        self.assertIn('id="id_detailed_issue"', html)        # parent select
        self.assertIn('id="id_detailed_issue2"', html)       # child select


class TicketListOlaFilterTest(TestCase):
    """The ticket-list ?ola= filter buckets the active queue by time-to-deadline,
    sharing thresholds with the dashboard OLA chart (apps.incidents.ola)."""

    @classmethod
    def setUpTestData(cls):
        cls.t1 = _make_t1('ola_filter_t1')  # SOC staff → sees all tickets
        now = timezone.now()
        cls.overdue  = _make_ticket(ola_contain_deadline=now - timedelta(hours=1))
        cls.due_1h   = _make_ticket(ola_contain_deadline=now + timedelta(minutes=30))
        cls.due_4h   = _make_ticket(ola_contain_deadline=now + timedelta(hours=2))
        cls.on_track = _make_ticket(ola_contain_deadline=now + timedelta(hours=10))

    def _list(self, **params):
        self.client.force_login(self.t1)
        resp = self.client.get(reverse('ticket_list'), params)
        return {t.pk for t in resp.context['page_obj']}, resp

    def test_overdue_filter_returns_only_overdue(self):
        ids, resp = self._list(ola='overdue')
        self.assertEqual(ids, {self.overdue.pk})
        self.assertEqual(resp.context['ola_filter'], 'overdue')

    def test_due_1h_filter_returns_only_due_within_1h(self):
        ids, _ = self._list(ola='due_1h')
        self.assertEqual(ids, {self.due_1h.pk})

    def test_on_track_filter_returns_only_on_track(self):
        ids, _ = self._list(ola='on_track')
        self.assertEqual(ids, {self.on_track.pk})

    def test_no_filter_returns_all_active(self):
        ids, _ = self._list()
        self.assertEqual(
            ids, {self.overdue.pk, self.due_1h.pk, self.due_4h.pk, self.on_track.pk})

    def test_invalid_bucket_is_ignored(self):
        ids, resp = self._list(ola='bogus')
        self.assertEqual(resp.context['ola_filter'], '')
        self.assertEqual(len(ids), 4)


class OlaPolicyTest(TestCase):
    """Per-severity OLA targets (triage + contain) applied by Ticket.save().

    Policy: Critical 30m/4h, High 2h/24h, Medium & Low 24h/none (notify-only),
    Unknown mirrors Critical.
    """

    def _make(self, severity):
        base = timezone.now()
        return _make_ticket(severity=severity, incident_datetime=base), base

    def test_critical_targets(self):
        t, base = self._make('Critical')
        self.assertEqual(t.ola_triage_deadline, base + timedelta(minutes=30))
        self.assertEqual(t.ola_contain_deadline, base + timedelta(hours=4))

    def test_high_targets(self):
        t, base = self._make('High')
        self.assertEqual(t.ola_triage_deadline, base + timedelta(hours=2))
        self.assertEqual(t.ola_contain_deadline, base + timedelta(hours=24))

    def test_medium_triage_only_no_contain(self):
        t, base = self._make('Medium')
        self.assertEqual(t.ola_triage_deadline, base + timedelta(hours=24))
        self.assertIsNone(t.ola_contain_deadline)

    def test_low_triage_only_no_contain(self):
        t, base = self._make('Low')
        self.assertEqual(t.ola_triage_deadline, base + timedelta(hours=24))
        self.assertIsNone(t.ola_contain_deadline)

    def test_unknown_mirrors_critical(self):
        t, base = self._make('Unknown')
        self.assertEqual(t.ola_triage_deadline, base + timedelta(minutes=30))
        self.assertEqual(t.ola_contain_deadline, base + timedelta(hours=4))

    def test_triage_breach_vs_contain_breach_are_independent(self):
        base = timezone.now() - timedelta(hours=10)   # long ago
        t = _make_ticket(severity='Critical', incident_datetime=base,
                         status=Ticket.STATUS_NEW)
        # created_at is ~now, well past triage (base+30m) and contain (base+4h).
        self.assertTrue(t.is_ola_triage_breached)   # raised late
        self.assertTrue(t.is_ola_contain_breached)  # active + past contain
        # Notification-only severities never register a contain breach.
        low = _make_ticket(severity='Low', incident_datetime=base,
                           status=Ticket.STATUS_NEW)
        self.assertFalse(low.is_ola_contain_breached)


# ──────────────────────────────────────────────────────────────────────────── #
# Project Incident (Case Bundling) — one incident fanned out to many tickets    #
# ──────────────────────────────────────────────────────────────────────────── #

def _pi_post_data(admin_a, admin_b, **overrides):
    """A valid create_project_incident POST payload with 2 target systems."""
    data = {
        # shared incident facts
        'title': 'Multi-system intrusion via public-facing app',
        'severity': 'High',
        'ncsa_severity': Ticket.NCSA_SEVERITY_SEVERE,
        'log_source': 'Wazuh',
        'issue_type': 'SIEM',
        'detailed_issue': 'Malicious Logic',
        'detailed_issue2': 'C2 Server',
        'issue_description': 'Attacker pivoted across several core systems.',
        'action_required': 'Isolate host and rotate credentials.',
        'action_precautions': 'Preserve volatile evidence before reimaging.',
        'spread_to_others': 'true',
        # target formset management form
        'target-TOTAL_FORMS': '2',
        'target-INITIAL_FORMS': '0',
        'target-MIN_NUM_FORMS': '2',
        'target-MAX_NUM_FORMS': '25',
        # target A
        'target-0-device_name': 'HR Portal',
        'target-0-ip_address': '192.0.2.11',
        'target-0-assigned_admin': str(admin_a.pk),
        # target B
        'target-1-device_name': 'AD Server',
        'target-1-ip_address': '192.0.2.12',
        'target-1-assigned_admin': str(admin_b.pk),
    }
    data.update(overrides)
    return data


class BundleSuffixHelperTest(TestCase):
    def test_excel_style_labels(self):
        self.assertEqual(bundle_suffix_for_index(0), 'A')
        self.assertEqual(bundle_suffix_for_index(1), 'B')
        self.assertEqual(bundle_suffix_for_index(25), 'Z')
        self.assertEqual(bundle_suffix_for_index(26), 'AA')


class ProjectIncidentFanOutTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1      = _make_t1('pi_t1')
        cls.t2      = _make_t2('pi_t2')
        cls.admin_a = _make_user('pi_admin_a', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.admin_b = _make_user('pi_admin_b', UserProfile.ROLE_SYSTEM_ADMIN)

    def test_fanout_creates_linked_member_tickets(self):
        self.client.login(username='pi_t1', password='testpass123')
        resp = self.client.post(
            reverse('create_project_incident'),
            _pi_post_data(self.admin_a, self.admin_b),
        )
        self.assertEqual(resp.status_code, 302)

        project = ProjectIncident.objects.get()
        members = list(project.members)
        self.assertEqual(len(members), 2)

        # Trackable, ordered ids: PI-YYMMDD-NN-A / -B
        self.assertTrue(project.project_code.startswith('PI-'))
        self.assertEqual([m.bundle_suffix for m in members], ['A', 'B'])
        self.assertEqual(members[0].bundle_ref, f'{project.project_code}-A')
        self.assertEqual(members[1].display_id, f'{project.project_code}-B')

        # Each member routed to its own admin, awaiting containment, as Incident.
        self.assertEqual({m.assigned_admin for m in members}, {self.admin_a, self.admin_b})
        for m in members:
            self.assertEqual(m.status, Ticket.STATUS_AWAITING_CONTAINMENT)
            self.assertEqual(m.classification, Ticket.CLASSIFICATION_INCIDENT)
            self.assertEqual(m.created_by, self.t1)
            # Shared incident facts copied onto every member.
            self.assertEqual(m.action_required, 'Isolate host and rotate credentials.')
            self.assertEqual(m.issue_description, 'Attacker pivoted across several core systems.')
            self.assertEqual(m.detailed_issue2, 'C2 Server')
        # Per-target facts differ.
        self.assertEqual({m.device_name for m in members}, {'HR Portal', 'AD Server'})

    def test_members_keep_independent_lifecycle(self):
        """Closing one member must not move the others (grouping only)."""
        self.client.login(username='pi_t1', password='testpass123')
        self.client.post(
            reverse('create_project_incident'),
            _pi_post_data(self.admin_a, self.admin_b),
        )
        project = ProjectIncident.objects.get()
        first, second = list(project.members)
        _advance_to(first, Ticket.STATUS_APPROVED, self.t1, admin=self.admin_a, t2=self.t2)
        second.refresh_from_db()
        self.assertEqual(second.status, Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertEqual(project.open_member_count, 1)
        self.assertFalse(project.all_closed)

    def test_fewer_than_two_targets_is_rejected(self):
        self.client.login(username='pi_t1', password='testpass123')
        data = _pi_post_data(self.admin_a, self.admin_b)
        # Blank out the second target row → only one valid target remains.
        data['target-1-device_name'] = ''
        data['target-1-ip_address'] = ''
        data['target-1-assigned_admin'] = ''
        resp = self.client.post(reverse('create_project_incident'), data)
        self.assertEqual(resp.status_code, 200)  # re-rendered with errors
        self.assertFalse(ProjectIncident.objects.exists())
        self.assertFalse(Ticket.objects.exists())

    def test_non_tier1_cannot_open_fanout_page(self):
        self.client.login(username='pi_t2', password='testpass123')
        resp = self.client.get(reverse('create_project_incident'))
        self.assertEqual(resp.status_code, 302)  # Tier 1 only

    def test_detail_page_lists_members_for_soc(self):
        self.client.login(username='pi_t1', password='testpass123')
        self.client.post(
            reverse('create_project_incident'),
            _pi_post_data(self.admin_a, self.admin_b),
        )
        project = ProjectIncident.objects.get()
        resp = self.client.get(reverse('project_incident_detail', args=[project.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, project.project_code)
        self.assertContains(resp, 'HR Portal')
        self.assertContains(resp, 'AD Server')

    def test_detail_page_scopes_members_to_system_admin(self):
        """A system admin only sees the member ticket assigned to them."""
        self.client.login(username='pi_t1', password='testpass123')
        self.client.post(
            reverse('create_project_incident'),
            _pi_post_data(self.admin_a, self.admin_b),
        )
        project = ProjectIncident.objects.get()
        self.client.logout()
        self.client.login(username='pi_admin_a', password='testpass123')
        resp = self.client.get(reverse('project_incident_detail', args=[project.pk]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'HR Portal')      # assigned to admin_a
        self.assertNotContains(resp, 'AD Server')   # assigned to admin_b

    # ── Origin from a Wazuh alert (analyst-initiated, pre-filled) ──────── #

    def _claimed_alert(self, claimer):
        return WazuhAlert.objects.create(
            opensearch_id=f'os-pi-{claimer.username}-{timezone.now().timestamp()}',
            timestamp=timezone.now(), rule_level=13,
            rule_description='Coordinated intrusion across core systems',
            agent_name='DC-01',
            triage_status=WazuhAlert.TRIAGE_TRIAGING,
            claimed_by=claimer, claimed_at=timezone.now(),
        )

    def test_triage_action_routes_to_project_incident_keeping_claim(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='pi_t1', password='testpass123')
        resp = self.client.post(reverse('triage_action'), {
            'alert_id': alert.pk, 'action': 'create_project_incident',
            'note': 'multi-system', 'category': WazuhAlert.CATEGORY_MALWARE,
        })
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse('create_project_incident'), resp.url)
        self.assertIn(f'wazuh_alert={alert.pk}', resp.url)
        # Alert stays claimed + triaging until the fan-out form is saved.
        alert.refresh_from_db()
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRIAGING)
        self.assertEqual(alert.claimed_by, self.t1)

    def test_get_prefills_from_alert(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='pi_t1', password='testpass123')
        resp = self.client.get(
            reverse('create_project_incident'), {'wazuh_alert': alert.pk},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Coordinated intrusion across core systems')
        self.assertContains(resp, f'name="wazuh_alert" value="{alert.pk}"')

    def test_get_rejects_alert_not_claimed_by_user(self):
        alert = self._claimed_alert(self.t2)  # claimed by someone else
        self.client.login(username='pi_t1', password='testpass123')
        resp = self.client.get(
            reverse('create_project_incident'), {'wazuh_alert': alert.pk},
        )
        self.assertEqual(resp.status_code, 302)  # bounced back to the queue

    def test_fanout_from_alert_links_bundle_and_consumes_alert(self):
        alert = self._claimed_alert(self.t1)
        self.client.login(username='pi_t1', password='testpass123')
        data = _pi_post_data(self.admin_a, self.admin_b, wazuh_alert=str(alert.pk))
        resp = self.client.post(reverse('create_project_incident'), data)
        self.assertEqual(resp.status_code, 302)

        project = ProjectIncident.objects.get()
        alert.refresh_from_db()
        # Alert points at the whole bundle (option B), not a single ticket.
        self.assertEqual(alert.project_incident, project)
        self.assertFalse(hasattr(alert, 'ticket'))
        # Alert consumed → leaves the triage queue.
        self.assertEqual(alert.triage_status, WazuhAlert.TRIAGE_TRUE_POSITIVE)
        self.assertEqual(alert.triaged_by, self.t1)
        self.assertIsNone(alert.claimed_by)
        # Response time stamped on the first member.
        first = project.members.first()
        self.assertIsNotNone(first.alert_conversion_duration)
        # The bundle exposes its origin alert via the reverse relation.
        self.assertEqual(project.source_alerts.first(), alert)

    # ── Origin from a Manual Triage record ────────────────────────────── #

    def _claimed_triage(self, claimer):
        return TriageRecord.objects.create(
            source=TriageRecord.SOURCE_EMAIL,
            source_reference='REP-2026-777',
            analyst=claimer,
            alert_description='User reported ransomware note across two shared drives',
            claimed_by=claimer, claimed_at=timezone.now(),
        )

    def test_manual_triage_get_prefills(self):
        triage = self._claimed_triage(self.t1)
        self.client.login(username='pi_t1', password='testpass123')
        resp = self.client.get(
            reverse('create_project_incident'), {'triage_id': triage.pk},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'ransomware note across two shared drives')
        self.assertContains(resp, f'name="triage_id" value="{triage.pk}"')

    def test_manual_triage_get_rejects_record_of_other_user(self):
        triage = self._claimed_triage(self.t2)  # claimed by someone else
        self.client.login(username='pi_t1', password='testpass123')
        resp = self.client.get(
            reverse('create_project_incident'), {'triage_id': triage.pk},
        )
        self.assertEqual(resp.status_code, 302)  # bounced to manual triage list

    def test_manual_triage_fanout_links_bundle_and_consumes_record(self):
        triage = self._claimed_triage(self.t1)
        self.client.login(username='pi_t1', password='testpass123')
        data = _pi_post_data(self.admin_a, self.admin_b, triage_id=str(triage.pk))
        resp = self.client.post(reverse('create_project_incident'), data)
        self.assertEqual(resp.status_code, 302)

        project = ProjectIncident.objects.get()
        triage.refresh_from_db()
        # Record points at the whole bundle, not a single ticket (option B).
        self.assertEqual(triage.project_incident, project)
        self.assertIsNone(triage.ticket_id)
        # Marked TP + unclaimed → leaves the manual triage queue.
        self.assertEqual(triage.decision, TriageRecord.DECISION_TP)
        self.assertIsNone(triage.claimed_by)
        self.assertEqual(project.source_triages.first(), triage)
