"""Email notification robustness: header-safe subjects, admin-edited templates
that cannot break a workflow action, local-time closure stamps, the content of
the containment alert, and the per-email attachment budget."""

import tempfile
from datetime import datetime, timezone as dt_timezone
from unittest.mock import patch

from django.core import mail
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.test import override_settings
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase
from apps.incidents import notifications
from apps.incidents.models import (
    NotificationTemplate, Ticket, TicketAttachment, TicketSubtask,
)
from apps.incidents.tests import (
    _make_redteam_manager, _make_t1, _make_ticket, _make_user,
)
from apps.incidents.ticket_workflow import _owner_closed_warnings

LOCMEM = 'django.core.mail.backends.locmem.EmailBackend'


def _with_email(user, email):
    user.email = email
    user.save(update_fields=['email'])
    return user


@override_settings(EMAIL_BACKEND=LOCMEM)
class ContainmentAlertTest(TestCase):
    def setUp(self):
        self.t1 = _make_t1('notif_t1')
        self.admin = _with_email(
            _make_user('notif_admin', UserProfile.ROLE_SYSTEM_ADMIN), 'admin@example.test',
        )

    def _ticket(self, **kwargs):
        defaults = dict(
            created_by=self.t1, assigned_admin=self.admin, severity='Critical',
            issue_description='first line\nsecond line of a pasted log',
        )
        defaults.update(kwargs)
        return _make_ticket(**defaults)

    def test_sends_when_fields_contain_line_breaks(self):
        """A multi-line description (and a hostile device name) must not make
        Django refuse the header — that silently dropped the admin's email."""
        ticket = self._ticket(device_name='HOST-01\r\nBcc: someone@example.test')
        self.assertTrue(notifications.notify_containment_alert(ticket))
        self.assertEqual(len(mail.outbox), 1)
        subject = mail.outbox[0].subject
        self.assertNotIn('\n', subject)
        self.assertNotIn('\r', subject)
        self.assertEqual(mail.outbox[0].to, ['admin@example.test'])

    def test_email_carries_emergency_deadline_and_guidance(self):
        """Every field the template reads is in its context — they used to be
        missing, so the OLA row claimed "no target" even for Critical."""
        ticket = self._ticket(
            is_emergency=True,
            action_required='Isolate the host from the network',
        )
        self.assertIsNotNone(ticket.ola_contain_deadline)
        notifications.notify_containment_alert(ticket)
        html = mail.outbox[0].alternatives[0][0]
        self.assertIn('เหตุฉุกเฉิน', html)
        self.assertIn('Isolate the host from the network', html)
        self.assertIn(
            timezone.localtime(ticket.ola_contain_deadline).strftime('%d/%m/%Y %H:%M'),
            html,
        )
        self.assertNotIn('ไม่มีเวลาเป้าหมายการควบคุมสำหรับระดับนี้', html)


@override_settings(EMAIL_BACKEND=LOCMEM)
class AdminEditedTemplateTest(TestCase):
    def setUp(self):
        self.manager = _with_email(
            _make_user('notif_mgr', UserProfile.ROLE_SOC_MANAGER), 'mgr@example.test',
        )
        self.ticket = _make_ticket(severity='High')

    def _template(self, **kwargs):
        defaults = dict(
            key=NotificationTemplate.KEY_MANAGER_TRIAGE_PENDING,
            subject='[{ticket_id}] review',
            body='Ticket {ticket_id}',
        )
        defaults.update(kwargs)
        return NotificationTemplate.objects.create(**defaults)

    def test_malformed_template_falls_back_instead_of_raising(self):
        """A stray brace (ValueError) or attribute access (AttributeError) used
        to escape _render and 500 the request after the transition committed."""
        for body in ('Ticket {ticket_id} {', 'Ticket {ticket_id.nope}', 'x } y'):
            NotificationTemplate.objects.all().delete()
            mail.outbox.clear()
            self._template(body=body)
            with self.subTest(body=body):
                self.assertTrue(notifications.notify_manager_triage_pending(self.ticket))
                self.assertIn('pre-containment review', mail.outbox[0].body)

    def test_valid_template_is_used_and_subject_kept_to_one_line(self):
        self._template(subject='[{ticket_id}]\nreview {severity}', body='Custom {ticket_id}')
        notifications.notify_manager_triage_pending(self.ticket)
        self.assertEqual(mail.outbox[0].body, f'Custom {self.ticket.ticket_id}')
        self.assertEqual(mail.outbox[0].subject, f'[{self.ticket.ticket_id}] review High')

    def test_clean_rejects_what_the_sender_could_not_format(self):
        for field, value in (
            ('body', 'Hello {'),
            ('body', 'Hello {not_a_placeholder}'),
            ('subject', 'Hi {ticket_id.upper.x}'),
            ('subject', 'Hi {0}'),
        ):
            template = NotificationTemplate(
                key=NotificationTemplate.KEY_MANAGER_TRIAGE_PENDING,
                subject='ok {ticket_id}', body='ok {ticket_id}',
            )
            setattr(template, field, value)
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValidationError) as ctx:
                    template.full_clean()
                self.assertIn(field, ctx.exception.message_dict)

    def test_clean_accepts_known_placeholders_and_escaped_braces(self):
        template = NotificationTemplate(
            key=NotificationTemplate.KEY_MANAGER_TRIAGE_PENDING,
            subject='[{ticket_id}] {severity}',
            body='{summary} — literal {{braces}} — {ticket_url}',
        )
        template.full_clean()


@override_settings(EMAIL_BACKEND=LOCMEM)
class SystemOwnerClosedTest(TestCase):
    def setUp(self):
        self.owner = _with_email(
            _make_user('notif_owner', UserProfile.ROLE_SYSTEM_OWNER), 'owner@example.test',
        )
        self.approver = _make_user('notif_approver', UserProfile.ROLE_SOC_MANAGER)

    def test_approval_time_is_local_not_utc(self):
        # 2026-09-24 02:30 UTC is 09:30 in Bangkok.
        approved_at = datetime(2026, 9, 24, 2, 30, tzinfo=dt_timezone.utc)
        ticket = _make_ticket(
            system_owner=self.owner, status=Ticket.STATUS_APPROVED,
            approved_by=self.approver, approved_at=approved_at,
        )
        notifications.notify_system_owner_closed(ticket)
        self.assertIn('24/09/2026 09:30', mail.outbox[0].body)

    def test_attachments_beyond_the_budget_are_listed_not_attached(self):
        ticket = _make_ticket(system_owner=self.owner, status=Ticket.STATUS_CLOSED_EVENT)
        small = TicketAttachment(ticket=ticket, original_name='small.txt')
        small.file.save('small.txt', ContentFile(b'a' * 10), save=True)
        big = TicketAttachment(ticket=ticket, original_name='big.log')
        big.file.save('big.log', ContentFile(b'b' * 20), save=True)
        self.addCleanup(small.file.delete, save=False)
        self.addCleanup(big.file.delete, save=False)

        with patch.object(notifications, 'MAX_EMAIL_ATTACHMENT_BYTES', 15):
            self.assertTrue(
                notifications.notify_system_owner_closed(ticket, attachments=[small, big])
            )
        message = mail.outbox[0]
        self.assertEqual([name for name, _content, _type in message.attachments], ['small.txt'])
        self.assertIn('big.log', message.body)


@override_settings(
    EMAIL_BACKEND=LOCMEM,
    MEDIA_ROOT=tempfile.mkdtemp(prefix='soc_notif_media_'),
)
class ClosureEmailEvidenceScopeTest(TestCase):
    """The owner's closure email carries ticket-level evidence only — never a
    response-request deliverable (e.g. a VA/PT result about their system)."""

    def test_deliverables_are_not_attached(self):
        owner = _with_email(
            _make_user('scope_owner', UserProfile.ROLE_SYSTEM_OWNER), 'owner@example.test',
        )
        redteam = _make_redteam_manager('scope_redteam')
        ticket = _make_ticket(system_owner=owner, status=Ticket.STATUS_CLOSED_EVENT)
        request = TicketSubtask.objects.create(
            ticket=ticket, subtask_type=TicketSubtask.TYPE_VA_PT,
            title='VA/PT', assigned_to=redteam,
        )
        TicketAttachment.objects.create(
            ticket=ticket, original_name='evidence.log',
            file=ContentFile(b'ticket evidence', name='evidence.log'),
        )
        TicketAttachment.objects.create(
            ticket=ticket, subtask=request, original_name='vapt-result.pdf',
            file=ContentFile(b'%PDF-1.4 scan', name='vapt-result.pdf'),
        )

        self.assertEqual(_owner_closed_warnings(ticket), ())

        names = [name for name, _content, _type in mail.outbox[0].attachments]
        self.assertEqual(names, ['evidence.log'])
