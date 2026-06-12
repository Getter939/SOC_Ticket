"""
Email notifications for the SOC ticketing workflow.

Rules
─────
• Decoupled from model logic — no email side-effects in transition_to.
• Every public function returns bool: True = sent, False = skipped/failed.
• Never raises — SMTP errors are caught, logged, and returned as False.
"""

import logging

from django.conf import settings
from django.core.mail import EmailMessage
from django.urls import reverse

from .models import NotificationTemplate

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────── #
# Internal helper                                                           #
# ──────────────────────────────────────────────────────────────────────── #

def _ticket_url(ticket):
    site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000').rstrip('/')
    try:
        path = reverse('ticket_detail', kwargs={'pk': ticket.pk})
    except Exception:
        path = f'/incidents/ticket/{ticket.pk}/'
    return f'{site_url}{path}'


def _render(key, context, default_subject, default_body):
    """
    Render subject/body for notification ``key`` from the admin-editable
    NotificationTemplate if one exists, otherwise fall back to the given
    defaults. Placeholders are filled with ``str.format(**context)``;
    malformed custom templates fall back to the default rather than erroring.
    """
    template = NotificationTemplate.objects.filter(key=key).first()
    subject, body = default_subject, default_body
    if template:
        try:
            subject = template.subject.format(**context)
            body = template.body.format(**context)
            return subject, body
        except (KeyError, IndexError) as exc:
            logger.warning('Invalid NotificationTemplate %s — falling back to default: %s', key, exc)

    return default_subject.format(**context), default_body.format(**context)


def _send(subject, body, recipient_email, ticket_id, attachments=None):
    """Shared send wrapper with optional file attachments."""
    try:
        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient_email],
        )
        for att in (attachments or []):
            try:
                with att.file.open('rb') as f:
                    email.attach(att.original_name, f.read(), 'application/octet-stream')
            except Exception as att_exc:
                logger.warning('Could not attach %s: %s', att.original_name, att_exc)
        email.send(fail_silently=False)
        logger.info('Email sent to %s for ticket %s.', recipient_email, ticket_id)
        return True
    except Exception as exc:
        logger.error('SMTP failure for ticket %s — %s', ticket_id, exc)
        return False


# ──────────────────────────────────────────────────────────────────────── #
# Security Admin notifications                                             #
# ──────────────────────────────────────────────────────────────────────── #

def notify_containment_required(ticket, reason=None):
    """
    Email the assigned admin that a ticket needs containment action.
    reason — when provided (rejection loop), tells the admin what to fix.
    """
    admin = ticket.assigned_admin
    if not admin or not admin.email:
        logger.warning(
            'notify_containment_required: ticket %s — no assigned admin or no email.',
            ticket.ticket_id,
        )
        return False

    ticket_url = _ticket_url(ticket)
    summary = ticket.issue_description[:100]
    if len(ticket.issue_description) > 100:
        summary += '…'

    if reason:
        default_subject = '[{ticket_id}] Containment resubmission required'
        reason_block = (
            'The SOC analyst has returned this ticket for re-containment.\n'
            f'  Analyst note: {reason}\n'
            '\n'
            'Please review the feedback, then log in and submit an updated containment report.'
        )
    else:
        default_subject = '[{ticket_id}] Containment required'
        reason_block = 'Please log in and submit your containment report as soon as possible.'

    default_body = (
        'Ticket {ticket_id} has been routed to you for containment action.\n'
        '\n'
        '  Ticket ID : {ticket_id}\n'
        '  Category  : {category} / {issue_type}\n'
        '  Summary   : {summary}\n'
        '\n'
        '{reason_block}\n'
        '\n'
        'View the ticket here (login required):\n'
        '  {ticket_url}\n'
        '\n'
        'Do not reply to this email.'
    )

    context = {
        'ticket_id': ticket.ticket_id,
        'ticket_url': ticket_url,
        'category': ticket.get_category_display(),
        'issue_type': ticket.get_issue_type_display(),
        'summary': summary,
        'reason_block': reason_block,
    }

    subject, body = _render(
        NotificationTemplate.KEY_CONTAINMENT_REQUIRED, context, default_subject, default_body,
    )
    return _send(subject, body, admin.email, ticket.ticket_id)


def notify_containment_submitted(ticket):
    """
    Email the SOC analyst (assigned_to) that the assigned admin has
    submitted a containment report and the ticket is ready for review.
    """
    analyst = ticket.assigned_to
    if not analyst or not analyst.email:
        logger.warning(
            'notify_containment_submitted: ticket %s — no assigned analyst or no email.',
            ticket.ticket_id,
        )
        return False

    ticket_url = _ticket_url(ticket)
    summary = ticket.issue_description[:100]
    if len(ticket.issue_description) > 100:
        summary += '…'

    admin = ticket.assigned_admin
    admin_name = (admin.get_full_name() or admin.username) if admin else '-'
    disposition = ticket.get_disposition_display() if ticket.disposition else '-'

    default_subject = '[{ticket_id}] Containment report submitted — review required'
    default_body = (
        'The assigned admin has submitted a containment report for ticket {ticket_id}.\n'
        '\n'
        '  Ticket ID    : {ticket_id}\n'
        '  Category     : {category} / {issue_type}\n'
        '  Summary      : {summary}\n'
        '  Submitted by : {admin_name}\n'
        '  Disposition  : {disposition}\n'
        '\n'
        'Containment report:\n'
        '{containment_report}\n'
        '\n'
        'Please review the result and verify whether the incident has been contained.\n'
        '\n'
        'View the ticket here (login required):\n'
        '  {ticket_url}\n'
        '\n'
        'Do not reply to this email.'
    )

    context = {
        'ticket_id': ticket.ticket_id,
        'ticket_url': ticket_url,
        'category': ticket.get_category_display(),
        'issue_type': ticket.get_issue_type_display(),
        'summary': summary,
        'admin_name': admin_name,
        'disposition': disposition,
        'containment_report': ticket.containment_report,
    }

    subject, body = _render(
        NotificationTemplate.KEY_CONTAINMENT_SUBMITTED, context, default_subject, default_body,
    )
    return _send(subject, body, analyst.email, ticket.ticket_id)


# ──────────────────────────────────────────────────────────────────────── #
# System Owner notifications                                               #
# ──────────────────────────────────────────────────────────────────────── #

def notify_system_owner_created(ticket, attachments=None):
    """
    Stage 5 — Email System Owner when a ticket is first created.
    attachments — optional list of TicketAttachment objects to include.
    """
    if not ticket.system_owner or not ticket.system_owner.email:
        return False

    owner = ticket.system_owner
    owner_name = owner.get_full_name() or owner.username
    dept = getattr(getattr(owner, 'profile', None), 'department', '')

    summary = ticket.issue_description[:150]
    if len(ticket.issue_description) > 150:
        summary += '...'

    default_subject = '[{ticket_id}] แจ้งเหตุความปลอดภัยบนระบบของท่าน'
    default_body = (
        'เรียน {owner_name}{department_suffix},\n'
        '\n'
        'ทีม SOC ของ NT ตรวจพบเหตุการณ์ความปลอดภัยที่เกี่ยวข้องกับระบบของท่าน\n'
        'และได้เปิด Ticket เพื่อดำเนินการแก้ไขแล้ว\n'
        '\n'
        '  Ticket ID      : {ticket_id}\n'
        '  ประเภทเหตุการณ์ : {category} / {issue_type}\n'
        '  IP Source       : {device_name}\n'
        '  สรุปเหตุการณ์   : {summary}\n'
        '\n'
        'ทีม SOC กำลังดำเนินการควบคุมและแก้ไขเหตุการณ์ดังกล่าว\n'
        'ท่านไม่จำเป็นต้องดำเนินการใดๆ — ทีม SOC จะแจ้งผลให้ทราบเมื่อเสร็จสิ้น\n'
        '\n'
        'หากมีข้อสงสัยกรุณาติดต่อทีม SOC โดยอ้างอิง Ticket ID ข้างต้น'
    )

    context = {
        'ticket_id': ticket.ticket_id,
        'ticket_url': _ticket_url(ticket),
        'owner_name': owner_name,
        'department': dept,
        'department_suffix': f' ({dept})' if dept else '',
        'category': ticket.get_category_display(),
        'issue_type': ticket.get_issue_type_display(),
        'device_name': ticket.device_name,
        'summary': summary,
    }

    subject, body = _render(
        NotificationTemplate.KEY_OWNER_CREATED, context, default_subject, default_body,
    )
    return _send(subject, body, owner.email, ticket.ticket_id, attachments)


def notify_system_owner_closed(ticket, attachments=None):
    """
    Stage 11 — Email System Owner when a ticket is APPROVED or CLOSED_FP.
    attachments — optional list of TicketAttachment objects to include.
    """
    if not ticket.system_owner or not ticket.system_owner.email:
        return False

    owner = ticket.system_owner
    owner_name = owner.get_full_name() or owner.username
    dept = getattr(getattr(owner, 'profile', None), 'department', '')
    is_fp = ticket.status == ticket.STATUS_CLOSED_FP

    if is_fp:
        outcome = (
            'ผลการตรวจสอบ: เหตุการณ์ดังกล่าวได้รับการวินิจฉัยว่าเป็น False Positive\n'
            '(ไม่ใช่ภัยคุกคามจริง) และปิดเคสเรียบร้อยแล้ว'
        )
    else:
        closed_by = ''
        if ticket.approved_by:
            closed_by = ticket.approved_by.get_full_name() or ticket.approved_by.username
        closed_at = ticket.approved_at.strftime('%d/%m/%Y %H:%M') if ticket.approved_at else '-'
        outcome = (
            'เหตุการณ์ดังกล่าวได้รับการควบคุม ตรวจสอบ และอนุมัติปิดเคสเรียบร้อยแล้ว\n'
            f'  ผู้อนุมัติ : {closed_by}\n'
            f'  ปิดเมื่อ   : {closed_at}'
        )

    default_subject = '[{ticket_id}] แจ้งผลการแก้ไขเหตุการณ์ความปลอดภัย'
    default_body = (
        'เรียน {owner_name}{department_suffix},\n'
        '\n'
        'Ticket ความปลอดภัย [{ticket_id}] ที่แจ้งเกี่ยวกับระบบของท่านได้รับการปิดแล้ว\n'
        '\n'
        '  Ticket ID      : {ticket_id}\n'
        '  ประเภทเหตุการณ์ : {category} / {issue_type}\n'
        '  IP Source       : {device_name}\n'
        '\n'
        '{outcome}\n'
        '\n'
        'บันทึกเหตุการณ์ฉบับสมบูรณ์ถูกเก็บรักษาไว้ในระบบ SOC\n'
        'หากมีข้อสงสัยกรุณาติดต่อทีม SOC โดยอ้างอิง Ticket ID ข้างต้น'
    )

    context = {
        'ticket_id': ticket.ticket_id,
        'ticket_url': _ticket_url(ticket),
        'owner_name': owner_name,
        'department': dept,
        'department_suffix': f' ({dept})' if dept else '',
        'category': ticket.get_category_display(),
        'issue_type': ticket.get_issue_type_display(),
        'device_name': ticket.device_name,
        'outcome': outcome,
    }

    subject, body = _render(
        NotificationTemplate.KEY_OWNER_CLOSED, context, default_subject, default_body,
    )
    return _send(subject, body, owner.email, ticket.ticket_id, attachments)
