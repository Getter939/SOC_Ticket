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

    subject = (
        f'[{ticket.ticket_id}] Containment resubmission required'
        if reason else
        f'[{ticket.ticket_id}] Containment required'
    )

    ticket_url = _ticket_url(ticket)
    summary = ticket.issue_description[:100]
    if len(ticket.issue_description) > 100:
        summary += '…'

    lines = [
        f'Ticket {ticket.ticket_id} has been routed to you for containment action.',
        '',
        f'  Ticket ID : {ticket.ticket_id}',
        f'  Category  : {ticket.get_category_display()} / {ticket.get_issue_type_display()}',
        f'  Summary   : {summary}',
        '',
    ]

    if reason:
        lines += [
            'The SOC analyst has returned this ticket for re-containment.',
            f'  Analyst note: {reason}',
            '',
            'Please review the feedback, then log in and submit an updated containment report.',
            '',
        ]
    else:
        lines += ['Please log in and submit your containment report as soon as possible.', '']

    lines += ['View the ticket here (login required):', f'  {ticket_url}', '', 'Do not reply to this email.']

    return _send(subject, '\n'.join(lines), admin.email, ticket.ticket_id)


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
    subject = f'[{ticket.ticket_id}] แจ้งเหตุความปลอดภัยบนระบบของท่าน'

    summary = ticket.issue_description[:150]
    if len(ticket.issue_description) > 150:
        summary += '...'

    lines = [
        f'เรียน {owner_name}{f" ({dept})" if dept else ""},',
        '',
        f'ทีม SOC ของ NT ตรวจพบเหตุการณ์ความปลอดภัยที่เกี่ยวข้องกับระบบของท่าน',
        'และได้เปิด Ticket เพื่อดำเนินการแก้ไขแล้ว',
        '',
        f'  Ticket ID      : {ticket.ticket_id}',
        f'  ประเภทเหตุการณ์ : {ticket.get_category_display()} / {ticket.get_issue_type_display()}',
        f'  IP Source       : {ticket.device_name}',
        f'  สรุปเหตุการณ์   : {summary}',
        '',
        'ทีม SOC กำลังดำเนินการควบคุมและแก้ไขเหตุการณ์ดังกล่าว',
        'ท่านไม่จำเป็นต้องดำเนินการใดๆ — ทีม SOC จะแจ้งผลให้ทราบเมื่อเสร็จสิ้น',
        '',
        'หากมีข้อสงสัยกรุณาติดต่อทีม SOC โดยอ้างอิง Ticket ID ข้างต้น',
    ]

    return _send(subject, '\n'.join(lines), owner.email, ticket.ticket_id, attachments)


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

    subject = f'[{ticket.ticket_id}] แจ้งผลการแก้ไขเหตุการณ์ความปลอดภัย'

    if is_fp:
        outcome_lines = [
            'ผลการตรวจสอบ: เหตุการณ์ดังกล่าวได้รับการวินิจฉัยว่าเป็น False Positive',
            '(ไม่ใช่ภัยคุกคามจริง) และปิดเคสเรียบร้อยแล้ว',
        ]
    else:
        closed_by = ''
        if ticket.approved_by:
            closed_by = ticket.approved_by.get_full_name() or ticket.approved_by.username
        closed_at = ticket.approved_at.strftime('%d/%m/%Y %H:%M') if ticket.approved_at else '-'
        outcome_lines = [
            'เหตุการณ์ดังกล่าวได้รับการควบคุม ตรวจสอบ และอนุมัติปิดเคสเรียบร้อยแล้ว',
            f'  ผู้อนุมัติ : {closed_by}',
            f'  ปิดเมื่อ   : {closed_at}',
        ]

    lines = [
        f'เรียน {owner_name}{f" ({dept})" if dept else ""},',
        '',
        f'Ticket ความปลอดภัย [{ticket.ticket_id}] ที่แจ้งเกี่ยวกับระบบของท่านได้รับการปิดแล้ว',
        '',
        f'  Ticket ID      : {ticket.ticket_id}',
        f'  ประเภทเหตุการณ์ : {ticket.get_category_display()} / {ticket.get_issue_type_display()}',
        f'  IP Source       : {ticket.device_name}',
        '',
    ] + outcome_lines + [
        '',
        'บันทึกเหตุการณ์ฉบับสมบูรณ์ถูกเก็บรักษาไว้ในระบบ SOC',
        'หากมีข้อสงสัยกรุณาติดต่อทีม SOC โดยอ้างอิง Ticket ID ข้างต้น',
    ]

    return _send(subject, '\n'.join(lines), owner.email, ticket.ticket_id, attachments)
