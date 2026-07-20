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
from django.contrib.auth.models import User
from django.core.mail import EmailMessage, send_mail
from django.template.loader import render_to_string
from django.urls import reverse

from .models import NotificationTemplate

logger = logging.getLogger(__name__)

SEVERITY_TH = {
    'Critical': 'วิกฤต',
    'High': 'สูง',
    'Medium': 'ปานกลาง',
    'Low': 'ต่ำ',
}


# ──────────────────────────────────────────────────────────────────────── #
# Internal helper                                                           #
# ──────────────────────────────────────────────────────────────────────── #

def _ticket_url(ticket):
    site_url = getattr(settings, 'SITE_URL', 'http://localhost:8088').rstrip('/')
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
    """Shared send wrapper with optional file attachments.

    ``recipient_email`` may be a single address or a list of addresses.
    """
    recipients = (
        list(recipient_email)
        if isinstance(recipient_email, (list, tuple, set))
        else [recipient_email]
    )
    try:
        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=recipients,
        )
        for att in (attachments or []):
            try:
                with att.file.open('rb') as f:
                    email.attach(att.original_name, f.read(), 'application/octet-stream')
            except Exception as att_exc:
                logger.warning('Could not attach %s: %s', att.original_name, att_exc)
        email.send(fail_silently=False)
        logger.info('Email sent to %s for ticket %s.', ', '.join(recipients), ticket_id)
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
        '  Type      : {issue_type}\n'
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
    Email Tier 2 staff that the assigned admin has submitted a containment
    report and the ticket is awaiting Tier 2 verification. Falls back to the
    assigned analyst if no Tier 2 staff with an email address exists.
    """
    from apps.accounts.models import UserProfile

    recipients = list(
        User.objects.filter(
            is_active=True,
            profile__role=UserProfile.ROLE_SOC_STAFF,
            profile__tier=UserProfile.TIER_T2,
        )
        .exclude(email='')
        .values_list('email', flat=True)
    )
    if not recipients:
        analyst = ticket.assigned_to
        if not analyst or not analyst.email:
            logger.warning(
                'notify_containment_submitted: ticket %s — no Tier 2 staff with '
                'email and no assigned analyst to fall back to.',
                ticket.ticket_id,
            )
            return False
        recipients = [analyst.email]

    ticket_url = _ticket_url(ticket)
    summary = ticket.issue_description[:100]
    if len(ticket.issue_description) > 100:
        summary += '…'

    admin = ticket.assigned_admin
    admin_name = (admin.get_full_name() or admin.username) if admin else '-'
    classification = ticket.get_classification_display() if ticket.classification else '-'

    default_subject = '[{ticket_id}] Containment report submitted — Tier 2 review required'
    default_body = (
        'The assigned admin has submitted a containment report for ticket {ticket_id}.\n'
        '\n'
        '  Ticket ID      : {ticket_id}\n'
        '  Type           : {issue_type}\n'
        '  Summary        : {summary}\n'
        '  Submitted by   : {admin_name}\n'
        '  Classification : {classification}\n'
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
        'issue_type': ticket.get_issue_type_display(),
        'summary': summary,
        'admin_name': admin_name,
        'classification': classification,
        'containment_report': ticket.containment_report,
    }

    subject, body = _render(
        NotificationTemplate.KEY_CONTAINMENT_SUBMITTED, context, default_subject, default_body,
    )
    return _send(subject, body, recipients, ticket.ticket_id)


# ──────────────────────────────────────────────────────────────────────── #
# SOC Manager notifications                                                 #
# ──────────────────────────────────────────────────────────────────────── #

def notify_manager_triage_pending(ticket):
    """
    Email SOC Managers that an Incident is waiting in the pre-containment
    review (PENDING_MGR_TRIAGE) — they must flag Emergency and forward it to
    the lane Tier 1 chose. No fallback: if no manager has an email, skip.
    """
    from apps.accounts.models import UserProfile

    recipients = list(
        User.objects.filter(
            is_active=True,
            profile__role=UserProfile.ROLE_SOC_MANAGER,
        )
        .exclude(email='')
        .values_list('email', flat=True)
    )
    if not recipients:
        logger.warning(
            'notify_manager_triage_pending: ticket %s — no SOC Manager with email.',
            ticket.ticket_id,
        )
        return False

    ticket_url = _ticket_url(ticket)
    summary = ticket.issue_description[:100]
    if len(ticket.issue_description) > 100:
        summary += '…'

    route = ticket.get_t1_route_display() if ticket.t1_route else '-'

    default_subject = '[{ticket_id}] Incident awaiting SOC Manager review'
    default_body = (
        'Tier 1 has classified ticket {ticket_id} as an Incident and routed it '
        'for your pre-containment review.\n'
        '\n'
        '  Ticket ID : {ticket_id}\n'
        '  Type      : {issue_type}\n'
        '  Severity  : {severity}\n'
        '  Summary   : {summary}\n'
        '  Route     : {route}\n'
        '\n'
        'Please review, flag Emergency if warranted, and forward it to the '
        'chosen handling lane.\n'
        '\n'
        'View the ticket here (login required):\n'
        '  {ticket_url}\n'
        '\n'
        'Do not reply to this email.'
    )

    context = {
        'ticket_id': ticket.ticket_id,
        'ticket_url': ticket_url,
        'issue_type': ticket.get_issue_type_display(),
        'severity': ticket.severity or '-',
        'summary': summary,
        'route': route,
    }

    subject, body = _render(
        NotificationTemplate.KEY_MANAGER_TRIAGE_PENDING, context,
        default_subject, default_body,
    )
    return _send(subject, body, recipients, ticket.ticket_id)


# ──────────────────────────────────────────────────────────────────────── #
# Response-team notifications (Forensic / Red Team)                         #
# ──────────────────────────────────────────────────────────────────────── #

def notify_response_request_created(subtask):
    """
    Email the assigned response-team member (Forensic Analyst / Red Team
    Manager) that a new request has been routed to them. No assignee or no
    email → skip.
    """
    responder = subtask.assigned_to
    if not responder or not responder.email:
        logger.warning(
            'notify_response_request_created: subtask %s — no assignee or no email.',
            subtask.pk,
        )
        return False

    ticket = subtask.ticket
    ticket_url = _ticket_url(ticket)
    summary = ticket.issue_description[:100]
    if len(ticket.issue_description) > 100:
        summary += '…'

    requester = subtask.created_by
    requested_by = (requester.get_full_name() or requester.username) if requester else '-'

    default_subject = '[{ticket_id}] คำขอทีมตอบสนองใหม่ — {request_type}'
    default_body = (
        'มีคำขอทีมตอบสนองใหม่ถูกมอบหมายให้ท่านสำหรับ Ticket {ticket_id}.\n'
        '\n'
        '  Ticket ID  : {ticket_id}\n'
        '  ประเภทคำขอ : {request_type}\n'
        '  หัวข้อ      : {title}\n'
        '  สรุปเหตุการณ์: {summary}\n'
        '  ผู้ร้องขอ   : {requested_by}\n'
        '\n'
        'รายละเอียด:\n'
        '{description}\n'
        '\n'
        'เปิดดู Ticket ได้ที่นี่ (ต้องเข้าสู่ระบบ):\n'
        '  {ticket_url}\n'
        '\n'
        'กรุณาอย่าตอบกลับอีเมลนี้'
    )

    context = {
        'ticket_id': ticket.ticket_id,
        'ticket_url': ticket_url,
        'request_type': subtask.get_subtask_type_display(),
        'title': subtask.title,
        'description': subtask.description or '-',
        'summary': summary,
        'requested_by': requested_by,
    }

    subject, body = _render(
        NotificationTemplate.KEY_RESPONSE_REQUEST_CREATED, context,
        default_subject, default_body,
    )
    return _send(subject, body, responder.email, ticket.ticket_id)


def notify_response_request_completed(subtask):
    """
    Email SOC Managers that a response-team request has been marked DONE, so
    they can review the result and proceed to approval. No manager with an
    email → skip.
    """
    from apps.accounts.models import UserProfile

    recipients = list(
        User.objects.filter(
            is_active=True,
            profile__role=UserProfile.ROLE_SOC_MANAGER,
        )
        .exclude(email='')
        .values_list('email', flat=True)
    )
    if not recipients:
        logger.warning(
            'notify_response_request_completed: subtask %s — no SOC Manager with email.',
            subtask.pk,
        )
        return False

    ticket = subtask.ticket
    ticket_url = _ticket_url(ticket)

    responder = subtask.assigned_to
    completed_by = (responder.get_full_name() or responder.username) if responder else '-'

    default_subject = '[{ticket_id}] คำขอทีมตอบสนองเสร็จสิ้น — {request_type}'
    default_body = (
        'คำขอทีมตอบสนองสำหรับ Ticket {ticket_id} ได้ดำเนินการเสร็จสิ้นแล้ว.\n'
        '\n'
        '  Ticket ID  : {ticket_id}\n'
        '  ประเภทคำขอ : {request_type}\n'
        '  หัวข้อ      : {title}\n'
        '  ผู้ดำเนินการ: {completed_by}\n'
        '\n'
        'ผลการดำเนินการ:\n'
        '{result_notes}\n'
        '\n'
        'เปิดดู Ticket ได้ที่นี่ (ต้องเข้าสู่ระบบ):\n'
        '  {ticket_url}\n'
        '\n'
        'กรุณาอย่าตอบกลับอีเมลนี้'
    )

    context = {
        'ticket_id': ticket.ticket_id,
        'ticket_url': ticket_url,
        'request_type': subtask.get_subtask_type_display(),
        'title': subtask.title,
        'result_notes': subtask.result_notes or '-',
        'completed_by': completed_by,
    }

    subject, body = _render(
        NotificationTemplate.KEY_RESPONSE_REQUEST_COMPLETED, context,
        default_subject, default_body,
    )
    return _send(subject, body, recipients, ticket.ticket_id)


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
        '  ประเภทเหตุการณ์ : {issue_type}\n'
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
    Email the System Owner when a ticket is APPROVED or CLOSED_EVENT.
    attachments — optional list of TicketAttachment objects to include.
    """
    if not ticket.system_owner or not ticket.system_owner.email:
        return False

    owner = ticket.system_owner
    owner_name = owner.get_full_name() or owner.username
    dept = getattr(getattr(owner, 'profile', None), 'department', '')
    is_event = ticket.status == ticket.STATUS_CLOSED_EVENT

    if is_event:
        outcome = (
            'ผลการตรวจสอบ: เหตุการณ์ดังกล่าวได้รับการวินิจฉัยว่าเป็น Event\n'
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
        '  ประเภทเหตุการณ์ : {issue_type}\n'
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
        'issue_type': ticket.get_issue_type_display(),
        'device_name': ticket.device_name,
        'outcome': outcome,
    }

    subject, body = _render(
        NotificationTemplate.KEY_OWNER_CLOSED, context, default_subject, default_body,
    )
    return _send(subject, body, owner.email, ticket.ticket_id, attachments)


# ──────────────────────────────────────────────────────────────────────── #
# Containment alert (HTML, Thai)                                            #
# ──────────────────────────────────────────────────────────────────────── #

def notify_containment_alert(ticket, reason=None):
    """
    Email the assigned admin an HTML containment alert (Thai body) with
    ticket details and a link to submit the containment report.
    """
    admin = ticket.assigned_admin
    if not admin or not admin.email:
        logger.warning(
            'notify_containment_alert: ticket %s — no assigned admin or no email.',
            ticket.ticket_id,
        )
        return False

    ticket_url = _ticket_url(ticket)

    if ticket.issue_type == 'SIEM':
        routed_by = 'ระบบ SIEM อัตโนมัติ'
    else:
        routed_by = ticket.created_by.get_full_name() or ticket.created_by.username

    assigned_to = ''
    if ticket.assigned_to:
        assigned_to = ticket.assigned_to.get_full_name() or ticket.assigned_to.username

    context = {
        'ticket': {
            'id': ticket.ticket_id,
            'ticket_id': ticket.ticket_id,
            'summary': ticket.issue_description,
            'severity': SEVERITY_TH.get(ticket.severity, ticket.severity),
            'assigned_to': assigned_to,
            'created_at': ticket.created_at,
            'routed_by': routed_by,
            'device_name': ticket.device_name,
        },
        'severity_th': SEVERITY_TH.get(ticket.severity, ticket.severity),
        'ticket_url': ticket_url,
        'reason': reason,
    }

    subject = f'[{ticket.ticket_id}] ต้องดำเนินการกักกัน – {ticket.issue_description[:60]}'
    html_message = render_to_string('tickets/email/containment_alert.html', context)

    try:
        send_mail(
            subject=subject,
            message='',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin.email],
            html_message=html_message,
            fail_silently=False,
        )
        logger.info('Containment alert email sent to %s for ticket %s.', admin.email, ticket.ticket_id)
        return True
    except Exception as exc:
        logger.error('SMTP failure for containment alert, ticket %s — %s', ticket.ticket_id, exc)
        return False
