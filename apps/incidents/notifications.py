"""
Email notifications for the SOC ticketing workflow.

Rules
─────
• This module is intentionally decoupled from Ticket.transition_to so that
  the model stays pure (no email side-effects, no dependency on Django mail
  or URL reversing), and the existing tests never send real mail.
• Every public function here returns a bool: True = sent, False = skipped or
  failed.  They never raise — SMTP errors are caught, logged, and surfaced
  to callers so they can show a warning without rolling back any DB state.
"""

import logging

from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse

logger = logging.getLogger(__name__)


def notify_containment_required(ticket, reason=None):
    """
    Email the assigned admin that a ticket needs containment action.

    Parameters
    ──────────
    ticket  — a Ticket instance whose status is AWAITING_CONTAINMENT.
    reason  — optional str; when provided (rejection loop), included in the
              body so the admin knows what to fix.  When None (initial
              routing), the email is a plain dispatch notice.

    Returns True if the email was sent, False if skipped or if SMTP failed.
    Never raises.

    Subject examples
    ────────────────
    [SOC-0001] Containment required
    [SOC-0001] Containment resubmission required
    """
    admin = ticket.assigned_admin
    if not admin or not admin.email:
        logger.warning(
            'notify_containment_required: ticket %s — no assigned admin or '
            'admin has no email address; notification skipped.',
            ticket.ticket_id,
        )
        return False

    if reason:
        subject = f'[{ticket.ticket_id}] Containment resubmission required'
    else:
        subject = f'[{ticket.ticket_id}] Containment required'

    # Build an absolute URL to the ticket so the admin can click straight in.
    site_url = getattr(settings, 'SITE_URL', 'http://localhost:8000').rstrip('/')
    try:
        ticket_path = reverse('ticket_detail', kwargs={'pk': ticket.pk})
    except Exception:
        ticket_path = f'/incidents/ticket/{ticket.pk}/'
    ticket_url = f'{site_url}{ticket_path}'

    # ── Body ─────────────────────────────────────────────────────────────── #
    # Keep incident details out of the email body — the recipient is directed
    # to the portal.  Include only what they need to identify the ticket and
    # understand the urgency.
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
            'Please review the analyst\'s feedback, then log in and submit an',
            'updated containment report.',
            '',
        ]
    else:
        lines += [
            'Please log in and submit your containment report as soon as possible.',
            '',
        ]

    lines += [
        'View the ticket here (login required):',
        f'  {ticket_url}',
        '',
        'Do not reply to this email.',
    ]

    body = '\n'.join(lines)

    try:
        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin.email],
            fail_silently=False,
        )
        logger.info(
            'notify_containment_required: sent to %s for ticket %s.',
            admin.email,
            ticket.ticket_id,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error(
            'notify_containment_required: SMTP failure for ticket %s — %s',
            ticket.ticket_id,
            exc,
        )
        return False
