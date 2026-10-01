"""Operator email for reporting-mart problems.

A missed night of mart snapshots or detection capture cannot be recaptured, so
both ``refresh_reporting`` and its watchdog ``check_reporting_freshness`` email
``settings.REPORTING_ALERT_EMAILS`` when something is wrong. An empty list
means "log only".
"""
import logging
import socket

from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


def send_reporting_alert(subject, problems):
    """Email ``problems`` (a list of strings). Never raises: a failed send is
    logged, so it can't hide the problems it was reporting. Returns True if a
    message was handed to the mail backend."""
    recipients = list(getattr(settings, 'REPORTING_ALERT_EMAILS', []) or [])
    if not recipients:
        logger.warning('Reporting alert not emailed (REPORTING_ALERT_EMAILS empty): %s - %s',
                       subject, '; '.join(problems))
        return False
    body = '\n'.join([
        f'Host: {socket.gethostname()}',
        '',
        *[f'- {p}' for p in problems],
        '',
        'Mart snapshots and detection capture for a missed night cannot be '
        'recaptured. See docs/operations/reporting-layer-operations.md.',
    ])
    try:
        send_mail(f'[SOC reporting] {subject}', body,
                  settings.DEFAULT_FROM_EMAIL or None, recipients)
        return True
    except Exception:   # noqa: BLE001 — the alert must never mask the original error
        logger.exception('Could not email reporting alert: %s', subject)
        return False
