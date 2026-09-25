"""Password-reset delivery and abuse controls.

This module deliberately stores only HMAC digests for throttle identities. A
database leak cannot be used to recover the email addresses or IP addresses
that requested a reset.
"""

import hashlib
import hmac
import logging
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.db import transaction
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from . import mfa
from .models import PasswordResetRateLimit


logger = logging.getLogger(__name__)


def _identity_digest(kind, value):
    """Return a keyed, non-reversible digest suitable for rate-limit keys."""
    message = f'{kind}:{value}'.encode('utf-8')
    return hmac.new(
        settings.SECRET_KEY.encode('utf-8'), message, hashlib.sha256
    ).hexdigest()


def _client_ip(request):
    """Use proxy-provided client IP only when that proxy is explicitly trusted.

    The RIGHTMOST X-Forwarded-For entry is the one the trusted proxy wrote.
    Proxies that append (IIS ARR does) leave whatever the client sent in front
    of it, so the leftmost entry is attacker-chosen and would let a requester
    reset the per-IP limit on every request by inventing a new address.
    """
    if getattr(settings, 'TRUST_X_FORWARDED_FOR', False):
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
        hops = [hop.strip() for hop in forwarded_for.split(',') if hop.strip()]
        if hops:
            return hops[-1]
    return request.META.get('REMOTE_ADDR', '')


def _consume_rate_limit(key_type, key_hash, limit):
    """Atomically consume one request from the identity's rolling window."""
    now = timezone.now()
    window = timedelta(seconds=settings.PASSWORD_RESET_RATE_WINDOW_SECONDS)

    with transaction.atomic():
        record, created = PasswordResetRateLimit.objects.select_for_update().get_or_create(
            key_type=key_type,
            key_hash=key_hash,
            defaults={'window_started_at': now, 'request_count': 1},
        )
        if created:
            return True

        if now - record.window_started_at >= window:
            record.window_started_at = now
            record.request_count = 1
            record.save(update_fields=('window_started_at', 'request_count'))
            return True

        if record.request_count >= limit:
            return False

        record.request_count += 1
        record.save(update_fields=('request_count',))
        return True


def password_reset_request_allowed(request, email):
    """Apply email and IP limits without retaining raw identifiers."""
    normalized_email = email.strip().casefold()
    email_allowed = _consume_rate_limit(
        PasswordResetRateLimit.KEY_EMAIL,
        _identity_digest('email', normalized_email),
        settings.PASSWORD_RESET_RATE_LIMIT_PER_EMAIL,
    )
    ip_allowed = _consume_rate_limit(
        PasswordResetRateLimit.KEY_IP,
        _identity_digest('ip', _client_ip(request)),
        settings.PASSWORD_RESET_RATE_LIMIT_PER_IP,
    )
    return email_allowed and ip_allowed


def _send_password_link_email(*, user, request, subject_template, body_template):
    """Email a one-time, time-limited set-password link without exposing a password."""
    site = get_current_site(request)
    context = {
        'email': user.email,
        'domain': site.domain,
        'site_name': site.name,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'user': user,
        'token': default_token_generator.make_token(user),
        'protocol': 'https' if (
            settings.PASSWORD_RESET_USE_HTTPS or request.is_secure()
        ) else 'http',
        'mfa_enabled': mfa.enforcement_enabled(),
    }
    subject = ''.join(render_to_string(subject_template, context).splitlines())
    body = render_to_string(body_template, context)
    message = EmailMultiAlternatives(
        subject=subject,
        body=body,
        from_email=settings.DEFAULT_FROM_EMAIL or None,
        to=[user.email],
    )
    message.send()


def send_password_reset_email(*, user, request):
    """Send a reset link to an existing user."""
    _send_password_link_email(
        user=user,
        request=request,
        subject_template='registration/password_reset_subject.txt',
        body_template='registration/password_reset_email.txt',
    )


def send_new_user_email(*, user, request):
    """Welcome a newly created user with their username and a first-password link."""
    _send_password_link_email(
        user=user,
        request=request,
        subject_template='registration/new_user_subject.txt',
        body_template='registration/new_user_email.txt',
    )


def send_password_changed_notification(*, user):
    """Notify the account owner after any successful password change."""
    if not user.email:
        return

    body = render_to_string('registration/password_changed_email.txt', {'user': user})
    message = EmailMultiAlternatives(
        subject='รหัสผ่าน SOC Support System ถูกเปลี่ยนแล้ว',
        body=body,
        from_email=settings.DEFAULT_FROM_EMAIL or None,
        to=[user.email],
    )
    try:
        message.send()
    except Exception:
        # A mail outage must not undo a completed password change. The event is
        # logged without exception details, which may include an email address.
        logger.error('Unable to send password-changed notification')
