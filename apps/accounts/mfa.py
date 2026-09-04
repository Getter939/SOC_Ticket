"""MFA lifecycle and session policy shared by views and recovery tooling."""

import base64
import hashlib
import json
import logging
import secrets
import time
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.debug import sensitive_variables
from django_otp import login as otp_login

from .mfa_crypto import encrypt, decrypt
from .models import AuthenticatorDevice, MFAAudit, MFARecoveryCode

logger = logging.getLogger(__name__)
PASSWORD_AT = 'mfa_password_at'
NEXT_URL = 'mfa_next'
SETUP_ID = 'mfa_setup_id'
CODE_BUNDLE = 'mfa_code_bundle'
FLOW_SECONDS = 600


def enforcement_enabled():
    """Whether the 2FA requirement is switched on (settings.MFA_ENABLED).

    The single source of truth read by the middleware, the login view and the
    startup check so the feature flips as one unit.
    """
    return getattr(settings, 'MFA_ENABLED', True)


def password_is_fresh(request):
    value = request.session.get(PASSWORD_AT)
    return isinstance(value, (int, float)) and 0 <= time.time() - value < FLOW_SECONDS


def is_verified(request):
    device = getattr(request.user, 'otp_device', None)
    return isinstance(device, AuthenticatorDevice) and device.confirmed


def safe_destination(request, value):
    if value and url_has_allowed_host_and_scheme(
        value,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        # Only local path destinations; avoid returning to an authentication loop.
        if (
            value.startswith('/')
            and not value.startswith('//')
            and not value.startswith(
                (
                    '/login',
                    '/logout',
                    '/password-reset',
                    '/accounts/2fa/',
                    '/admin/login',
                )
            )
        ):
            return value
    return reverse('home')


def audit(user, event, *, actor=None, reason=''):
    MFAAudit.objects.create(
        user=user, username=user.get_username(), actor=actor or user, event=event, reason=reason
    )


def notify(user, message):
    """Deliver after commit; never log SMTP exceptions or credential material."""
    if not user.email:
        return

    def deliver():
        try:
            send_mail(
                'SOC Support System: account security',
                message,
                settings.DEFAULT_FROM_EMAIL or None,
                [user.email],
            )
        except Exception:
            logger.error('Unable to send MFA security notification')

    transaction.on_commit(deliver)


@transaction.atomic
@sensitive_variables()
def begin_setup(request):
    get_user_model().objects.select_for_update().get(pk=request.user.pk)
    device, _ = AuthenticatorDevice.objects.get_or_create(
        user=request.user,
        defaults={'name': 'Authenticator app'},
    )
    if device.confirmed:
        return device
    if str(device.setup_id) != request.session.get(SETUP_ID) or not device.encrypted_secret:
        device.setup_id = uuid.uuid4()
        device.encrypted_secret = encrypt(base64.b32encode(secrets.token_bytes(20)).decode('ascii'))
        device.last_t = -1
        # Preserve failed-attempt counts even when another login restarts setup.
        device.save()
        request.session[SETUP_ID] = str(device.setup_id)
    return device


@sensitive_variables()
def generate_recovery_codes(request, device):
    """Caller holds the device row lock. Plaintext is displayed, never persisted."""
    codes = [secrets.token_hex(16) for _ in range(10)]
    device.recovery_codes.all().delete()
    MFARecoveryCode.objects.bulk_create(
        [
            MFARecoveryCode(device=device, digest=hashlib.sha256(code.encode('ascii')).hexdigest())
            for code in codes
        ]
    )
    device.recovery_codes_confirmed = False
    device.recovery_generation = uuid.uuid4()
    device.save(update_fields=['recovery_codes_confirmed', 'recovery_generation'])
    request.session[CODE_BUNDLE] = encrypt(
        json.dumps(
            {
                'device': device.pk,
                'generation': str(device.recovery_generation),
                'created': time.time(),
                'codes': ['-'.join(code[i : i + 8] for i in range(0, 32, 8)) for code in codes],
            }
        )
    )
    audit(request.user, 'codes_generated')


@sensitive_variables()
def recovery_bundle(request, device):
    from cryptography.fernet import InvalidToken

    try:
        bundle = json.loads(decrypt(request.session.get(CODE_BUNDLE, '')))
        if (
            bundle['device'] == device.pk
            and bundle.get('generation') == str(device.recovery_generation)
            and 0 <= time.time() - bundle['created'] < FLOW_SECONDS
        ):
            return bundle['codes']
    except (InvalidToken, ValueError, KeyError, TypeError):
        pass
    request.session.pop(CODE_BUNDLE, None)
    return None


def mark_verified(request, device):
    request.session.cycle_key()
    otp_login(request, device)
    request.session.pop(PASSWORD_AT, None)
    request.session.pop(SETUP_ID, None)


@transaction.atomic
@sensitive_variables()
def verify(request, token, *, enrollment=False):
    # Serialize enrollment, verification and reset in a consistent lock order.
    get_user_model().objects.select_for_update().get(pk=request.user.pk)
    device = AuthenticatorDevice.objects.select_for_update().filter(user=request.user).first()
    if device is None:
        return None
    if enrollment:
        if device.confirmed or str(device.setup_id) != request.session.get(SETUP_ID):
            return None
    elif not device.confirmed:
        return None
    allowed = device.verify_is_allowed()[0]
    if not device.verify_token(token):
        if allowed:
            audit(request.user, 'failed')
        return None
    if enrollment:
        device.confirmed = True
        device.save(update_fields=['confirmed'])
        audit(request.user, 'enrolled')
        notify(
            request.user,
            'Two-factor authentication was enabled for your SOC account. Contact IT immediately if you did not make this change.',
        )
    else:
        recovery = len(''.join(str(token).split()).replace('-', '')) == 32
        audit(request.user, 'recovery_used' if recovery else 'verified')
        if recovery:
            notify(
                request.user,
                'A recovery code was used to sign in to your SOC account. Contact IT immediately if this was not you.',
            )
    if not device.recovery_codes_confirmed:
        generate_recovery_codes(request, device)
    mark_verified(request, device)
    return device


@transaction.atomic
def reset_authenticator(user, *, actor, reason):
    """Operator-assisted recovery; never grants a verified application session."""
    if not reason.strip():
        raise ValueError('An identity-verification reason is required.')
    get_user_model().objects.select_for_update().get(pk=user.pk)
    AuthenticatorDevice.objects.filter(user=user).delete()
    audit(user, 'reset', actor=actor, reason=reason.strip())
    notify(
        user,
        'Your SOC authenticator was reset. Sign in with your password and enroll a new authenticator. Contact IT immediately if you did not request this change.',
    )


@transaction.atomic
@sensitive_variables()
def replace_recovery_codes(request, token):
    # Keep the same user-then-device lock order as verification/reset. The
    # audit insert also references the user, so locking just the device here
    # could deadlock against a concurrent login holding the user lock.
    get_user_model().objects.select_for_update().get(pk=request.user.pk)
    device = verify(request, token)
    if device is None:
        return False
    if device.recovery_codes_confirmed:
        generate_recovery_codes(request, device)
    notify(
        request.user,
        'New recovery codes were generated for your SOC account. Previous recovery codes no longer work. Contact IT if this was not you.',
    )
    return True
