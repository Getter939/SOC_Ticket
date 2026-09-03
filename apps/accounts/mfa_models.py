"""Project-owned encrypted device using django-otp's verification primitives."""

import base64
import hashlib
import re
import time
import uuid
from urllib.parse import quote, urlencode

from django.conf import settings
from django.db import models, transaction
from django.views.decorators.debug import sensitive_variables
from django_otp.models import Device, ThrottlingMixin, TimestampMixin
from django_otp.oath import TOTP

from .mfa_crypto import decrypt


class AuthenticatorDevice(TimestampMixin, ThrottlingMixin, Device):
    confirmed = models.BooleanField(default=False)
    encrypted_secret = models.TextField(editable=False)
    setup_id = models.UUIDField(default=uuid.uuid4, editable=False)
    last_t = models.BigIntegerField(default=-1)
    recovery_codes_confirmed = models.BooleanField(default=False)
    recovery_generation = models.UUIDField(default=uuid.uuid4, editable=False)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['user'], name='one_authenticator_per_user')]

    @property
    def secret(self):
        return decrypt(self.encrypted_secret)

    @property
    def config_url(self):
        issuer = 'SOC Support System'
        label = quote(f'{issuer}:{self.user.get_username()}', safe='')
        return f'otpauth://totp/{label}?' + urlencode(
            {
                'secret': self.secret,
                'issuer': issuer,
                'algorithm': 'SHA1',
                'digits': 6,
                'period': 30,
            }
        )

    def get_throttle_factor(self):
        return 1

    @sensitive_variables()
    def verify_token(self, token):
        # Lock even if called through an API other than our views. The lock
        # serializes OTP replay checks and recovery-code consumption on Postgres.
        with transaction.atomic():
            current = type(self).objects.select_for_update().get(pk=self.pk)
            success = current._verify_locked(token)
            self.refresh_from_db()
            return success

    @sensitive_variables()
    def _verify_locked(self, token):
        if not self.verify_is_allowed()[0]:
            return False
        token = re.sub(r'[\s-]', '', str(token)).lower()
        success = False
        if re.fullmatch(r'[0-9]{6}', token):
            totp = TOTP(base64.b32decode(self.secret), step=30, digits=6)
            totp.time = time.time()
            success = totp.verify(int(token), tolerance=1, min_t=self.last_t + 1)
            if success:
                self.last_t = totp.t()
        elif self.confirmed and re.fullmatch(r'[0-9a-f]{32}', token):
            digest = hashlib.sha256(token.encode('ascii')).hexdigest()
            deleted, _ = self.recovery_codes.filter(digest=digest).delete()
            success = bool(deleted)
        if success:
            self.throttle_reset(commit=False)
            self.set_last_used_timestamp(commit=False)
            self.save()
        else:
            # Cap exponential delay at 512 seconds, preserving an effective
            # account-wide throttle without allowing an indefinite lockout.
            self.throttling_failure_count = min(self.throttling_failure_count, 9)
            self.throttle_increment()
        return success


class MFARecoveryCode(models.Model):
    device = models.ForeignKey(
        AuthenticatorDevice, on_delete=models.CASCADE, related_name='recovery_codes'
    )
    # Codes have 128 random bits; SHA-256 is safe here without a password KDF.
    digest = models.CharField(max_length=64, editable=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['device', 'digest'], name='unique_mfa_recovery_code')
        ]


class MFAAudit(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='mfa_audits'
    )
    username = models.CharField(max_length=150)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='mfa_actions'
    )
    event = models.CharField(
        max_length=32,
        choices=[
            ('enrolled', 'Authenticator enrolled'),
            ('verified', 'Authenticator verified'),
            ('failed', 'Verification failed'),
            ('recovery_used', 'Recovery code used'),
            ('codes_generated', 'Recovery codes generated'),
            ('reset', 'Authenticator reset'),
        ],
    )
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
