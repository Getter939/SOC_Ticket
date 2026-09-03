"""Explicit verified-session fixtures for business/authorization tests.

Only Django's test-client login helpers simulate MFA here. Real HTTP login
requests always exercise the production flow. MFA tests use Django's plain
TestCase and Client; no runtime enforcement setting is disabled for tests.
"""

import base64

from django.test import Client, TestCase, override_settings
from django_otp import DEVICE_ID_SESSION_KEY

from .mfa_crypto import encrypt
from .models import AuthenticatorDevice

TEST_MFA_KEY = base64.urlsafe_b64encode(b'0' * 32).decode('ascii')


class MFAClient(Client):
    def _login(self, user, backend=None):
        super()._login(user, backend)
        device, _ = AuthenticatorDevice.objects.get_or_create(
            user=user,
            defaults={
                'name': 'Test authenticator',
                'confirmed': True,
                'encrypted_secret': encrypt(
                    base64.b32encode(b'test-device-key-12345').decode('ascii')
                ),
                'recovery_codes_confirmed': True,
            },
        )
        session = self.session
        session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        session.save()


@override_settings(MFA_ENCRYPTION_KEYS=[TEST_MFA_KEY])
class MFATestCase(TestCase):
    client_class = MFAClient
