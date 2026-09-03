"""Encrypt recoverable MFA material separately from Django's signing key."""

from cryptography.fernet import Fernet, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.debug import sensitive_variables


@sensitive_variables()
def cipher():
    try:
        keys = settings.MFA_ENCRYPTION_KEYS
        if not keys:
            raise ValueError
        return MultiFernet([Fernet(key.encode('ascii')) for key in keys])
    except (ValueError, TypeError, UnicodeError, AttributeError) as exc:
        raise ImproperlyConfigured(
            'Set MFA_ENCRYPTION_KEYS to a separate Fernet key before enabling access.'
        ) from exc


@sensitive_variables()
def encrypt(value):
    return cipher().encrypt(value.encode('utf-8')).decode('ascii')


@sensitive_variables()
def decrypt(value):
    return cipher().decrypt(value.encode('ascii')).decode('utf-8')
