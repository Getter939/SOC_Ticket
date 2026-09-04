from django.conf import settings
from django.core.checks import Error, register
from django.core.exceptions import ImproperlyConfigured

from .mfa_crypto import cipher


@register()
def mfa_configuration(app_configs, **kwargs):
    # No encryption keys are needed while the feature is switched off.
    if not getattr(settings, 'MFA_ENABLED', True):
        return []
    try:
        cipher()
    except ImproperlyConfigured:
        return [
            Error(
                'MFA_ENCRYPTION_KEYS must contain valid Fernet keys.',
                hint='Generate a separate key and configure it before migration/startup; see docs/operations/two-factor-authentication.md.',
                id='accounts.E001',
            )
        ]
    return []
