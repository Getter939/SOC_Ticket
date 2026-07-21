"""Request-scoped context for password-change audit events."""

from contextlib import contextmanager
from contextvars import ContextVar


_password_audit_context = ContextVar('password_audit_context', default=None)


@contextmanager
def password_audit_context(*, source, actor=None):
    """Attribute a password save to its trusted request source and actor."""
    token = _password_audit_context.set({'source': source, 'actor': actor})
    try:
        yield
    finally:
        _password_audit_context.reset(token)


def get_password_audit_context():
    return _password_audit_context.get()
