"""Capture password changes from every User.save() path, including CLI commands."""

from django.contrib.auth.models import User
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .models import PasswordChangeAudit
from .password_audit import get_password_audit_context


@receiver(pre_save, sender=User)
def remember_previous_password(sender, instance, raw=False, **kwargs):
    """Mark the instance only when its persisted password value will change."""
    if raw:
        instance._password_audit_changed = False
        return

    if instance._state.adding:
        instance._password_audit_changed = bool(instance.password)
        return

    previous_password = sender.objects.filter(pk=instance.pk).values_list(
        'password', flat=True,
    ).first()
    instance._password_audit_changed = previous_password != instance.password


@receiver(post_save, sender=User)
def record_password_change(sender, instance, raw=False, **kwargs):
    """Persist only attribution metadata, never plaintext passwords or hashes."""
    if raw or not getattr(instance, '_password_audit_changed', False):
        return

    context = get_password_audit_context() or {}
    actor = context.get('actor')
    PasswordChangeAudit.objects.create(
        user=instance,
        actor=actor if getattr(actor, 'pk', None) else None,
        source=context.get('source', PasswordChangeAudit.SOURCE_SYSTEM),
    )
