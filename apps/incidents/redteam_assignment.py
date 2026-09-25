"""Move open legacy Hardening work when its designated manager is configured."""

from django.core.exceptions import ValidationError
from django.db import transaction

from apps.accounts.models import UserProfile

from .models import TicketFieldChange, TicketSubtask
from .notifications import notify_response_request_created


def assign_open_hardening_requests(*, manager, actor):
    """Convert open InfraSec requests and assign all open Hardening work.

    Completed and cancelled requests keep their historical type and owner.
    This is called after an administrator designates the Hardening manager, so
    an in-progress request is never stranded without an eligible assignee.
    """
    profile = getattr(manager, 'profile', None)
    if (
        not manager.is_active or profile is None
        or profile.role != UserProfile.ROLE_REDTEAM_MANAGER
        or profile.redteam_function != UserProfile.REDTEAM_HARDENING
    ):
        raise ValidationError('ต้องกำหนดผู้จัดการ Red Team สำหรับ Hardening ก่อน')

    changed = 0
    notify_ids = []
    with transaction.atomic():
        requests = (
            TicketSubtask.objects.select_for_update()
            .filter(subtask_type__in=(
                TicketSubtask.TYPE_INFRA_SEC,
                TicketSubtask.TYPE_HARDENING,
            ))
            .exclude(status__in=TicketSubtask.TERMINAL_STATUSES)
        )
        for request in requests:
            old_type = request.subtask_type
            old_assignee = request.assigned_to
            if old_type == TicketSubtask.TYPE_HARDENING and request.assigned_to_id == manager.pk:
                continue
            request.subtask_type = TicketSubtask.TYPE_HARDENING
            request.assigned_to = manager
            request.save(update_fields=['subtask_type', 'assigned_to', 'updated_at'])
            if old_type != request.subtask_type:
                TicketFieldChange.objects.create(
                    ticket_id=request.ticket_id,
                    subtask=request,
                    field_name='subtask_type',
                    field_label=f'ประเภทคำขอ — {request.title}'[:120],
                    old_value=old_type,
                    new_value=request.subtask_type,
                    changed_by=actor,
                    source='redteam_assignment',
                )
            if old_assignee is None or old_assignee.pk != manager.pk:
                TicketFieldChange.objects.create(
                    ticket_id=request.ticket_id,
                    subtask=request,
                    field_name='assigned_to',
                    field_label=f'ผู้รับผิดชอบ — {request.title}'[:120],
                    old_value=old_assignee.username if old_assignee else '',
                    new_value=manager.username,
                    changed_by=actor,
                    source='redteam_assignment',
                )
                notify_ids.append(request.pk)
            changed += 1
        if notify_ids:
            def notify_assignee():
                for pk in notify_ids:
                    notify_response_request_created(TicketSubtask.objects.get(pk=pk))

            transaction.on_commit(notify_assignee)
    return changed
