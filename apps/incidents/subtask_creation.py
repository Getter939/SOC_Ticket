"""Write-side creation operations for legacy subtasks and response requests."""

from dataclasses import dataclass

from django.core.exceptions import ValidationError
from django.db import transaction

from apps.accounts.models import UserProfile

from .models import Ticket, TicketSubtask
from .notifications import notify_response_request_created


@dataclass(frozen=True)
class SubtaskCreationResult:
    """The non-HTTP result of creating a TicketSubtask."""

    subtask: TicketSubtask
    notification_sent: bool | None = None


def create_legacy_subtask(*, ticket, actor, subtask_form):
    """Persist a validated unassigned Investigation or Countermeasure note."""
    with transaction.atomic():
        subtask = subtask_form.save(commit=False)
        subtask.ticket = ticket
        subtask.created_by = actor
        subtask.save()
    return SubtaskCreationResult(subtask=subtask)


def create_response_request(*, ticket, actor, response_form):
    """Resolve a response-team assignee and create the routed request."""
    subtask_type = response_form.cleaned_data['subtask_type']
    assignee = resolve_response_assignee(
        subtask_type=subtask_type,
        chosen=response_form.cleaned_data.get('assigned_to'),
    )
    with transaction.atomic():
        subtask = response_form.save(commit=False)
        subtask.ticket = ticket
        subtask.created_by = actor
        subtask.assigned_to = assignee
        subtask.save()
    return SubtaskCreationResult(
        subtask=subtask,
        notification_sent=notify_response_request_created(subtask),
    )


def resolve_response_assignee(*, subtask_type, chosen=None):
    """Return the sole/selected active role-holder, or raise the UI message."""
    eligible = TicketSubtask.eligible_assignees(subtask_type)
    role_label = dict(UserProfile.ROLE_CHOICES).get(
        TicketSubtask.role_for_type(subtask_type),
        '',
    )
    if not eligible.exists():
        raise ValidationError(
            f'ยังไม่มีบัญชีผู้ใช้ในบทบาท "{role_label}" — ไม่สามารถมอบหมายคำขอนี้ได้'
        )
    if chosen is not None:
        if not eligible.filter(pk=chosen.pk).exists():
            raise ValidationError(
                f'ผู้รับผิดชอบที่เลือกไม่ได้อยู่ในบทบาท "{role_label}"'
            )
        return chosen
    if eligible.count() == 1:
        return eligible.first()
    raise ValidationError(
        f'มีผู้รับผิดชอบในบทบาท "{role_label}" มากกว่าหนึ่งคน — กรุณาเลือกผู้รับผิดชอบ'
    )
