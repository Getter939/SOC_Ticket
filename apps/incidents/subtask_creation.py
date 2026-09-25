"""Write-side creation operations for response-team requests."""

from dataclasses import dataclass

from django.core.exceptions import ValidationError
from django.db import transaction

from apps.accounts.models import UserProfile

from .models import TicketSubtask
from .notifications import notify_response_request_created


@dataclass(frozen=True)
class SubtaskCreationResult:
    """The non-HTTP result of creating one or more TicketSubtasks."""

    subtasks: tuple[TicketSubtask, ...]
    notifications_sent: tuple[bool | None, ...]

    @property
    def subtask(self):
        """First created request, retained for callers of the single-request API."""
        return self.subtasks[0]

    @property
    def notification_sent(self):
        """Whether all request notifications were sent."""
        return all(self.notifications_sent)


def create_response_request(*, ticket, actor, response_form):
    """Create a separate request for every selected response-team function."""
    cleaned = response_form.cleaned_data
    subtask_types = cleaned.get('selected_subtask_types') or cleaned.get('subtask_types')
    if not subtask_types:
        # Compatibility with callers that still provide the former single-type
        # form shape.
        subtask_type = cleaned.get('subtask_type') or getattr(response_form, 'subtask_type', None)
        subtask_types = [subtask_type] if subtask_type else []
    if not subtask_types:
        raise ValidationError('กรุณาเลือกอย่างน้อยหนึ่งประเภทงาน')
    subtask_types = list(dict.fromkeys(subtask_types))

    selected_assignees = cleaned.get('selected_assignees') or {}
    # Compatibility with the former single-recipient field.
    legacy_assignee = cleaned.get('assigned_to')
    assignments = {}
    for subtask_type in subtask_types:
        eligible = TicketSubtask.eligible_assignees(subtask_type)
        chosen_for_type = selected_assignees.get(subtask_type)
        if (
            chosen_for_type is None
            and legacy_assignee is not None
            and eligible.filter(pk=legacy_assignee.pk).exists()
        ):
            chosen_for_type = legacy_assignee
        assignments[subtask_type] = resolve_response_assignee(
            subtask_type=subtask_type,
            chosen=chosen_for_type,
        )

    title = cleaned.get('title', getattr(response_form, 'title', ''))
    description = cleaned.get('description', getattr(response_form, 'description', ''))
    subtasks = []
    with transaction.atomic():
        for subtask_type in subtask_types:
            subtask = TicketSubtask.objects.create(
                ticket=ticket,
                created_by=actor,
                assigned_to=assignments[subtask_type],
                subtask_type=subtask_type,
                title=title,
                description=description,
            )
            subtasks.append(subtask)
    notifications_sent = tuple(
        notify_response_request_created(subtask)
        for subtask in subtasks
    )
    return SubtaskCreationResult(
        subtasks=tuple(subtasks),
        notifications_sent=notifications_sent,
    )


def resolve_response_assignee(*, subtask_type, chosen=None):
    """Return the sole/selected active role-holder, or raise the UI message."""
    eligible = TicketSubtask.eligible_assignees(subtask_type)
    role_label = dict(UserProfile.ROLE_CHOICES).get(
        TicketSubtask.role_for_type(subtask_type),
        '',
    )
    type_label = dict(TicketSubtask.TYPE_CHOICES).get(subtask_type, subtask_type)
    if not eligible.exists():
        raise ValidationError(
            f'ยังไม่มีบัญชีผู้ใช้ในบทบาท "{role_label}" ที่รับผิดชอบ '
            f'"{type_label}" — ไม่สามารถมอบหมายคำขอนี้ได้'
        )
    if chosen is not None:
        if not eligible.filter(pk=chosen.pk).exists():
            raise ValidationError(
                f'ผู้รับผิดชอบที่เลือกไม่ได้อยู่ในบทบาท "{role_label}" '
                f'ที่รับผิดชอบ "{type_label}"'
            )
        return chosen
    if eligible.count() == 1:
        return eligible.first()
    raise ValidationError(
        f'มีผู้รับผิดชอบในบทบาท "{role_label}" มากกว่าหนึ่งคน — กรุณาเลือกผู้รับผิดชอบ'
    )
