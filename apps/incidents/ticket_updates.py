"""Write-side Ticket editing and subtask update operations.

Views retain request validation, authorization, and messages. This module owns
the coordinated persistence of content edits, subtask history, deliverables,
and response-request completion notifications.
"""

from dataclasses import dataclass, field

from django.db import transaction

from . import history
from .models import Ticket, TicketAttachment, TicketLog, TicketSubtask
from .notifications import notify_response_request_completed
from .ticket_evidence import add_ticket_attachments


@dataclass(frozen=True)
class TicketEditResult:
    """The non-HTTP result of a validated ticket content correction."""

    ticket: Ticket
    changes: tuple = field(default_factory=tuple)


@dataclass(frozen=True)
class SubtaskUpdateResult:
    """The non-HTTP result of a validated subtask update."""

    subtask: TicketSubtask
    attachments: tuple[TicketAttachment, ...] = field(default_factory=tuple)
    completion_notified: bool = False


def save_ticket_edit(*, ticket, actor, edit_form, reason):
    """Save a validated TicketEditForm with field-level and summary audit rows."""
    with transaction.atomic():
        before = history.snapshot_saved(ticket)
        updated_ticket = edit_form.save()
        changes = tuple(
            history.record_changes(updated_ticket, before, actor, source='edit')
        )
        if changes:
            summary = ', '.join(change.field_label for change in changes)
            TicketLog.objects.create(
                ticket=updated_ticket,
                note=(
                    f'แก้ไขข้อมูลเคส ({len(changes)} รายการ): {summary}\n'
                    f'เหตุผล: {reason}'
                ),
                status_at_time=updated_ticket.status,
                author=actor,
            )
    return TicketEditResult(ticket=updated_ticket, changes=changes)


def save_subtask_update(
    *,
    ticket,
    actor,
    update_form,
    previous_status,
    previous_notes,
    was_done,
    result_upload=None,
    result_description='',
):
    """Save a validated subtask update, its history, and optional deliverable."""
    with transaction.atomic():
        subtask = update_form.save()
        history.record_subtask_status_change(
            subtask,
            previous_status,
            subtask.status,
            actor,
        )
        history.record_subtask_change(
            subtask,
            previous_notes,
            subtask.result_notes,
            actor,
        )
        attachments = ()
        if result_upload is not None:
            attachments = add_ticket_attachments(
                ticket=ticket,
                actor=actor,
                uploads=(result_upload,),
                subtask=subtask,
                description=result_description,
            ).attachments

    completion_notified = False
    if subtask.is_response_request and subtask.is_done and not was_done:
        completion_notified = notify_response_request_completed(subtask)
    return SubtaskUpdateResult(
        subtask=subtask,
        attachments=attachments,
        completion_notified=completion_notified,
    )
