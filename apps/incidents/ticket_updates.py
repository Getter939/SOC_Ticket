"""Write-side Ticket editing and subtask update operations.

Views retain request validation, authorization, and messages. This module owns
the coordinated persistence of content edits, subtask history, deliverables,
and response-request completion notifications.
"""

from dataclasses import dataclass, field

from django.core.exceptions import ValidationError
from django.db import transaction

from . import history
from .models import Ticket, TicketAttachment, TicketLog, TicketSubtask
from .notifications import notify_response_request_completed
from .staging import adopt_staged
from .ticket_evidence import add_ticket_attachments


@dataclass(frozen=True)
class TicketEditResult:
    """The non-HTTP result of a validated ticket content correction."""

    ticket: Ticket
    changes: tuple = field(default_factory=tuple)
    attachments: tuple[TicketAttachment, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SubtaskUpdateResult:
    """The non-HTTP result of a validated subtask update."""

    subtask: TicketSubtask
    attachments: tuple[TicketAttachment, ...] = field(default_factory=tuple)
    completion_notified: bool = False


def save_ticket_edit(*, ticket, actor, edit_form, reason, evidence_token=None):
    """Save validated content and staged evidence together with their audit rows.

    The edit view locks the ticket and checks upload permission before supplying
    an evidence token. Staged files remain available if this transaction fails.
    """
    with transaction.atomic():
        before = history.snapshot_saved(ticket)
        before_iocs = history.ioc_snapshot(ticket)
        updated_ticket = edit_form.save()
        if hasattr(edit_form, 'save_iocs'):
            edit_form.save_iocs(updated_ticket)
        changes = list(
            history.record_changes(updated_ticket, before, actor, source='edit')
        )
        ioc_change = history.record_ioc_change(
            updated_ticket, before_iocs, history.ioc_snapshot(updated_ticket),
            actor, source='edit',
        )
        if ioc_change:
            changes.append(ioc_change)
        changes = tuple(changes)
        attachments = tuple(adopt_staged(evidence_token, actor, ticket=updated_ticket))
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
        if attachments:
            names = ', '.join(attachment.original_name for attachment in attachments)
            TicketLog.objects.create(
                ticket=updated_ticket,
                note=f'แนบไฟล์หลักฐาน ({len(attachments)} ไฟล์): {names}\nเหตุผล: {reason}',
                status_at_time=updated_ticket.status,
                author=actor,
            )
    return TicketEditResult(ticket=updated_ticket, changes=changes, attachments=attachments)


def save_subtask_update(
    *,
    ticket,
    actor,
    update_form,
    previous_status,
    previous_notes,
    was_done,
    previous_report_number='',
    result_upload=None,
    result_description='',
):
    """Save a validated subtask update, its history, and optional deliverable."""
    with transaction.atomic():
        # The assignee and the SOC Manager both write to a request. Lock the row
        # and refuse if it was saved after this form's copy was loaded; otherwise
        # the later submit silently replaces the earlier one's notes/status and
        # the audit history records the wrong "before" value.
        locked = (
            TicketSubtask.objects.select_for_update()
            .filter(pk=update_form.instance.pk).values_list('updated_at', flat=True).first()
        )
        if locked is not None and locked != update_form.instance.updated_at:
            raise ValidationError(
                'คำขอนี้ถูกอัปเดตโดยผู้อื่นระหว่างที่คุณดำเนินการ '
                'กรุณาโหลดหน้าใหม่แล้วลองอีกครั้ง — ไม่มีการบันทึกข้อมูล'
            )
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
        history.record_subtask_report_number_change(
            subtask,
            previous_report_number,
            subtask.report_number,
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
