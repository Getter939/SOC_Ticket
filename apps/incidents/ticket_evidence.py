"""Write-side Ticket evidence operations.

Views validate request input, apply authorization policies, and decide which
messages to show. This module owns the transactional creation and recoverable
removal of TicketAttachment records and their required audit history.
"""

from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from .models import Ticket, TicketAttachment, TicketLog


@dataclass(frozen=True)
class TicketEvidenceResult:
    """The non-HTTP result of a Ticket evidence write operation."""

    ticket: Ticket
    attachments: tuple[TicketAttachment, ...] = field(default_factory=tuple)


def add_ticket_attachments(*, ticket, actor, uploads, description='', subtask=None):
    """Persist validated ticket evidence, optionally as a subtask deliverable."""
    uploads = tuple(uploads)
    with transaction.atomic():
        attachments = tuple(
            TicketAttachment.objects.create(
                ticket=ticket,
                subtask=subtask,
                file=upload,
                original_name=upload.name,
                description=description,
                uploaded_by=actor,
            )
            for upload in uploads
        )
    return TicketEvidenceResult(ticket=ticket, attachments=attachments)


def delete_ticket_attachment(*, attachment, actor, reason):
    """Soft-delete evidence while retaining the file and full audit reason."""
    with transaction.atomic():
        locked_attachment = TicketAttachment.objects.select_for_update().get(
            pk=attachment.pk,
        )
        ticket = Ticket.objects.select_for_update().get(pk=locked_attachment.ticket_id)
        locked_attachment.deleted_by = actor
        locked_attachment.deleted_at = timezone.now()
        locked_attachment.deleted_reason = reason[:255]
        locked_attachment.save(update_fields=('deleted_by', 'deleted_at', 'deleted_reason'))
        TicketLog.objects.create(
            ticket=ticket,
            note=f'Attachment removed: {locked_attachment.original_name} — เหตุผล: {reason}',
            status_at_time=ticket.status,
            author=actor,
        )
    return TicketEvidenceResult(ticket=ticket, attachments=(locked_attachment,))


def restore_ticket_attachment(*, attachment, actor):
    """Restore soft-deleted evidence and preserve its prior remover in the log."""
    with transaction.atomic():
        locked_attachment = TicketAttachment.all_objects.select_for_update().get(
            pk=attachment.pk,
        )
        ticket = Ticket.objects.select_for_update().get(pk=locked_attachment.ticket_id)
        removed_by = (
            locked_attachment.deleted_by.get_full_name()
            or locked_attachment.deleted_by.username
        ) if locked_attachment.deleted_by else 'ไม่ทราบผู้ลบ'
        locked_attachment.deleted_by = None
        locked_attachment.deleted_at = None
        locked_attachment.deleted_reason = ''
        locked_attachment.save(update_fields=('deleted_by', 'deleted_at', 'deleted_reason'))
        TicketLog.objects.create(
            ticket=ticket,
            note=(
                f'Attachment restored: {locked_attachment.original_name} '
                f'(เดิมลบโดย {removed_by})'
            ),
            status_at_time=ticket.status,
            author=actor,
        )
    return TicketEvidenceResult(ticket=ticket, attachments=(locked_attachment,))
