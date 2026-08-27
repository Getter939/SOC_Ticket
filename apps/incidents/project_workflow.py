"""Write-side Project Incident workflow operations.

Views retain HTTP validation, authorization, and user-facing messages.  This
module coordinates the database changes that affect a Project Incident and its
member tickets so those mutations have one transactional home.
"""

from dataclasses import dataclass, field

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from .models import ProjectIncident, ProjectIncidentAttachment, ProjectIncidentLog, Ticket, TicketLog
from .notifications import notify_containment_alert


@dataclass(frozen=True)
class ProjectWorkflowResult:
    """The non-HTTP outcome of a Project Incident write operation."""

    project: ProjectIncident
    tickets: tuple[Ticket, ...] = ()
    attachments: tuple[ProjectIncidentAttachment, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)


def forward_project_review(*, project, actor, want_emergency, note):
    """Record one group verdict and forward every member awaiting review."""
    verdict = 'Emergency' if want_emergency else 'Normal'
    with transaction.atomic():
        locked_project = ProjectIncident.objects.select_for_update().get(pk=project.pk)
        pending = tuple(
            locked_project.member_tickets.select_for_update().filter(
                status=Ticket.STATUS_PENDING_MGR_TRIAGE,
            )
        )
        if not pending:
            raise ValidationError('ไม่มี Member Ticket ที่รอ Project Review')

        now = timezone.now()
        locked_project.is_emergency = want_emergency
        locked_project.emergency_decided_by = actor
        locked_project.emergency_decided_at = now
        locked_project.save(update_fields=(
            'is_emergency', 'emergency_decided_by', 'emergency_decided_at',
            'updated_at',
        ))
        ProjectIncidentLog.objects.create(
            project=locked_project,
            author=actor,
            note=f'Project Review: {verdict} — {note}',
        )
        for ticket in pending:
            ticket.assess_emergency_initial(want_emergency, actor)
            target = (
                Ticket.STATUS_AWAITING_OWNER
                if ticket.t1_route == Ticket.T1_ROUTE_OWNER
                else Ticket.STATUS_AWAITING_CONTAINMENT
            )
            ticket.transition_to(target, actor, f'[Project Review: {verdict}] {note}')

    warnings = tuple(
        warning
        for ticket in pending
        if ticket.status == Ticket.STATUS_AWAITING_CONTAINMENT
        for warning in _containment_warnings(ticket)
    )
    return ProjectWorkflowResult(
        project=locked_project,
        tickets=pending,
        warnings=warnings,
    )


def reassess_project_emergency(*, project, actor, value, reason):
    """Apply a post-review emergency reassessment to active member tickets."""
    with transaction.atomic():
        locked_project = ProjectIncident.objects.select_for_update().get(pk=project.pk)
        active_members = tuple(
            locked_project.member_tickets.select_for_update()
            .exclude(status__in=Ticket.TERMINAL_STATUSES)
            .exclude(status=Ticket.STATUS_PENDING_MGR_TRIAGE)
        )
        for ticket in active_members:
            if ticket.is_emergency != value:
                old = ticket.is_emergency
                ticket.is_emergency = value
                ticket.save(update_fields=('is_emergency', 'updated_at'))
                action_label = 'ตั้งเป็น' if value else 'ยกเลิก'
                TicketLog.objects.create(
                    ticket=ticket,
                    author=actor,
                    status_at_time=ticket.status,
                    note=(
                        f'[Project Reassess Emergency] {action_label} Emergency '
                        f'({old} → {value}) — เหตุผล: {reason}'
                    ),
                )
        locked_project.is_emergency = value
        locked_project.save(update_fields=('is_emergency', 'updated_at'))
        state = 'Emergency' if value else 'Normal'
        ProjectIncidentLog.objects.create(
            project=locked_project,
            author=actor,
            note=f'Reassess Emergency: {state} — {reason}',
        )
    return ProjectWorkflowResult(project=locked_project, tickets=active_members)


def add_shared_attachments(*, project, actor, uploads, description):
    """Add a validated batch of shared evidence and its single audit record."""
    uploads = tuple(uploads)
    with transaction.atomic():
        attachments = tuple(
            ProjectIncidentAttachment.objects.create(
                project=project,
                file=upload,
                original_name=upload.name,
                description=description,
                uploaded_by=actor,
            )
            for upload in uploads
        )
        ProjectIncidentLog.objects.create(
            project=project,
            author=actor,
            note='แนบหลักฐานส่วนกลาง: ' + ', '.join(upload.name for upload in uploads),
        )
    return ProjectWorkflowResult(project=project, attachments=attachments)


def delete_shared_attachment(*, attachment, actor, reason):
    """Soft-delete shared evidence and record its recovery reason."""
    with transaction.atomic():
        locked_attachment = ProjectIncidentAttachment.objects.select_for_update().get(
            pk=attachment.pk,
        )
        locked_attachment.deleted_by = actor
        locked_attachment.deleted_at = timezone.now()
        locked_attachment.deleted_reason = reason[:255]
        locked_attachment.save(update_fields=('deleted_by', 'deleted_at', 'deleted_reason'))
        ProjectIncidentLog.objects.create(
            project=locked_attachment.project,
            author=actor,
            note=(
                f'ลบหลักฐานส่วนกลาง: {locked_attachment.original_name} '
                f'— เหตุผล: {reason}'
            ),
        )
    return ProjectWorkflowResult(project=locked_attachment.project, attachments=(locked_attachment,))


def restore_shared_attachment(*, attachment, actor):
    """Restore soft-deleted shared evidence and retain who removed it."""
    with transaction.atomic():
        locked_attachment = ProjectIncidentAttachment.all_objects.select_for_update().get(
            pk=attachment.pk,
        )
        removed_by = (
            locked_attachment.deleted_by.get_full_name()
            or locked_attachment.deleted_by.username
        ) if locked_attachment.deleted_by else 'ไม่ทราบผู้ลบ'
        locked_attachment.deleted_by = None
        locked_attachment.deleted_at = None
        locked_attachment.deleted_reason = ''
        locked_attachment.save(update_fields=('deleted_by', 'deleted_at', 'deleted_reason'))
        ProjectIncidentLog.objects.create(
            project=locked_attachment.project,
            author=actor,
            note=(
                f'กู้คืนหลักฐานส่วนกลาง: {locked_attachment.original_name} '
                f'(ลบโดย {removed_by})'
            ),
        )
    return ProjectWorkflowResult(project=locked_attachment.project, attachments=(locked_attachment,))


def _containment_warnings(ticket):
    """Notify the assigned admin, returning the existing view warning text."""
    if not ticket.assigned_admin_id:
        return ('Ticket routed — ไม่สามารถส่งอีเมลแจ้งเตือนได้: ยังไม่ได้กำหนดผู้ดูแลระบบ',)
    admin = ticket.assigned_admin
    if not admin.email:
        return (f'Ticket routed — {admin.get_full_name() or admin.username} ไม่มีอีเมล',)
    if not notify_containment_alert(ticket, reason=None):
        return ('Ticket routed แต่ส่งอีเมลแจ้งเตือนไม่สำเร็จ — โปรดแจ้งผู้ดูแลระบบด้วยตนเอง',)
    return ()
