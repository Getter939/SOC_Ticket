"""Read models for incident pages.

Selectors centralize query shape and read-only decoration.  They do not mutate
workflow state and do not construct forms or HTTP responses.
"""

from django.contrib.auth.models import User
from django.db.models import Prefetch

from apps.accounts.models import UserProfile

from .models import (
    Ticket,
    TicketAttachment,
    TicketFieldChange,
    TicketLogRevision,
    TicketSubtask,
)
from .policies import can_delete_ticket_attachment, can_restore_ticket_attachment


def get_ticket_detail_read_model(
    *,
    ticket,
    user,
    can_submit_containment,
    can_request_response,
):
    """Return query-backed context for the ticket detail page.

    The view supplies workflow permissions it already computed for POST
    handling.  This selector owns only data loading, query optimization, and
    per-record presentation flags derived from the shared policy module.
    """
    logs = ticket.logs.select_related('author').prefetch_related(
        Prefetch(
            'revisions',
            queryset=TicketLogRevision.objects.select_related('edited_by'),
        )
    )

    containment_return_log = None
    if can_submit_containment and ticket.logs.filter(
        status_at_time=Ticket.STATUS_CONTAINMENT_REPORTED,
    ).exists():
        containment_return_log = ticket.logs.filter(
            status_at_time=Ticket.STATUS_AWAITING_CONTAINMENT,
        ).select_related('author').first()

    attachments = list(
        ticket.attachments.filter(subtask__isnull=True).select_related('uploaded_by')
    )
    for attachment in attachments:
        attachment.can_delete = can_delete_ticket_attachment(ticket, attachment, user)

    subtasks = ticket.subtasks.select_related('assigned_to', 'created_by').prefetch_related(
        Prefetch(
            'attachments',
            queryset=TicketAttachment.objects.select_related('subtask__assigned_to'),
        ),
        Prefetch(
            'field_changes',
            queryset=TicketFieldChange.objects.filter(field_name='status')
            .select_related('changed_by').order_by('changed_at'),
        ),
    )
    for subtask in subtasks:
        for attachment in subtask.attachments.all():
            attachment.can_delete = can_delete_ticket_attachment(ticket, attachment, user)

    response_routing = {}
    response_member_roles = {}
    if can_request_response:
        response_routing = TicketSubtask.response_routing()
        response_member_roles = {
            str(pk): role
            for pk, role in User.objects.filter(
                is_active=True,
                profile__role__in=(
                    UserProfile.ROLE_FORENSIC,
                    UserProfile.ROLE_REDTEAM_MANAGER,
                ),
            ).values_list('pk', 'profile__role')
        }

    can_restore_attachment = can_restore_ticket_attachment(user)
    deleted_attachments = (
        TicketAttachment.all_objects
        .filter(ticket=ticket, deleted_at__isnull=False)
        .select_related('deleted_by').order_by('-deleted_at')
        if can_restore_attachment else []
    )

    return {
        'alert_links': list(ticket.alert_links.select_related('alert', 'linked_by')),
        'logs': logs,
        'containment_return_log': containment_return_log,
        'attachments': attachments,
        'field_changes': ticket.field_changes.exclude(
            subtask__isnull=False,
            field_name='status',
        ).select_related('changed_by', 'subtask')[:50],
        'can_restore_attachment': can_restore_attachment,
        'deleted_attachments': deleted_attachments,
        'response_routing': response_routing,
        'response_member_roles': response_member_roles,
        'subtasks': subtasks,
    }
