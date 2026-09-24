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
from .policies import (
    can_accept_subtask,
    can_delete_ticket_attachment,
    can_restore_ticket_attachment,
    can_update_subtask,
)


def get_closed_event_signoff(ticket):
    """Who reviewed and who closed a CLOSED_EVENT ticket, read from its timeline.

    verified_by/approved_by are stamped only on the Incident path into
    APPROVED, so an Event close leaves them blank. The TicketLog rows carry the
    same facts: the first CLOSED_EVENT row is the close itself, and the status
    before it tells which edge was taken — Tier 2 closing directly, or the SOC
    Manager confirming a Tier 2 close proposal (PENDING_MGR_EVENT_REVIEW).
    """
    close_log = None
    prior = []
    for log in ticket.logs.select_related('author').order_by('created_at', 'pk'):
        if log.status_at_time == Ticket.STATUS_CLOSED_EVENT:
            close_log = log
            break
        prior.append(log)

    signoff = {
        'reviewer': None, 'reviewed_at': None,
        'approver': None, 'closed_at': ticket.closed_at,
        'direct_close': True,
    }
    if close_log is None:
        return signoff
    signoff['closed_at'] = ticket.closed_at or close_log.created_at

    if prior and prior[-1].status_at_time == Ticket.STATUS_PENDING_MGR_EVENT_REVIEW:
        # The proposal is the row that entered the review state — the first of
        # the trailing run, not a comment logged while it sat with the manager.
        proposal = prior[-1]
        for log in reversed(prior):
            if log.status_at_time != Ticket.STATUS_PENDING_MGR_EVENT_REVIEW:
                break
            proposal = log
        signoff.update(
            reviewer=proposal.author, reviewed_at=proposal.created_at,
            approver=close_log.author, direct_close=False,
        )
    else:
        signoff.update(reviewer=close_log.author, reviewed_at=close_log.created_at)
    return signoff


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

    subtasks = list(ticket.subtasks.select_related(
        'assigned_to', 'created_by',
    ).prefetch_related(
        Prefetch(
            'attachments',
            queryset=TicketAttachment.objects.select_related('subtask__assigned_to'),
        ),
        Prefetch(
            'field_changes',
            queryset=TicketFieldChange.objects.filter(field_name='status')
            .select_related('changed_by').order_by('changed_at'),
        ),
    ))
    for subtask in subtasks:
        subtask.can_update = can_update_subtask(subtask, user)
        subtask.can_accept = can_accept_subtask(subtask, user)
        # The viewer's own response request is worked from the "งานของคุณ" card
        # at the top of the action column, not from the list further down.
        subtask.is_mine = subtask.is_response_request and subtask.assigned_to_id == user.pk
        # Prefill for the RCA report-number input; the analyst's own value wins.
        subtask.report_number_prefill = (
            subtask.report_number or subtask.expected_report_number
        )
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

    alert_links = list(ticket.alert_links.select_related('alert', 'linked_by'))

    return {
        'alert_links': alert_links,
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
        # Response-team requests are the live list; retired legacy Investigation/
        # Countermeasure rows (if any historical ones exist) render read-only in a
        # separate collapsed block.
        'response_subtasks': [s for s in subtasks if s.is_response_request],
        'legacy_subtasks': [s for s in subtasks if not s.is_response_request],
        'my_response_requests': [s for s in subtasks if s.is_mine],
        # Nav badge counts open response-team requests only — retired legacy
        # subtasks never count as "ค้าง".
        'open_subtask_count': sum(
            subtask.is_response_request and not subtask.is_done
            for subtask in subtasks
        ),
        'evidence_count': len(attachments) + len(alert_links),
        'event_signoff': (
            get_closed_event_signoff(ticket)
            if ticket.status == Ticket.STATUS_CLOSED_EVENT else None
        ),
    }
