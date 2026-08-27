"""Authorization policies shared by incident views and read models.

Keep these predicates free of request/response concerns.  Views remain
responsible for enforcing model transitions and returning the appropriate HTTP
response; this module answers only whether a user may be offered or attempt an
incident action.
"""

from apps.wazuh_ingest.models import WazuhAlert

from .models import Ticket, TriageRecord


def user_can_drive(ticket, user, permission):
    """Return whether ``user`` satisfies a SOC transition permission token."""
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    if profile is None:
        return False
    if permission == 'TIER1_CREATOR':
        return profile.is_tier1 and user.pk == ticket.created_by_id
    if permission == 'TIER2':
        return profile.is_tier2
    if permission == 'MANAGER':
        return profile.is_soc_manager
    return False


def holds_ticket_court(ticket, user):
    """Return whether the ticket is currently waiting on ``user``.

    This is deliberately pure court logic: callers layer terminal-state rules
    and superuser bypasses on top where those semantics are appropriate.
    """
    profile = getattr(user, 'profile', None)
    if profile is None:
        return False

    if ticket.status in (
        Ticket.STATUS_NEW,
        Ticket.STATUS_T1_REVIEW,
        Ticket.STATUS_OWNER_REMEDIATED,
    ):
        return profile.is_tier1 and ticket.created_by_id == user.pk
    if ticket.status in Ticket.TIER2_QUEUE_STATUSES:
        return profile.is_tier2 and not ticket.t2_claim_blocks(user)
    if ticket.status in Ticket.MANAGER_QUEUE_STATUSES:
        return profile.is_soc_manager
    if ticket.status == Ticket.STATUS_AWAITING_CONTAINMENT:
        return profile.is_system_admin and ticket.assigned_admin_id == user.pk
    if ticket.status == Ticket.STATUS_AWAITING_OWNER:
        if profile.is_system_owner and ticket.system_owner_id == user.pk:
            return True
        return profile.is_tier1 and ticket.created_by_id == user.pk
    return False


def can_upload_ticket_attachment(ticket, user):
    """Return whether ``user`` may add evidence to this ticket now."""
    if ticket.status in Ticket.TERMINAL_STATUSES:
        return False
    if user.is_superuser:
        return True
    return holds_ticket_court(ticket, user)


def is_soc(user):
    """Return whether ``user`` is a superuser or SOC analyst/manager."""
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.is_soc)


def is_soc_manager(user):
    """Return whether ``user`` is a superuser or SOC Manager."""
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.is_soc_manager)


def can_delete_ticket_attachment(ticket, attachment, user):
    """Return whether ``user`` may remove this piece of ticket evidence."""
    if ticket.status in Ticket.TERMINAL_STATUSES:
        return False
    if attachment.uploaded_by_id == user.pk:
        return True
    if (
        attachment.subtask_id
        and attachment.subtask.is_response_request
        and attachment.subtask.assigned_to_id == user.pk
    ):
        return True
    return is_soc_manager(user)


def can_upload_project_attachment(project, user):
    """Return whether ``user`` may add shared evidence to a case bundle."""
    if project.all_closed:
        return False
    if user.is_superuser or is_soc_manager(user):
        return True
    return any(
        holds_ticket_court(member, user)
        for member in project.member_tickets.all()
    )


def can_delete_project_attachment(project, attachment, user):
    """Return whether ``user`` may remove shared bundle evidence."""
    if project.all_closed:
        return False
    if attachment.uploaded_by_id == user.pk:
        return True
    return is_soc_manager(user)


def can_edit_ticket(ticket, user):
    """Return whether ``user`` may correct this ticket's content."""
    if ticket.status in Ticket.TERMINAL_STATUSES:
        return False
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    if profile is None:
        return False
    if ticket.status == Ticket.STATUS_NEW and ticket.created_by_id == user.pk:
        return profile.is_tier1
    if ticket.t2_claim_blocks(user):
        return False
    return is_soc(user)


def can_restore_ticket_attachment(user):
    """Return whether ``user`` may recover deleted ticket evidence."""
    return is_soc_manager(user)


def can_upload_subtask_result(subtask, user):
    """Return whether ``user`` may add a deliverable to this subtask."""
    if user.is_superuser or subtask.assigned_to_id == user.pk:
        return True
    profile = getattr(user, 'profile', None)
    return profile is not None and profile.is_soc_manager


def can_access_ticket_report(user):
    """Return whether ``user`` may preview or export incident reports."""
    return is_soc(user)


def can_create_ticket_from_triage(triage, user):
    """Return whether ``user`` may convert a manual triage record."""
    if triage.ticket_id or triage.project_incident_id:
        return False
    if not triage.decision:
        return (
            user.is_superuser
            or (
                triage.claimed_by_id == user.id
                and getattr(getattr(user, 'profile', None), 'is_tier1', False)
            )
        )
    if user.is_superuser:
        return triage.final_decision == TriageRecord.DECISION_TP
    if triage.decision == TriageRecord.DECISION_TP:
        return triage.analyst_id == user.id
    return (
        triage.decision == TriageRecord.DECISION_ESCALATED
        and triage.t2_decision == TriageRecord.DECISION_TP
        and triage.escalated_to_id == user.id
    )


def can_create_ticket_from_wazuh(alert, user):
    """Return whether ``user`` may convert a claimed Wazuh alert."""
    profile = getattr(user, 'profile', None)
    if (
        alert.claimed_by_id != user.id
        or hasattr(alert, 'ticket')
        or hasattr(alert, 'ticket_alert_link')
        or alert.project_incident_id
    ):
        return False
    if user.is_superuser:
        return alert.triage_status in (
            WazuhAlert.TRIAGE_TRIAGING,
            WazuhAlert.TRIAGE_ESCALATED,
        )
    if alert.triage_status == WazuhAlert.TRIAGE_TRIAGING:
        return True
    if alert.triage_status != WazuhAlert.TRIAGE_ESCALATED or profile is None:
        return False
    user_tier = WazuhAlert.TIER_MANAGER if profile.is_soc_manager else profile.tier
    return alert.escalated_to_tier == user_tier
