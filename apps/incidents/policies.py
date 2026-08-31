"""Authorization policies shared by incident views and read models.

Keep these predicates free of request/response concerns.  Views remain
responsible for enforcing model transitions and returning the appropriate HTTP
response; this module answers only whether a user may be offered or attempt an
incident action.
"""

from apps.wazuh_ingest.models import WazuhAlert

from .models import Ticket, TriageRecord


def user_can_drive(ticket, user, permission):
    """Whether ``user`` satisfies a SOC-side transition permission token.

    Only the SOC-driven tokens are considered here (the ASSIGNED_ADMIN step is
    handled by the dedicated containment form, not the status dropdown).
    """
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
    """Whether user is the party this ticket is currently waiting on.

    The "whose court is it?" rule on its own, so the surfaces that care about
    it cannot drift apart: the attachment gate enforces it, and the edit form
    warns on it (see ``edit_ticket``).

    Deliberately pure court logic — no terminal-status refusal and no
    superuser bypass. Callers layer those on, which is what lets the edit
    warning treat a superuser as out-of-court (they never hold one) while
    can_upload_ticket_attachment still lets them through.
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
        # Both, deliberately. Owners are contacted out of band and in practice
        # never log in — gating this on the owner alone meant NOBODY could
        # attach while the ticket sat here, so a screenshot the owner emailed
        # in had nowhere to go until Tier 1 advanced the ticket just to earn
        # the right to upload it. The creator is the party actually holding
        # the case; the owner keeps the right for the day one does log in.
        if profile.is_system_owner and ticket.system_owner_id == user.pk:
            return True
        return profile.is_tier1 and ticket.created_by_id == user.pk
    return False


def can_upload_ticket_attachment(ticket, user):
    """Whether user currently owns this ticket's attachment action.

    Seeing a ticket is deliberately broader than acting on it. Attachments
    therefore follow the same "whose court is it?" rule as the workflow
    (holds_ticket_court), and are never accepted after a ticket has reached a
    terminal state.

    This gates ``upload_attachment``. There is exactly one documented exception:
    a response-request deliverable uploaded through ``update_subtask``, which
    runs on can_upload_subtask_result() instead — see the reasoning there.
    """
    if ticket.status in Ticket.TERMINAL_STATUSES:
        return False
    if user.is_superuser:
        return True
    return holds_ticket_court(ticket, user)


def is_soc(user):
    """Superuser, or a SOC analyst/manager — the "sees and drives everything" set."""
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.is_soc)


def is_soc_manager(user):
    """Superuser, or a SOC Manager — the privileged-override set.

    Mirrors Ticket._is_emergency_manager, which is the same rule expressed on
    the model for emergency reassessment. Kept as a plain predicate here because
    the checks below are about a person, not about a particular ticket.
    """
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.is_soc_manager)


def can_delete_ticket_attachment(ticket, attachment, user):
    """Whether user may remove this piece of evidence.

    Removing evidence is deliberately narrower than adding it. The terminal
    check comes first, ahead of the superuser bypass — the same order as
    can_upload_ticket_attachment, and what makes a closed case refuse
    everyone. Once a ticket is APPROVED or CLOSED_EVENT its evidence is frozen;
    that is the window in which a quiet deletion would never be noticed.

    "Any SOC member" is not enough: SOC can see every ticket, so that rule let
    an uninvolved analyst remove another team's evidence. The uploader may undo
    their own mistake, the responder assigned to a response request may manage
    that request's deliverables, and a SOC Manager may act on anything still
    open.
    """
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
    """Whether user may add shared evidence to a case bundle.

    The bundle has no single "court" of its own — it is a grouping, and each
    member sits in its own. So the rule is: hold the court on ANY member, or be
    a SOC Manager. That admits exactly the people already working the incident
    (the assigned admin of one affected system, the owner of another) without
    opening group evidence to every SOC account.

    Frozen once every member is closed, mirroring the terminal-status refusal
    in can_upload_ticket_attachment — a finished case's evidence set is fixed.
    """
    if project.all_closed:
        return False
    if user.is_superuser or is_soc_manager(user):
        return True
    return any(
        holds_ticket_court(member, user)
        for member in project.member_tickets.all()
    )


def can_delete_project_attachment(project, attachment, user):
    """Whether user may remove shared bundle evidence.

    Same shape as can_delete_ticket_attachment: narrower than adding, frozen
    on a finished bundle, uploader may undo their own mistake, SOC Manager may
    act on anything still open.
    """
    if project.all_closed:
        return False
    if attachment.uploaded_by_id == user.pk:
        return True
    return is_soc_manager(user)


def can_edit_ticket(ticket, user):
    """Whether user may correct this ticket's content.

    There was no edit surface at all before this: Tier 1's original content
    could only ever be fixed by a Tier 2 analyst while the ticket sat at
    ESCALATED_T2, so a ticket routed straight to the manager was uneditable for
    its whole life.

    The creator gets to fix their own typo while the ticket is still untouched
    (NEW — nobody else has acted on it). After that it is SOC's call, because by
    then the content is what other roles are acting on. Closed cases are frozen,
    and every edit is recorded field-by-field (see apps.incidents.history).

    Note the creator clause is currently redundant: only Tier 1 can open a
    ticket, and Tier 1 is SOC, so the final line already covers them. It is
    written out anyway so that narrowing SOC's edit rights later cannot silently
    take away the author's right to correct their own untouched ticket.

    A Tier 2 claim covers the ticket's CONTENT as well as its status.
    transition_to refuses a second Tier 2 at its step 3b; without the same
    check here that analyst could still rewrite the description the claimer is
    working from, so the two surfaces would answer differently about the same
    ticket at the same moment.

    Otherwise this stays deliberately broader than holds_ticket_court: a
    correction is not a workflow move, and refusing an analyst the right to fix
    their own earlier mistake once the ticket moved on would cost more than it
    protects. ``edit_ticket`` warns when the ticket is in someone else's court
    instead, and every edit is attributed and diffed either way.
    """
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
    """Whether user may bring deleted evidence back.

    Not gated on terminal status, unlike deletion. Refusing removal on a closed
    case protects the evidence set; refusing *recovery* would only make a
    mistake permanent, so restore stays available after closure.
    """
    return is_soc_manager(user)


def can_upload_subtask_result(subtask, user):
    """Whether user may attach a deliverable to this subtask.

    A deliberate exception to can_upload_ticket_attachment()'s "whose court is
    the TICKET in?" rule, because for a response request the court that matters
    is the REQUEST. A Forensic Analyst must be able to file their report while
    the parent ticket sits in PENDING_MGR_TRIAGE — a state whose ticket-level
    rule answers `profile.is_soc_manager`, which would refuse them.

    Narrower than the `is_soc or is_assignee` test this replaces: plain SOC
    staff could previously attach a file here to a ticket they had no
    ticket-level upload right on. The assignee does the work, the SOC manager
    owns the request lifecycle, and nobody else needs a file on it.

    Terminal-status refusal is NOT repeated here — callers check it first, ahead
    of the superuser bypass, which is what makes a closed ticket refuse everyone.
    """
    if user.is_superuser or subtask.assigned_to_id == user.pk:
        return True
    profile = getattr(user, 'profile', None)
    return profile is not None and profile.is_soc_manager


def can_access_ticket_report(user):
    """Whether user may preview or export the incident report.

    The report is a SOC deliverable, not a per-party document: it carries NT
    branding and the verified/approved sign-off block, and it is aimed outward
    (e.g., executives). The roles that merely appear *in* a case — the assigned
    admin, the system owner, a response-team member holding a subtask — are
    subjects of the report rather than its authors, and everything they need
    operationally is already on ticket_detail.

    Deliberately a role test with no ticket argument: exporting writes the
    report_* provenance fields (see reports._record_export_metadata), so letting
    a party to the incident regenerate the report would overwrite who produced
    it and reset the stale-report badge. Keeping that SOC-only is what keeps the
    provenance authoritative.
    """
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
