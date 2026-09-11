"""Write-side ticket workflow operations.

Views validate HTTP input and decide how to render messages.  This module owns
the state-changing operations that coordinate model transitions, audit history,
and notifications so each workflow action has one application-level home.
"""

from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from . import history
from .models import Ticket
from .notifications import (
    notify_containment_alert,
    notify_containment_submitted,
    notify_manager_triage_pending,
    notify_system_owner_closed,
)


@dataclass(frozen=True)
class TicketWorkflowResult:
    """The non-HTTP outcome of a ticket workflow operation."""

    ticket: Ticket
    target_status: str | None = None
    claimed: bool | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)


def reassess_emergency(*, ticket, actor, value, reason):
    """Record a manager's post-review emergency reassessment."""
    ticket.reassess_emergency(value, actor, reason)
    return TicketWorkflowResult(ticket=ticket)


def cancellation_action(*, ticket, actor, action, **kwargs):
    return ticket.cancellation_action(actor=actor, action=action, **kwargs)


def step_back(*, ticket, actor, reason):
    """Move a ticket back one approved workflow step."""
    target_status = ticket.step_back(actor, reason)
    return TicketWorkflowResult(ticket=ticket, target_status=target_status)


def complete_t2_review(*, ticket, actor, review_form, next_status, decision_note, fallback_label):
    """Save Tier 2 corrections, record field history, and transition the ticket."""
    with transaction.atomic():
        before = history.snapshot_saved(ticket)
        before_iocs = history.ioc_snapshot(ticket)
        ticket = review_form.save()
        if hasattr(review_form, 'save_iocs'):
            review_form.save_iocs(ticket)
        history.record_changes(ticket, before, actor, source='t2_review')
        history.record_ioc_change(
            ticket, before_iocs, history.ioc_snapshot(ticket), actor, source='t2_review')
        ticket.transition_to(next_status, actor, decision_note or fallback_label)

    warnings = _owner_closed_warnings(ticket) if next_status == Ticket.STATUS_CLOSED_EVENT else ()
    return TicketWorkflowResult(ticket=ticket, target_status=next_status, warnings=warnings)


def assign_admin_or_owner_route(*, ticket, actor, route, note, assignment_form=None):
    """Set Tier 1's handling lane and forward the ticket for manager review."""
    with transaction.atomic():
        if route == Ticket.T1_ROUTE_OWNER:
            ticket.t1_route = Ticket.T1_ROUTE_OWNER
        else:
            ticket = assignment_form.save(commit=False)
            ticket.t1_route = Ticket.T1_ROUTE_ADMIN
        ticket.transition_to(Ticket.STATUS_PENDING_MGR_TRIAGE, actor, note)

    notify_manager_triage_pending(ticket)
    return TicketWorkflowResult(
        ticket=ticket,
        target_status=Ticket.STATUS_PENDING_MGR_TRIAGE,
    )


def manager_forward(*, ticket, actor, want_emergency, target_status, note):
    """Record the manager's initial emergency verdict and forward the selected lane."""
    verdict = 'Emergency' if want_emergency else 'Normal'
    forward_note = f'[ประเมินสถานะฉุกเฉิน: {verdict}] {note}'
    with transaction.atomic():
        ticket.assess_emergency_initial(want_emergency, actor)
        ticket.transition_to(target_status, actor, forward_note)

    warnings = (
        _containment_warnings(ticket, reason=None)
        if target_status == Ticket.STATUS_AWAITING_CONTAINMENT
        else ()
    )
    return TicketWorkflowResult(
        ticket=ticket,
        target_status=target_status,
        warnings=warnings,
    )


def start_monitoring(*, ticket, actor, note):
    """Tier 2 parks a not-yet-classified case under Tier 1 for the watch window.

    transition_to stamps the 30-day deadline, marks the ticket monitored (one
    way), and clears the classification. No email — the case simply appears in
    the owning Tier 1's My Queue with its countdown.
    """
    with transaction.atomic():
        ticket.transition_to(Ticket.STATUS_MONITORING, actor, note)
    return TicketWorkflowResult(
        ticket=ticket,
        target_status=Ticket.STATUS_MONITORING,
    )


def conclude_monitoring(*, ticket, actor, outcome, note):
    """The owning Tier 1 ends a monitoring window.

    ``outcome='incident'`` — something happened: classify Incident and hand to
    the SOC Manager pre-containment triage. ``outcome='event'`` — the window
    closed quietly: classify Event and hand to Tier 2 to confirm the close. Both
    set the classification the exit edge's gate requires.
    """
    with transaction.atomic():
        if outcome == 'incident':
            ticket.classification = Ticket.CLASSIFICATION_INCIDENT
            target = Ticket.STATUS_PENDING_MGR_TRIAGE
        else:
            ticket.classification = Ticket.CLASSIFICATION_EVENT
            target = Ticket.STATUS_ESCALATED_T2
        ticket.transition_to(target, actor, note)

    if target == Ticket.STATUS_PENDING_MGR_TRIAGE:
        notify_manager_triage_pending(ticket)
    return TicketWorkflowResult(ticket=ticket, target_status=target)


def reclassify_as_event(*, ticket, actor, note):
    """Let Tier 2 classify an active case as an Event and close it."""
    with transaction.atomic():
        ticket.classification = Ticket.CLASSIFICATION_EVENT
        ticket.transition_to(Ticket.STATUS_CLOSED_EVENT, actor, note)

    return TicketWorkflowResult(
        ticket=ticket,
        target_status=Ticket.STATUS_CLOSED_EVENT,
        warnings=_owner_closed_warnings(ticket),
    )


def submit_containment(*, ticket, actor, report, remediation, note, checked_indexes):
    """Save containment evidence, record changes, and submit it for Tier 2 review."""
    before = history.snapshot(ticket)
    ticket.containment_report = report
    if remediation:
        ticket.remediation_summary = remediation

    item_lines, _ = Ticket.parse_checklist_items(ticket.action_required)
    ticket.containment_checklist = [
        {'text': line, 'done': str(index) in checked_indexes}
        for index, line in enumerate(item_lines)
    ]
    done_count = sum(1 for item in ticket.containment_checklist if item['done'])
    total_count = len(ticket.containment_checklist)

    transition_note = note or 'ส่งรายงานการควบคุมแล้ว'
    if total_count:
        transition_note = (
            f'{transition_note}\n'
            f'(เช็กลิสต์สิ่งที่ต้องดำเนินการ: '
            f'ดำเนินการแล้ว {done_count}/{total_count} รายการ)'
        )

    ticket.transition_to(Ticket.STATUS_CONTAINMENT_REPORTED, actor, transition_note)
    history.record_changes(ticket, before, actor, source='containment')

    warnings = ()
    if not notify_containment_submitted(ticket):
        warnings = ('ส่งรายงานการควบคุมแล้ว แต่ส่งอีเมลแจ้งเจ้าหน้าที่ SOC ไม่สำเร็จ',)
    return TicketWorkflowResult(
        ticket=ticket,
        target_status=Ticket.STATUS_CONTAINMENT_REPORTED,
        warnings=warnings,
    )


def record_remediation_check(
    *, ticket, actor, checked_keys, other, findings=None, countermeasure=None,
):
    """Save Tier 2's section-8 remediation checklist as it verifies containment.

    Stores the ticked item KEYS (unknown keys ignored) plus the free-text
    'อื่นๆ ระบุ'. ``findings`` / ``countermeasure`` are the Owner-lane's optional
    Investigation Findings / Countermeasure — accepted only when provided (the
    Admin lane leaves them to the System Admin). Field history is recorded by the
    caller's surrounding snapshot; this only mutates and saves.
    """
    from .report_content import REMEDIATION_CHECKLIST_KEYS

    ticket.remediation_checklist = [
        key for key in checked_keys if key in REMEDIATION_CHECKLIST_KEYS
    ]
    ticket.remediation_other = other or ''
    update_fields = ['remediation_checklist', 'remediation_other']
    if findings is not None:
        ticket.remediation_summary = findings
        update_fields.append('remediation_summary')
    if countermeasure is not None:
        ticket.containment_report = countermeasure
        update_fields.append('containment_report')
    ticket.save(update_fields=update_fields)


def transition_ticket(*, ticket, actor, next_status, note):
    """Apply a standard status transition and its resulting notifications."""
    previous_status = ticket.status
    ticket.transition_to(next_status, actor, note)

    warnings = ()
    if next_status == Ticket.STATUS_AWAITING_CONTAINMENT:
        reason = note if previous_status == Ticket.STATUS_CONTAINMENT_REPORTED else None
        warnings = _containment_warnings(ticket, reason=reason)
    elif next_status in (Ticket.STATUS_APPROVED, Ticket.STATUS_CLOSED_EVENT):
        warnings = _owner_closed_warnings(ticket)
    return TicketWorkflowResult(
        ticket=ticket,
        target_status=next_status,
        warnings=warnings,
    )


def claim_tier2_ticket(*, ticket, actor):
    """Atomically claim an unclaimed Tier 2 queue ticket for ``actor``."""
    claimed = Ticket.objects.filter(
        pk=ticket.pk,
        status__in=Ticket.TIER2_QUEUE_STATUSES,
        t2_claimed_by__isnull=True,
    ).update(t2_claimed_by=actor, t2_claimed_at=timezone.now())
    return TicketWorkflowResult(ticket=ticket, claimed=bool(claimed))


def _containment_warnings(ticket, *, reason):
    if not ticket.assigned_admin_id:
        return ('Ticket routed — ไม่สามารถส่งอีเมลแจ้งเตือนได้: ยังไม่ได้กำหนดผู้ดูแลระบบ',)

    admin = ticket.assigned_admin
    if not admin.email:
        return (f'Ticket routed — {admin.get_full_name() or admin.username} ไม่มีอีเมล',)
    if not notify_containment_alert(ticket, reason=reason):
        return ('Ticket routed แต่ส่งอีเมลแจ้งเตือนไม่สำเร็จ — โปรดแจ้งผู้ดูแลระบบด้วยตนเอง',)
    return ()


def _owner_closed_warnings(ticket):
    if ticket.system_owner and ticket.system_owner.email:
        attachments = list(ticket.attachments.all())
        if not notify_system_owner_closed(ticket, attachments=attachments):
            return ('Ticket ปิดแล้ว แต่ส่งอีเมลแจ้ง System Owner ไม่สำเร็จ',)
    return ()
