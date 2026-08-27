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


def step_back(*, ticket, actor, reason):
    """Move a ticket back one approved workflow step."""
    target_status = ticket.step_back(actor, reason)
    return TicketWorkflowResult(ticket=ticket, target_status=target_status)


def complete_t2_review(*, ticket, actor, review_form, next_status, decision_note, fallback_label):
    """Save Tier 2 corrections, record field history, and transition the ticket."""
    with transaction.atomic():
        before = history.snapshot_saved(ticket)
        ticket = review_form.save()
        history.record_changes(ticket, before, actor, source='t2_review')
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
