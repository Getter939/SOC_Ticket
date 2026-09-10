"""Cancellation rules, serialized on the parent ticket with an immutable audit."""

from functools import partial

from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from django.utils import timezone

from .models import Ticket, TicketCancellationRequest, TicketLog, TicketSubtask
from .policies import holds_ticket_court, is_soc_manager


def can_request_cancellation(ticket, actor):
    if not actor.is_authenticated or ticket.status in Ticket.TERMINAL_STATUSES:
        return False
    if ticket.t2_claim_blocks(actor) and not is_soc_manager(actor):
        return False
    if not Ticket.objects.visible_to(actor).filter(pk=ticket.pk).exists():
        return False
    profile = getattr(actor, 'profile', None)
    creator = ticket.created_by_id == actor.pk and profile and profile.is_soc
    return bool(is_soc_manager(actor) or creator or holds_ticket_court(ticket, actor))


def can_cancel_directly(ticket, actor):
    if not can_request_cancellation(ticket, actor):
        return False
    profile = getattr(actor, 'profile', None)
    return bool(is_soc_manager(actor) or (
        ticket.status == Ticket.STATUS_NEW and ticket.created_by_id == actor.pk
        and profile and profile.is_tier1
    ))


def perform_cancellation(*, ticket, actor, action, request_id=None, reason='',
                         explanation='', duplicate_of=None, decision_note='',
                         cancel_subtask_ids=()):
    from .notifications import notify_ticket_cancellation

    with transaction.atomic():
        # Match the Project Review lock order: project, then member ticket.
        if ticket.project_incident_id:
            from .models import ProjectIncident
            ProjectIncident.objects.select_for_update().get(pk=ticket.project_incident_id)
        current = Ticket.objects.select_for_update().get(pk=ticket.pk)
        if current.status in Ticket.TERMINAL_STATUSES:
            raise ValidationError('รายการนี้ปิดหรือยกเลิกแล้ว ไม่สามารถดำเนินการได้')
        if not Ticket.objects.visible_to(actor).filter(pk=current.pk).exists():
            raise ValidationError('คุณไม่มีสิทธิ์เข้าถึงรายการนี้')
        pending = current.cancellation_requests.filter(status='PENDING').first()
        now = timezone.now()
        manager = is_soc_manager(actor)
        decision_note = decision_note.strip()

        if action in ('request', 'direct'):
            if pending:
                raise ValidationError('รายการนี้มีคำขอยกเลิกที่รออนุมัติอยู่แล้ว')
            if not can_request_cancellation(current, actor):
                raise ValidationError('เฉพาะผู้เปิดหรือผู้รับผิดชอบขั้นตอนปัจจุบันเท่านั้นที่ขอยกเลิกได้')
            if action == 'direct' and not can_cancel_directly(current, actor):
                raise ValidationError('รายการนี้ต้องได้รับอนุมัติยกเลิกจากผู้จัดการ SOC')
            explanation = explanation.strip()
            if reason not in dict(TicketCancellationRequest.REASON_CHOICES) or not explanation:
                raise ValidationError('กรุณาเลือกประเภทเหตุผลและกรอกรายละเอียดการยกเลิก')
            if reason == 'DUPLICATE':
                duplicate = Ticket.objects.visible_to(actor).filter(
                    pk=getattr(duplicate_of, 'pk', duplicate_of),
                ).exclude(pk=current.pk).exclude(status=Ticket.STATUS_CANCELLED).first()
                if duplicate is None:
                    raise ValidationError('กรุณาเลือกรายการต้นฉบับที่เข้าถึงได้และยังไม่ถูกยกเลิก')
                duplicate_of = duplicate
            else:
                duplicate_of = None
            record = TicketCancellationRequest.objects.create(
                ticket=current, requested_by=actor, reason=reason, explanation=explanation,
                duplicate_of=duplicate_of,
                mode=('MANAGER' if manager else 'CREATOR') if action == 'direct' else 'REVIEW',
            )
        else:
            if action not in ('approve', 'reject', 'withdraw'):
                raise ValidationError('ไม่พบการดำเนินการที่ระบุ')
            if pending is None or str(pending.pk) != str(request_id):
                raise ValidationError('คำขอนี้สิ้นสุดหรือมีการเปลี่ยนแปลงแล้ว กรุณาโหลดหน้าใหม่')
            record = pending
            if action == 'withdraw':
                if actor.pk != record.requested_by_id:
                    raise ValidationError('เฉพาะผู้ส่งคำขอเท่านั้นที่ถอนคำขอได้')
            elif not manager:
                raise ValidationError('เฉพาะผู้จัดการ SOC เท่านั้นที่พิจารณาคำขอยกเลิกได้')
            if action in ('approve', 'reject') and not decision_note:
                raise ValidationError('กรุณากรอกบันทึกการตัดสินใจ')

        if action in ('approve', 'direct'):
            # Revalidate the reference at decision time, after the review delay.
            if record.duplicate_of_id:
                try:
                    with transaction.atomic():
                        original = Ticket.objects.select_for_update(nowait=True).get(pk=record.duplicate_of_id)
                except DatabaseError:
                    raise ValidationError('รายการต้นฉบับกำลังถูกดำเนินการ กรุณาลองใหม่')
                if original.status == Ticket.STATUS_CANCELLED or not Ticket.objects.visible_to(actor).filter(pk=original.pk).exists():
                    raise ValidationError('รายการต้นฉบับถูกยกเลิกหรือเข้าถึงไม่ได้ กรุณาส่งคำขอใหม่')
            outstanding = list(current.subtasks.exclude(status__in=TicketSubtask.TERMINAL_STATUSES))
            try:
                selected = {int(value) for value in cancel_subtask_ids}
            except (TypeError, ValueError):
                raise ValidationError('รายการงานที่เลือกไม่ถูกต้อง')
            if selected != {task.pk for task in outstanding} or (outstanding and not manager):
                raise ValidationError('ต้องดำเนินงานค้างให้เสร็จ หรือให้ผู้จัดการเลือกยกเลิกงานค้างทุกรายการอย่างชัดเจน')
            for task in outstanding:
                from .history import record_subtask_status_change
                previous = task.status
                TicketSubtask.objects.filter(pk=task.pk).update(
                    status=TicketSubtask.STATUS_CANCELLED, status_changed_at=now, updated_at=now,
                )
                task.status = TicketSubtask.STATUS_CANCELLED
                record_subtask_status_change(task, previous, task.status, actor)
            record.cancelled_subtask_ids = sorted(selected)
            record.status = 'APPROVED'
            # Only this guarded operation writes CANCELLED. Model.save refuses it.
            Ticket.objects.filter(pk=current.pk).update(
                status=Ticket.STATUS_CANCELLED, closed_at=now, status_changed_at=now,
                updated_at=now, t2_claimed_by=None, t2_claimed_at=None,
            )
            current.status = Ticket.STATUS_CANCELLED
        elif action == 'reject':
            record.status = 'REJECTED'
        elif action == 'withdraw':
            record.status = 'WITHDRAWN'

        if action != 'request':
            record.decided_by = actor
            record.decided_at = now
            record.decision_note = decision_note or record.explanation
            record.save()
        label = {
            'request': 'ขอยกเลิกรายการ', 'direct': 'ยกเลิกรายการโดยตรง',
            'approve': 'อนุมัติยกเลิกรายการ', 'reject': 'ไม่อนุมัติยกเลิกรายการ',
            'withdraw': 'ถอนคำขอยกเลิกรายการ',
        }[action]
        duplicate_label = f' — รายการต้นฉบับ {record.duplicate_of.ticket_id}' if record.duplicate_of_id else ''
        TicketLog.objects.create(
            ticket=current, author=actor, status_at_time=current.status,
            note=f'{label}: {record.get_reason_display()} — {record.explanation}{duplicate_label}'
                 + (f'\nบันทึกการตัดสินใจ: {record.decision_note}' if record.decision_note else ''),
        )
        transaction.on_commit(partial(notify_ticket_cancellation, record.pk, action), robust=True)
    ticket.refresh_from_db()
    return record
