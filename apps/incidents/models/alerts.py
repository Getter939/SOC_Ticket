
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models

from .ticket import Ticket

class TicketAlertLink(models.Model):
    """One Wazuh alert retained as evidence for a ticket.

    ``Ticket.wazuh_alert`` remains the primary-alert compatibility pointer for
    existing single-alert code. Every alert, including that primary one, also
    has exactly one link so supporting alerts cannot be attached elsewhere.
    """

    ROLE_PRIMARY = 'PRIMARY'
    ROLE_SUPPORTING = 'SUPPORTING'
    ROLE_CHOICES = [
        (ROLE_PRIMARY, 'การแจ้งเตือนหลัก'),
        (ROLE_SUPPORTING, 'การแจ้งเตือนประกอบ'),
    ]

    ticket = models.ForeignKey(
        Ticket, on_delete=models.CASCADE, related_name='alert_links',
    )
    alert = models.OneToOneField(
        'wazuh_ingest.WazuhAlert', on_delete=models.CASCADE,
        related_name='ticket_alert_link',
    )
    role = models.CharField(max_length=12, choices=ROLE_CHOICES)
    linked_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket_alert_links',
    )
    linked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['ticket'], condition=models.Q(role='PRIMARY'),
                name='one_primary_alert_per_ticket',
            ),
        ]
        # Explicit weight, NOT ordering on ``role`` itself: role is a CharField,
        # so ordering on it is alphabetical and only puts PRIMARY first because
        # 'PRIMARY' < 'SUPPORTING' happens to be true. A third role would break
        # that silently — the same trap the Tier 2 queue's severity sort fell
        # into. Ordering on the weight says what is meant.
        # 'PRIMARY' spelled out, not ROLE_PRIMARY: a nested Meta cannot see the
        # enclosing class's attributes. Same reason the UniqueConstraint above
        # uses the literal.
        ordering = [
            models.Case(
                models.When(role='PRIMARY', then=models.Value(0)),
                default=models.Value(1),
                output_field=models.IntegerField(),
            ),
            'alert__timestamp',
            'alert_id',
        ]

    def __str__(self):
        return f'{self.ticket.ticket_id} ← alert #{self.alert_id} ({self.role})'

    def clean(self):
        """Keep the PRIMARY link and ``Ticket.wazuh_alert`` from drifting apart.

        The primary alert is recorded twice — once as the ticket's own
        ``wazuh_alert`` pointer (which single-alert code still reads) and once as
        the PRIMARY link. Nothing at the database level can tie the two together,
        so a write that sets only one leaves the ticket claiming two different
        primary alerts. Rejecting the mismatch here is the write-time half; the
        creation path in ``create_ticket`` derives the role from
        ``ticket.wazuh_alert_id`` so it cannot produce one.
        """
        super().clean()
        if self.role != self.ROLE_PRIMARY or self.ticket_id is None:
            return
        if self.alert_id != self.ticket.wazuh_alert_id:
            raise ValidationError({
                'alert': (
                    'Primary alert link must match the ticket\'s wazuh_alert '
                    f'(link #{self.alert_id} vs ticket #{self.ticket.wazuh_alert_id}).'
                ),
            })


class TicketCancellationRequest(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'รออนุมัติ'), ('APPROVED', 'อนุมัติยกเลิกแล้ว'),
        ('REJECTED', 'ไม่อนุมัติ'), ('WITHDRAWN', 'ถอนคำขอแล้ว'),
        ('SUPERSEDED', 'สิ้นสุดคำขอเนื่องจากรายการปิดแล้ว'),
    ]
    REASON_CHOICES = [
        ('DUPLICATE', 'รายการซ้ำ'), ('CREATED_IN_ERROR', 'สร้างรายการผิด'),
        ('OTHER', 'เหตุผลอื่น'),
    ]
    MODE_CHOICES = [
        ('REVIEW', 'ผู้จัดการพิจารณาคำขอ'), ('CREATOR', 'ผู้เปิดยกเลิกรายการใหม่'),
        ('MANAGER', 'ผู้จัดการยกเลิกโดยตรง'),
    ]
    ticket = models.ForeignKey(Ticket, verbose_name='รายการ', on_delete=models.PROTECT, related_name='cancellation_requests')
    requested_by = models.ForeignKey(User, verbose_name='ผู้ขอ', on_delete=models.SET_NULL, null=True, related_name='+')
    reason = models.CharField('ประเภทเหตุผล', max_length=24, choices=REASON_CHOICES)
    explanation = models.TextField('รายละเอียดเหตุผล')
    duplicate_of = models.ForeignKey(Ticket, verbose_name='รายการต้นฉบับ', on_delete=models.PROTECT, null=True, blank=True, related_name='+')
    status = models.CharField('สถานะคำขอ', max_length=16, choices=STATUS_CHOICES, default='PENDING')
    mode = models.CharField('วิธีอนุมัติ', max_length=12, choices=MODE_CHOICES, default='REVIEW')
    requested_at = models.DateTimeField('วันที่ขอ', auto_now_add=True)
    decided_by = models.ForeignKey(User, verbose_name='ผู้ตัดสินใจ', on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    decided_at = models.DateTimeField('วันที่ตัดสินใจ', null=True, blank=True)
    decision_note = models.TextField('บันทึกการตัดสินใจ', blank=True)
    cancelled_subtask_ids = models.JSONField('งานย่อยที่ยกเลิก', default=list, blank=True)

    class Meta:
        ordering = ['-requested_at', '-pk']
        verbose_name = 'คำขอยกเลิกรายการ'
        verbose_name_plural = 'คำขอยกเลิกรายการ'
        constraints = [
            models.UniqueConstraint(fields=['ticket'], condition=models.Q(status='PENDING'),
                                    name='one_pending_ticket_cancellation'),
            models.CheckConstraint(condition=~models.Q(ticket=models.F('duplicate_of')),
                                   name='cancellation_duplicate_not_self'),
        ]
