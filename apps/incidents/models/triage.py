
from django.contrib.auth.models import User
from django.db import models

from .ticket import Ticket
from .choices import (
    SOURCE_CHOICES,
)

# ======================================================================= #
# Pre-ticket triage                                                        #
# ======================================================================= #

class TriageRecord(models.Model):
    """
    A report that arrived through a NON-SIEM channel (phone, email, TI, user
    report, external org), logged before anyone decides whether it deserves a
    ticket. SIEM alerts have their own queue — see wazuh_ingest.WazuhAlert.

    Why the record exists at all: a Ticket consumes an id and starts its OLA
    clocks the moment it is saved, so turning every phone call straight into a
    ticket would pollute ticket numbering, the OLA figures and the reporting
    mart with junk. This is the buffer in front of that, plus the claim
    discipline that stops two analysts working the same report across a shift.

    Lifecycle (Tier 1 only, surfaced in My Queue):
      logged → claimed → either
        • converted   — becomes a Ticket or a ProjectIncident bundle, decision
                        stamped TP (Incident) or FP (Event), linked via the
                        ``ticket`` / ``project_incident`` FKs; or
        • dismissed   — junk, decision stamped FP with NO ticket; or
        • released    — handed back to the queue with a reason.
      Either disposal stamps ``resolved_by`` / ``resolved_at``.

    RETIRED (do not build on these): ``DECISION_ESCALATED`` and the four
    ``escalated_to`` / ``t2_*`` fields belonged to a pre-ticket Tier 2
    escalation step that no longer exists — the Event/Incident and escalation
    decisions now live on the Ticket. Nothing writes them any more; they are
    kept, read-only in the admin, so legacy rows stay readable and searchable.
    """

    DECISION_FP        = 'FP'
    DECISION_TP        = 'TP'
    DECISION_ESCALATED = 'ESCALATED'

    # Source vocabulary is shared with Ticket.issue_type — the field below uses
    # the module-level SOURCE_CHOICES. These class constants are kept as aliases
    # for code that references TriageRecord.SOURCE_* (tests, seeders, views).
    SOURCE_SIEM        = 'SIEM'
    SOURCE_ADMIN       = 'ADMIN'
    SOURCE_TI          = 'TI'
    SOURCE_EMAIL       = 'EMAIL'
    SOURCE_PHONE       = 'PHONE'
    SOURCE_USER_REPORT = 'USER_REPORT'
    SOURCE_EXTERNAL    = 'EXTERNAL'
    SOURCE_OTHER       = 'OTHER'

    T1_DECISION_CHOICES = [
        (DECISION_FP,        'Event — ปิดเคส'),
        (DECISION_TP,        'Incident — สร้าง Ticket'),
        (DECISION_ESCALATED, 'ส่งต่อให้ Tier 2 (ข้อมูลเดิม)'),
    ]

    T2_DECISION_CHOICES = [
        (DECISION_FP, 'Event — ปิดเคส'),
        (DECISION_TP, 'Incident — สร้าง Ticket'),
    ]

    # ── T1 fields ──────────────────────────────────────────────────── #
    source = models.CharField(
        max_length=20, choices=SOURCE_CHOICES, default=SOURCE_OTHER,
        verbose_name='แหล่งที่มาของ Alert',
    )
    source_reference = models.CharField(
        max_length=100, blank=True, default='',
        verbose_name='รหัสอ้างอิงจากแหล่งที่มา',
    )
    analyst = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='triage_records', verbose_name='นักวิเคราะห์ T1',
    )
    alert_description = models.TextField(verbose_name='รายละเอียด Alert')
    source_ip = models.CharField(
        max_length=50, blank=True, default='', verbose_name='IP Source',
    )
    decision = models.CharField(
        max_length=20, choices=T1_DECISION_CHOICES, blank=True, default='',
        verbose_name='ผลลัพธ์เดิมของ Manual Triage',
    )
    notes = models.TextField(blank=True, default='', verbose_name='บันทึก T1')
    created_at = models.DateTimeField(auto_now_add=True)

    # Manual triage is an intake queue. Classification and routing happen only
    # after a claimed item is turned into a Ticket.
    claimed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='claimed_manual_triages', verbose_name='ผู้รับรายการ Manual Triage',
    )
    claimed_at = models.DateTimeField(null=True, blank=True)
    release_reason = models.TextField(blank=True, default='', verbose_name='เหตุผลที่คืนคิว')

    # Who disposed of this record, and when. Set on BOTH outcomes — converted
    # to a ticket/bundle, or dismissed as junk — because ``claimed_by`` is
    # cleared at that same moment. Without this the handler is unrecoverable:
    # a conversion could be traced through ticket.created_by, but a dismissal
    # left nothing but a free-text line in ``notes``, so a report could be
    # thrown away with no accountable owner.
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='resolved_manual_triages', verbose_name='ผู้ดำเนินการ',
    )
    resolved_at = models.DateTimeField(null=True, blank=True)

    # ── T2 escalation fields ───────────────────────────────────────── #
    escalated_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='escalated_triages', verbose_name='Escalate ไปยัง T2',
    )
    t2_decision = models.CharField(
        max_length=20, choices=T2_DECISION_CHOICES,
        blank=True, default='', verbose_name='การตัดสินใจ T2',
    )
    t2_notes = models.TextField(blank=True, default='', verbose_name='บันทึก T2')
    t2_decided_at = models.DateTimeField(null=True, blank=True)

    # ── Linked ticket (if TP) ──────────────────────────────────────── #
    ticket = models.OneToOneField(
        Ticket, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='triage', verbose_name='Ticket ที่สร้าง',
    )

    # Set when this record is turned into a multi-system Project Incident (case
    # bundle) instead of a single ticket. Mirrors WazuhAlert.project_incident:
    # the record points at the whole bundle, and the ``ticket`` OneToOne stays
    # null. Either link marks the record consumed (see
    # policies.can_create_ticket_from_triage).
    project_incident = models.ForeignKey(
        'ProjectIncident', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='source_triages', verbose_name='Project Incident (Case Bundle)',
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        analyst_name = self.analyst.username if self.analyst else '?'
        return f'Triage #{self.pk} by {analyst_name} — {self.decision}'

    @property
    def final_decision(self):
        """Resolved decision: T2's if escalated, else T1's.

        Only legacy rows can be ESCALATED (see the class docstring), but this
        stays live: policies.can_create_ticket_from_triage still uses it so an old
        escalated record can be converted rather than stranded.
        """
        if self.decision == self.DECISION_ESCALATED:
            return self.t2_decision or 'PENDING'
        return self.decision
