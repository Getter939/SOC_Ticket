
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone

from .ticket import Ticket

# ======================================================================= #
# Sub-tasks (Investigation / Countermeasure)                               #
# ======================================================================= #

class TicketSubtask(models.Model):
    """
    A linked sub-task spawned from an Incident ticket, modelled after RTIR's
    Investigation / Countermeasure linked tickets — lets parallel work
    streams (e.g. "block this IP" and "dig into the logs") be tracked
    independently of the parent ticket's main status.
    """

    # RETIRED legacy intra-SOC note types. No form or view creates these any
    # more (the create path was removed); the two values and their labels are
    # kept only so pre-existing historical rows still render a friendly name via
    # get_subtask_type_display. They route nowhere and gate nothing.
    TYPE_INVESTIGATION = 'INVESTIGATION'
    TYPE_COUNTERMEASURE = 'COUNTERMEASURE'
    # Response-team request types — spawned by the SOC Manager and routed by
    # type to a response-team role (see RESPONSE_ROUTING). Unlike the two legacy
    # types above, an open request of these types blocks the parent Incident
    # from being APPROVED (see Ticket.has_open_response_requests).
    TYPE_VA = 'VA'
    TYPE_PENTEST = 'PENTEST'
    TYPE_HARDENING = 'HARDENING'
    # Historical values remain readable for completed requests.
    TYPE_VA_PT = 'VA_PT'
    TYPE_INFRA_SEC = 'INFRA_SEC'
    TYPE_FORENSIC_RCA = 'FORENSIC_RCA'

    TYPE_CHOICES = [
        (TYPE_INVESTIGATION, 'การสืบสวน'),
        (TYPE_COUNTERMEASURE, 'มาตรการตอบโต้'),
        (TYPE_VA, 'ประเมินช่องโหว่ (VA)'),
        (TYPE_PENTEST, 'ทดสอบเจาะระบบ (PenTest)'),
        (TYPE_HARDENING, 'ปรับความมั่นคงปลอดภัย (Hardening)'),
        (TYPE_FORENSIC_RCA, 'Forensics / RCA'),
        (TYPE_VA_PT, 'VA/PT (เดิม)'),
        (TYPE_INFRA_SEC, 'Hardening (เดิม)'),
    ]

    # Request types that route to a response team and gate final approval.
    NEW_RESPONSE_TYPES = frozenset({TYPE_VA, TYPE_PENTEST, TYPE_HARDENING, TYPE_FORENSIC_RCA})
    RESPONSE_TYPES = NEW_RESPONSE_TYPES | frozenset({TYPE_VA_PT, TYPE_INFRA_SEC})
    REDTEAM_FUNCTIONS = {
        TYPE_VA: 'VA',
        TYPE_PENTEST: 'PENTEST',
        TYPE_HARDENING: 'HARDENING',
    }
    REPORT_PREFIXES = {
        TYPE_VA: 'VA',
        TYPE_PENTEST: 'PT',
        TYPE_HARDENING: 'BL',
    }

    STATUS_OPEN = 'OPEN'
    STATUS_IN_PROGRESS = 'IN_PROGRESS'
    STATUS_DONE = 'DONE'
    STATUS_CANCELLED = 'CANCELLED'
    TERMINAL_STATUSES = frozenset({STATUS_DONE, STATUS_CANCELLED})

    STATUS_CHOICES = [
        (STATUS_OPEN, 'เปิด'),
        (STATUS_IN_PROGRESS, 'กำลังดำเนินการ'),
        (STATUS_DONE, 'เสร็จสิ้น'),
        (STATUS_CANCELLED, 'ยกเลิกแล้ว'),
    ]

    ticket = models.ForeignKey(
        Ticket, on_delete=models.CASCADE, related_name='subtasks',
        verbose_name='Ticket หลัก',
    )
    subtask_type = models.CharField(
        max_length=20, choices=TYPE_CHOICES, verbose_name='ประเภท',
    )
    title = models.CharField(max_length=255, verbose_name='หัวข้อ')
    description = models.TextField(blank=True, default='', verbose_name='รายละเอียด')
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN, verbose_name='สถานะ',
    )
    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket_subtasks', verbose_name='ผู้รับผิดชอบ',
    )
    result_notes = models.TextField(blank=True, default='', verbose_name='ผลการดำเนินการ')
    # The number of the report the responder delivered (the RCA report is a
    # physical document the SOC Manager collects). Mandatory when any response
    # request is marked DONE — see SubtaskUpdateForm.
    report_number = models.CharField(
        max_length=40, blank=True, default='', verbose_name='เลขที่รายงาน',
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='created_subtasks', verbose_name='ผู้สร้าง',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # Unlike updated_at (which also changes for notes and attachments), this
    # identifies exactly when the task entered its current status.
    status_changed_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่อัปเดตสถานะ',
    )

    class Meta:
        ordering = ['-created_at']

    @classmethod
    def from_db(cls, db, field_names, values):
        """Remember the stored status so ``save`` can spot a real transition.

        Cheaper than re-reading the row in save(), and it makes the stamp a
        property of the model rather than of one view.
        """
        instance = super().from_db(db, field_names, values)
        if 'status' in field_names:
            instance._loaded_status = instance.status
        return instance

    def save(self, *args, **kwargs):
        with transaction.atomic():
            parent = Ticket.objects.select_for_update().get(pk=self.ticket_id)
            if parent.status == Ticket.STATUS_CANCELLED or self.status == self.STATUS_CANCELLED:
                raise ValidationError('งานนี้ยกเลิกได้ผ่านขั้นตอนยกเลิกรายการโดยผู้จัดการ SOC เท่านั้น')
            return self._save_subtask(*args, **kwargs)

    def _save_subtask(self, *args, **kwargs):
        """Stamp ``status_changed_at`` whenever the status actually moves.

        This lives in save(), not in ``update_subtask``, so admin edits, seeds,
        data migrations and any future write path stamp it too — a view-only
        stamp silently skips all of them and leaves the per-task age wrong.
        Notes and attachment updates deliberately do NOT bump it; that is the
        whole reason this field exists alongside ``updated_at``.
        """
        loaded_status = getattr(self, '_loaded_status', None)
        is_new = not self.pk
        if is_new:
            if self.status_changed_at is None:
                self.status_changed_at = timezone.now()
        elif loaded_status is not None and loaded_status != self.status:
            self.status_changed_at = timezone.now()
            # An update_fields save must be told about the extra column or the
            # stamp is computed and then silently dropped.
            update_fields = kwargs.get('update_fields')
            if update_fields is not None:
                kwargs['update_fields'] = set(update_fields) | {'status_changed_at'}
        result = super().save(*args, **kwargs)
        self._loaded_status = self.status
        return result

    def __str__(self):
        return f'[{self.get_subtask_type_display()}] {self.title} ({self.ticket.ticket_id})'

    @property
    def is_done(self):
        return self.status == self.STATUS_DONE

    @property
    def is_response_request(self):
        """True for a current or historical response-team request."""
        return self.subtask_type in self.RESPONSE_TYPES

    # Report kind per response type — the token in its report number
    # (reports.REPORT_KIND_TOKENS): SOC-RCA- / SOC-VAPT- / SOC-HARD-YYYYMM-NNNN.
    REPORT_KINDS = {
        TYPE_FORENSIC_RCA: 'RCA',
        TYPE_VA_PT: 'VAPT',
        TYPE_INFRA_SEC: 'HARD',
    }

    @property
    def requires_report_number(self):
        """No response request can be marked DONE without the number of the
        report the responder delivered."""
        return self.is_response_request

    @property
    def uses_manual_report_number(self):
        return self.subtask_type in self.REDTEAM_FUNCTIONS

    @property
    def expected_report_number(self):
        """FA's suggested number or a format hint for a Red Team request."""
        prefix = self.REPORT_PREFIXES.get(self.subtask_type)
        if prefix:
            return f'{prefix}-YYYY-NNNN'
        kind = self.REPORT_KINDS.get(self.subtask_type)
        if not kind:
            return ''
        from ..reports import _report_ticket_id
        return _report_ticket_id(self.ticket, kind=kind)

    @classmethod
    def response_routing(cls):
        """Map each response-request type → the role that receives it.

        Lazily imports UserProfile so the routing always references the
        canonical role constants (no drift) without a circular import at
        module load. Three current Red Team types share one role but are
        separated by profile function; Forensics/RCA goes to the Forensic Analyst.
        """
        from apps.accounts.models import UserProfile
        return {
            cls.TYPE_VA:           UserProfile.ROLE_REDTEAM_MANAGER,
            cls.TYPE_PENTEST:      UserProfile.ROLE_REDTEAM_MANAGER,
            cls.TYPE_HARDENING:    UserProfile.ROLE_REDTEAM_MANAGER,
            cls.TYPE_VA_PT:        UserProfile.ROLE_REDTEAM_MANAGER,
            cls.TYPE_INFRA_SEC:    UserProfile.ROLE_REDTEAM_MANAGER,
            cls.TYPE_FORENSIC_RCA: UserProfile.ROLE_FORENSIC,
        }

    @classmethod
    def role_for_type(cls, subtask_type):
        """The response-team role that owns ``subtask_type``, or None."""
        return cls.response_routing().get(subtask_type)

    @classmethod
    def types_for_role(cls, role):
        """The response-request types a given role may be handed.

        Inverse of ``response_routing()`` — derived from it rather than written
        out again, so there is still exactly one routing map to keep correct.
        Returns an empty frozenset for any role that owns no response type
        (SOC, admins, owners, executives, blank roles), which makes it safe to
        drop straight into a ``subtask_type__in=`` filter: an unknown role
        matches nothing rather than everything.
        """
        return frozenset(t for t, r in cls.response_routing().items() if r == role)

    @classmethod
    def types_for_profile(cls, profile):
        """Types a responder may see, including their own historical requests."""
        if profile.is_forensic:
            return frozenset({cls.TYPE_FORENSIC_RCA})
        if profile.is_redteam_manager:
            current = frozenset(
                t for t, function in cls.REDTEAM_FUNCTIONS.items()
                if function == profile.redteam_function
            )
            return current | frozenset({cls.TYPE_VA_PT, cls.TYPE_INFRA_SEC})
        return frozenset()

    @classmethod
    def eligible_assignees(cls, subtask_type):
        """Active users who may be auto-assigned a request of ``subtask_type``.

        Returns an empty queryset for the non-response (legacy) types. The
        spawn flow auto-assigns when exactly one exists, offers a picker when
        several do, and blocks the spawn when none exist.
        """
        role = cls.role_for_type(subtask_type)
        if not role:
            return User.objects.none()
        eligible = User.objects.filter(is_active=True, profile__role=role)
        function = cls.REDTEAM_FUNCTIONS.get(subtask_type)
        if function:
            eligible = eligible.filter(profile__redteam_function=function)
        return eligible

    def clean(self):
        """Reject a response request handed to someone the type doesn't route to.

        The routing invariant (VA/PT + InfraSec → Red Team Manager, Forensics/RCA
        → Forensic Analyst) used to live only in ``create_response_request``. That
        left every other write path — Django admin, seed commands, data migrations
        — free to produce a mismatched row, which would then surface in the wrong
        person's queue AND unlock the parent ticket through
        ``TicketQuerySet.visible_to()``.

        This is the write-time half of the fix. It runs through ``full_clean()``,
        so it covers ModelForms and the admin but NOT a bare
        ``TicketSubtask.objects.create()`` — the read-time filters in
        ``visible_to()`` and ``response_request_queue`` are what make the
        invariant hold even then. Both layers are deliberate; neither is
        redundant.

        Legacy Investigation/Countermeasure subtasks route nowhere and keep their
        existing freedom (``SubtaskForm`` already excludes response-team users).
        """
        super().clean()
        if self.subtask_type not in self.RESPONSE_TYPES or self.assigned_to_id is None:
            return
        expected_role = self.role_for_type(self.subtask_type)
        profile = getattr(self.assigned_to, 'profile', None)
        # No profile → fail closed, matching visible_to()'s treatment of the
        # profile-less account that can exist between creation and setup.
        function = self.REDTEAM_FUNCTIONS.get(self.subtask_type)
        if (
            profile is None or profile.role != expected_role
            or (function and profile.redteam_function != function)
        ):
            raise ValidationError({
                'assigned_to': (
                    f'คำขอประเภท "{self.get_subtask_type_display()}" '
                    f'ต้องมอบหมายให้ผู้ที่มีบทบาท "{expected_role}" เท่านั้น'
                )
            })
