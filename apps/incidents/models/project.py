
from django.contrib.auth.models import User
from django.db import IntegrityError, models, transaction
from django.utils import timezone

def bundle_suffix_for_index(index):
    """Excel-style column label for a member's position in a bundle.

    0→A, 1→B, … 25→Z, 26→AA. Used to build the trackable child id
    ``<project_code>-<suffix>`` (e.g. PI-260706-01-C).
    """
    label = ''
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        label = chr(65 + rem) + label
    return label


class ProjectIncident(models.Model):
    """
    One multi-system security case worked as several linked tickets — one per
    affected system. Member tickets share the case facts but are independently
    classified: Events go to Tier 2 verification, while Incidents share the
    Project Review decision before entering their per-target handling routes.

    This is the "Case Bundling" grouping: the bundle counts as a single
    case/report, while its member tickets are verified or contained and closed
    independently. Members are reached via the
    ``member_tickets`` reverse relation and carry a stable, trackable id of the
    form ``<project_code>-<bundle_suffix>`` (see ``Ticket.bundle_ref``).
    """
    project_code = models.CharField(
        max_length=20, unique=True, editable=False, blank=True,
        verbose_name='รหัส Project Incident',
    )
    title = models.CharField(max_length=255, verbose_name='หัวข้อเหตุการณ์')
    summary = models.TextField(
        blank=True, default='', verbose_name='รายละเอียดโดยรวม',
    )
    # The manager rules Emergency once for the bundle's Incident members;
    # Event members bypass Project Review and never inherit reassessments.
    is_emergency = models.BooleanField(default=False, verbose_name='สถานะฉุกเฉิน')
    emergency_decided_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='emergency_assessed_projects',
        verbose_name='ผู้ประเมินสถานะฉุกเฉิน',
    )
    emergency_decided_at = models.DateTimeField(
        null=True, blank=True, verbose_name='เวลาประเมินสถานะฉุกเฉิน',
    )
    actions_taken_summary = models.TextField(
        blank=True, default='', verbose_name='สรุปเรื่องที่ดำเนินการแล้ว',
    )
    next_steps_summary = models.TextField(
        blank=True, default='', verbose_name='สรุปการดำเนินการลำดับถัดไป',
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='created_project_incidents', verbose_name='ผู้เปิดเหตุการณ์',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Project Incident (Case Bundle)'
        verbose_name_plural = 'Project Incidents (Case Bundles)'

    def __str__(self):
        return f'{self.project_code} — {self.title}'

    # How many times to regenerate project_code when a concurrent insert wins
    # the unique-constraint race before giving up.
    _CODE_MAX_RETRIES = 5

    def _assign_project_code(self):
        """Compute the next human-trackable code PI-YYMMDD-NN (NN = per-day
        sequence), mirroring the Ticket.ticket_id scheme so the two id spaces
        are visually distinct. The read-then-write here is racy on its own — see
        save() for the retry that closes the window against committed rows.
        """
        now = timezone.now()
        prefix = f'PI-{now.year % 100:02d}{now.month:02d}{now.day:02d}-'
        last = (
            ProjectIncident.objects.filter(project_code__startswith=prefix)
            .order_by('-project_code')
            .first()
        )
        if last:
            try:
                seq = int(last.project_code.rsplit('-', 1)[1]) + 1
            except (ValueError, IndexError):
                seq = 1
        else:
            seq = 1
        self.project_code = f'{prefix}{seq:02d}'
        while ProjectIncident.objects.filter(project_code=self.project_code).exists():
            seq += 1
            self.project_code = f'{prefix}{seq:02d}'

    def save(self, *args, **kwargs):
        # Already-coded rows (updates, or an explicit code) save straight through.
        if self.pk or (self.project_code and self.project_code.strip()):
            super().save(*args, **kwargs)
            return

        # New row needing a generated code: the per-day sequence is a
        # read-then-write, so two concurrent inserts on the same day can compute
        # the same NN and one INSERT then violates the unique constraint. Retry
        # with a freshly recomputed code; each attempt runs in a savepoint so the
        # failed INSERT doesn't poison the caller's surrounding transaction, and
        # the recompute sees the committed winner (READ COMMITTED).
        for attempt in range(self._CODE_MAX_RETRIES):
            self._assign_project_code()
            try:
                with transaction.atomic():
                    super().save(*args, **kwargs)
                return
            except IntegrityError:
                if attempt == self._CODE_MAX_RETRIES - 1:
                    raise

    # ── Rollup helpers (grouping only — members keep their own lifecycle) ─ #
    @property
    def members(self):
        """Member tickets ordered by bundle suffix (A, B, C …)."""
        return self.member_tickets.order_by('bundle_suffix', 'created_at')

    @property
    def member_count(self):
        return self.member_tickets.count()

    @property
    def open_member_count(self):
        return self.member_tickets.exclude(status__in=Ticket.TERMINAL_STATUSES).count()

    @property
    def all_closed(self):
        total = self.member_count
        return total > 0 and self.open_member_count == 0

    @property
    def cancelled_member_count(self):
        return self.member_tickets.filter(status=Ticket.STATUS_CANCELLED).count()

    @property
    def resolved_member_count(self):
        return self.member_tickets.filter(status=Ticket.STATUS_APPROVED).count()

    @property
    def event_closed_member_count(self):
        return self.member_tickets.filter(status=Ticket.STATUS_CLOSED_EVENT).count()


class ProjectIncidentLog(models.Model):
    """Audit history for group-level coordination decisions."""

    project = models.ForeignKey(
        ProjectIncident, on_delete=models.CASCADE, related_name='logs',
    )
    note = models.TextField(verbose_name='บันทึกรายละเอียด')
    created_at = models.DateTimeField(auto_now_add=True)
    author = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='project_incident_logs',
    )

    class Meta:
        ordering = ['-created_at']


def project_attachment_upload_path(instance, filename):
    return f'project_attachments/{instance.project.project_code}/{filename}'


class ProjectIncidentAttachmentQuerySet(models.QuerySet):
    def active(self):
        return self.filter(deleted_at__isnull=True)


class ProjectIncidentAttachmentManager(
    models.Manager.from_queryset(ProjectIncidentAttachmentQuerySet)
):
    """Default manager: operational views never expose removed evidence."""

    def get_queryset(self):
        return super().get_queryset().active()


class ProjectIncidentAttachment(models.Model):
    """Evidence shared by every member of a Project Incident.

    Same lifecycle as TicketAttachment — including the soft delete, so group
    evidence removed by mistake is recoverable by a SOC Manager rather than
    gone. The two are kept deliberately symmetrical; see the ticket model
    below for the reasoning behind each field.
    """

    objects = ProjectIncidentAttachmentManager()
    all_objects = models.Manager()

    project = models.ForeignKey(
        ProjectIncident, on_delete=models.CASCADE, related_name='attachments',
    )
    file = models.FileField(upload_to=project_attachment_upload_path)
    original_name = models.CharField(max_length=255)
    description = models.CharField(max_length=255, blank=True, default='')
    uploaded_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='uploaded_project_attachments',
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    deleted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='deleted_project_attachments',
    )
    deleted_at = models.DateTimeField(null=True, blank=True)
    # Mandatory at the view layer, not the model — same as TicketAttachment, so
    # rows created before this field existed stay valid.
    deleted_reason = models.CharField(max_length=255, blank=True, default='')

    class Meta:
        ordering = ['uploaded_at']

    @property
    def preview_kind(self):
        """'image', 'text', or '' — same inline-preview rule as TicketAttachment.
        Imported lazily: attachments.py imports Ticket, which imports this module
        at class-definition time, so a top-level import here would be circular."""
        from .attachments import preview_kind_for
        return preview_kind_for(self.original_name)


# Late import to avoid a circular dependency: Ticket imports ProjectIncident at
# class-definition time, while ProjectIncident only needs Ticket at call time.
from .ticket import Ticket  # noqa: E402,F401
