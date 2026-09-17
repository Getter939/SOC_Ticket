
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models

from .ticket import Ticket
from .subtask import TicketSubtask
from .ioc import AnalystIOC

# ======================================================================= #
# Root Cause Analysis report (Forensic Analyst deliverable)                #
# ======================================================================= #

class RCAReport(models.Model):
    """The structured half of a Forensics / RCA request's report.

    One per FORENSIC_RCA request. Holds what the report needs as *data* —
    Section 1 (prefilled from the ticket, then the analyst's to correct) and,
    through the child tables below, the affected assets (4), timeline (5), root
    causes (6.2), indicators (7) and remediation list (8). The narrative sections
    are written in Word on the generated draft, never here (apps.incidents.rca).

    Deliberately not on Ticket: the ticket's report_* fields are the single
    provenance slot of the Incident/Event report, and an RCA draft must never
    overwrite them. The draft's own provenance lives in the draft_* fields.
    """

    IMPORTANCE_GENERAL = 'general'
    IMPORTANCE_IMPORTANT = 'important'
    IMPORTANCE_CRITICAL = 'critical'
    IMPORTANCE_CHOICES = [
        (IMPORTANCE_GENERAL, 'ปกติทั่วไป'),
        (IMPORTANCE_IMPORTANT, 'สำคัญ'),
        (IMPORTANCE_CRITICAL, 'สำคัญมาก'),
    ]
    # The RCA form's SIEM scale says Moderate where the ticket says Medium.
    SIEM_SEVERITY_CHOICES = [
        ('Low', 'Low'),
        ('Moderate', 'Moderate'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]
    FORENSIC_TYPE_CHOICES = [
        ('host_disk', 'Host / Disk Triage'),
        ('log_timeline', 'Log & Timeline Analysis'),
        ('malware', 'Malware Analysis'),
        ('memory', 'Memory Forensic'),
        ('network', 'Network Forensic'),
    ]

    subtask = models.OneToOneField(
        TicketSubtask, on_delete=models.CASCADE, related_name='rca',
        verbose_name='คำขอ Forensics / RCA',
    )
    # ── Section 1 — prefilled from the ticket, then edited by the analyst ─ #
    incident_name = models.CharField(max_length=255, blank=True, default='', verbose_name='ชื่อเหตุการณ์')
    first_occurrence = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่/เวลา ที่เกิดเหตุครั้งแรก',
    )
    # The "(ยืนยันได้)" nuance of the old free-text field lives here now: an
    # optional note for an approximate or unconfirmable first-occurrence time.
    first_occurrence_note = models.CharField(
        max_length=255, blank=True, default='',
        verbose_name='หมายเหตุเวลาที่เกิดเหตุ (เช่น โดยประมาณ/ยืนยันไม่ได้)',
    )
    detected_at = models.DateTimeField(null=True, blank=True, verbose_name='วันที่/เวลา ที่ตรวจพบ')
    scope_start = models.DateTimeField(
        null=True, blank=True, verbose_name='ช่วงเวลาที่ตรวจพิสูจน์ — เริ่ม',
    )
    scope_end = models.DateTimeField(
        null=True, blank=True, verbose_name='ช่วงเวลาที่ตรวจพิสูจน์ — ถึง',
    )
    # List of FORENSIC_TYPE_CHOICES keys.
    forensic_types = models.JSONField(default=list, blank=True, verbose_name='ประเภทการตรวจพิสูจน์')
    importance = models.CharField(
        max_length=20, choices=IMPORTANCE_CHOICES, blank=True, default='',
        verbose_name='ระดับความสำคัญ',
    )
    siem_severity = models.CharField(
        max_length=20, choices=SIEM_SEVERITY_CHOICES, blank=True, default='',
        verbose_name='ระดับความรุนแรง (อ้างอิงตามระบบ SIEM)',
    )
    ncsa_severity = models.CharField(
        max_length=20, choices=Ticket.NCSA_SEVERITY_CHOICES, blank=True, default='',
        verbose_name='ระดับความรุนแรง (อ้างอิงตาม สกมช.)',
    )
    threat_category = models.CharField(
        max_length=50, choices=Ticket.DETAILED_ISSUE_CHOICES, blank=True, default='',
        verbose_name='หมวดหมู่ของภัยคุกคามทางไซเบอร์',
    )
    assets_examined = models.TextField(blank=True, default='', verbose_name='ทรัพย์สินที่นำเข้าตรวจพิสูจน์')
    asset_type = models.CharField(
        max_length=50, choices=Ticket.ASSET_TYPE_CHOICES, blank=True, default='',
        verbose_name='ประเภททรัพย์สิน',
    )
    affected_systems = models.TextField(blank=True, default='', verbose_name='ระบบ/บริการที่ได้รับผลกระทบ')
    asset_owner = models.TextField(blank=True, default='', verbose_name='ส่วนงานเจ้าของหรือผู้ดูแลทรัพย์สิน')
    examiner = models.CharField(max_length=255, blank=True, default='', verbose_name='ผู้ตรวจพิสูจน์')
    related_refs = models.TextField(blank=True, default='', verbose_name='เลขอ้างอิงที่เกี่ยวข้อง')
    # ── Provenance of the last generated DOCX draft ──────────────────────── #
    draft_generated_at = models.DateTimeField(null=True, blank=True)
    draft_generated_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+',
    )
    draft_sha256 = models.CharField(max_length=64, blank=True, default='')
    draft_template_version = models.CharField(max_length=20, blank=True, default='')
    # updated_at is bumped explicitly by every RCA write path (rca.record_edit),
    # including edits that only touch the child tables, so the stale-draft
    # notice sees them.
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+',
    )

    def __str__(self):
        return f'RCA — {self.subtask}'

    def clean(self):
        super().clean()
        known = {key for key, _ in self.FORENSIC_TYPE_CHOICES}
        unknown = [key for key in (self.forensic_types or []) if key not in known]
        if unknown:
            raise ValidationError({'forensic_types': f'ไม่รู้จักประเภท: {", ".join(unknown)}'})

    @property
    def has_stale_draft(self):
        """True once the data changed after the last draft was generated."""
        return bool(
            self.draft_generated_at and self.updated_at
            and self.updated_at > self.draft_generated_at
        )


class RCAAsset(models.Model):
    """Section 4 — one affected host/account row."""

    rca = models.ForeignKey(RCAReport, on_delete=models.CASCADE, related_name='assets')
    order = models.PositiveIntegerField(default=0)
    host = models.CharField(max_length=255, verbose_name='เครื่อง')
    ip = models.CharField(max_length=255, blank=True, default='', verbose_name='IP Address')
    detail = models.TextField(blank=True, default='', verbose_name='ระบบปฏิบัติการ / รายละเอียด')

    class Meta:
        ordering = ['order', 'pk']


class RCATimelineEntry(models.Model):
    """Section 5 — one row of the consolidated timeline (UTC+7)."""

    rca = models.ForeignKey(RCAReport, on_delete=models.CASCADE, related_name='timeline')
    occurred_at = models.DateTimeField(verbose_name='วัน/เวลา')
    # Set for a span such as a brute-force burst (16:27–16:38).
    occurred_until = models.DateTimeField(null=True, blank=True, verbose_name='ถึงเวลา')
    host = models.CharField(max_length=255, blank=True, default='', verbose_name='เครื่อง')
    event = models.TextField(verbose_name='เหตุการณ์')
    evidence_file = models.CharField(max_length=255, blank=True, default='', verbose_name='ไฟล์หลักฐาน')
    evidence_line = models.CharField(max_length=64, blank=True, default='', verbose_name='บรรทัด')
    excerpt = models.TextField(blank=True, default='', verbose_name='ตัวอย่างจากไฟล์หลักฐาน')

    class Meta:
        ordering = ['occurred_at', 'pk']

    def clean(self):
        super().clean()
        if self.occurred_until and self.occurred_at and self.occurred_until < self.occurred_at:
            raise ValidationError({'occurred_until': 'เวลาสิ้นสุดต้องไม่ก่อนเวลาเริ่ม'})


class RCARootCause(models.Model):
    """Section 6.2 — one root cause or contributing factor. Its RC-n code is
    derived from its position at render time, so reordering never leaves a
    recommendation pointing at a stale code."""

    rca = models.ForeignKey(RCAReport, on_delete=models.CASCADE, related_name='root_causes')
    order = models.PositiveIntegerField(default=0)
    category = models.CharField(max_length=100, blank=True, default='', verbose_name='ประเภท')
    cause = models.TextField(verbose_name='สาเหตุ')
    evidence_ref = models.TextField(blank=True, default='', verbose_name='ไฟล์หลักฐาน / Event ID / บรรทัด')
    excerpt = models.TextField(blank=True, default='', verbose_name='ตัวอย่างจากไฟล์หลักฐาน')

    class Meta:
        ordering = ['order', 'pk']


class RCARecommendation(models.Model):
    """Section 8 — one remediation action, tied to the root causes it fixes."""

    rca = models.ForeignKey(RCAReport, on_delete=models.CASCADE, related_name='recommendations')
    order = models.PositiveIntegerField(default=0)
    action = models.TextField(verbose_name='สิ่งที่ควรดำเนินการ')
    root_causes = models.ManyToManyField(
        RCARootCause, blank=True, related_name='recommendations', verbose_name='แก้ที่ Root Cause',
    )

    class Meta:
        ordering = ['order', 'pk']


class RCAIndicator(models.Model):
    """Section 7 — one indicator, rendered into the table its category belongs to.

    ``source`` separates indicators pulled from the ticket (already in the IOC
    Database through TicketIOC, so never pushed) from ones the analyst found.
    ``excluded`` marks benign/responder values (e.g. the evidence-collection
    host) that stay in the report but never reach the IOC Database.
    """

    CAT_FILE_PATH = 'file_path'
    CAT_IP = 'ip'
    CAT_URL = 'url'
    CAT_DOMAIN = 'domain'
    CAT_EMAIL = 'email'
    CAT_HASH = 'hash'
    CAT_ACCOUNT = 'account'
    CATEGORY_CHOICES = [
        (CAT_FILE_PATH, 'File Path'),
        (CAT_IP, 'IP Address'),
        (CAT_URL, 'URL'),
        (CAT_DOMAIN, 'Domain'),
        (CAT_EMAIL, 'Email'),
        (CAT_HASH, 'Hash (SHA-256)'),
        (CAT_ACCOUNT, 'บัญชีผู้ใช้'),
    ]
    # Report table each category is rendered into.
    SECTION_BY_CATEGORY = {
        CAT_FILE_PATH: '7.1',
        CAT_IP: '7.3',
        CAT_URL: '7.4', CAT_DOMAIN: '7.4', CAT_EMAIL: '7.4',
        CAT_HASH: '7.5',
        CAT_ACCOUNT: '7.6',
    }
    # Categories normalized with the shared IOC normalizers (ioc_values).
    NORMALIZED_CATEGORIES = frozenset({CAT_FILE_PATH, CAT_IP, CAT_URL, CAT_DOMAIN, CAT_HASH})

    SOURCE_TICKET = 'ticket'
    SOURCE_ANALYST = 'analyst'
    SOURCE_CHOICES = [(SOURCE_TICKET, 'จาก Ticket'), (SOURCE_ANALYST, 'Forensic พบเพิ่ม')]

    rca = models.ForeignKey(RCAReport, on_delete=models.CASCADE, related_name='indicators')
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, verbose_name='ประเภท IOC')
    value = models.CharField(max_length=500, verbose_name='Indicator')
    host = models.CharField(max_length=255, blank=True, default='', verbose_name='เครื่อง')
    # Type/role column for IP and URL rows; file name + where found for a hash.
    label = models.TextField(blank=True, default='', verbose_name='ประเภท / ไฟล์ที่พบ')
    note = models.TextField(blank=True, default='', verbose_name='หมายเหตุ / บทบาทในเหตุการณ์')
    excluded = models.BooleanField(default=False, verbose_name='Exclude (ไม่ส่งเข้า IOC Database)')
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default=SOURCE_ANALYST)
    pushed_ioc = models.ForeignKey(
        AnalystIOC, null=True, blank=True, on_delete=models.SET_NULL, related_name='+',
    )
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['category', 'order', 'pk']
        constraints = [
            models.UniqueConstraint(
                fields=['rca', 'category', 'value'], name='rca_indicator_unique_value',
            ),
        ]

    def __str__(self):
        return f'{self.get_category_display()}: {self.value}'

    @classmethod
    def normalize_value(cls, category, value):
        """Canonical form of ``value`` for ``category`` (raises ValidationError
        on a malformed hash / IP / domain / URL / email). Empty in → empty out.

        Shared by ``clean()`` and ``RCAIndicatorForm.clean_value`` so the form's
        ``cleaned_data['value']`` is already canonical — that is what lets the
        inline formset's unique check catch a within-category duplicate that only
        collides after normalisation (e.g. an upper/lower-case hash pair) instead
        of the save hitting the DB constraint and 500-ing.
        """
        from django.core.validators import validate_email
        from ..ioc_values import normalize_for_category

        value = (value or '').strip()
        if not value:
            return ''
        if category in cls.NORMALIZED_CATEGORIES:
            return normalize_for_category(category, value)
        if category == cls.CAT_EMAIL:
            value = value.lower()
            validate_email(value)
        return value

    def clean(self):
        super().clean()
        try:
            self.value = self.normalize_value(self.category, self.value)
        except ValidationError as exc:
            raise ValidationError({'value': exc.messages})
        if not self.value:
            raise ValidationError({'value': 'กรุณาระบุค่า Indicator'})
