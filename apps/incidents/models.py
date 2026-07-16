import re

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction
from django.utils import timezone
from datetime import timedelta


# ── Unified source / reporting-channel vocabulary ────────────────────────── #
# "How an incident reached the SOC." Shared by Ticket.issue_type (the channel
# recorded on a ticket) and TriageRecord.source (the manual-intake channel), so
# a triage record maps 1:1 onto the ticket it spawns (see create_ticket
# auto-fill). SIEM counts as a reporting channel. Values are UPPER_SNAKE codes;
# the labels are what users see.
SOURCE_SIEM        = 'SIEM'
SOURCE_ADMIN       = 'ADMIN'
SOURCE_TI          = 'TI'
SOURCE_EMAIL       = 'EMAIL'
SOURCE_PHONE       = 'PHONE'
SOURCE_USER_REPORT = 'USER_REPORT'
SOURCE_EXTERNAL    = 'EXTERNAL'
SOURCE_OTHER       = 'OTHER'

SOURCE_CHOICES = [
    (SOURCE_SIEM,        'ระบบเฝ้าระวัง (SIEM)'),
    (SOURCE_ADMIN,       'ผู้ดูแลระบบ (Admin)'),
    (SOURCE_TI,          'Threat Intelligence (TI)'),
    (SOURCE_EMAIL,       'Email'),
    (SOURCE_PHONE,       'Phone / Hotline'),
    (SOURCE_USER_REPORT, 'User / Internal Report'),
    (SOURCE_EXTERNAL,    'หน่วยงานภายนอก (External Organization)'),
    (SOURCE_OTHER,       'Other'),
]


class TicketQuerySet(models.QuerySet):
    def visible_to(self, user):
        """
        Return the subset of tickets the given user is allowed to see.

        Rules (single authoritative place — never bypass this):
          - SOC staff / SOC manager  → all tickets
          - System admin             → only tickets where assigned_admin == user
          - No profile / unknown role→ empty queryset (safest default)
        """
        if user.is_superuser:
            return self
        profile = getattr(user, 'profile', None)
        if profile is None:
            return self.none()
        if profile.is_soc:
            return self
        if profile.is_system_admin:
            return self.filter(assigned_admin=user)
        if profile.is_system_owner:
            return self.filter(system_owner=user)
        return self.none()


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
    One real-world security incident that hit MULTIPLE systems and is therefore
    worked as several linked tickets — one per affected system, each routed to
    that system's own admin. The member tickets share the containment guidance
    and classification; only the target (device / IP / owner / admin) differs.

    This is the "Case Bundling" grouping: the bundle counts as a single
    incident/report, while its member tickets are contained and closed
    independently on their own OLA clocks. Members are reached via the
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


class Ticket(models.Model):
    objects = TicketQuerySet.as_manager()

    # ------------------------------------------------------------------ #
    # Status choices — redesigned SOC workflow                            #
    # ------------------------------------------------------------------ #
    STATUS_NEW                  = 'NEW'
    STATUS_ESCALATED_T2         = 'ESCALATED_T2'
    STATUS_T1_REVIEW            = 'T1_REVIEW'
    # ── SOC Manager pre-containment review (blocking) ────────────────── #
    # Every Incident passes through the SOC Manager before it reaches a
    # handling lane. The manager flags Emergency (yes/no) and forwards; they
    # cannot divert the case — the lane is fixed by Tier 1's ``t1_route``
    # (ADMIN → AWAITING_CONTAINMENT, OWNER → AWAITING_OWNER). See the
    # deterministic t1_route guard in can_transition_to / transition_to.
    STATUS_PENDING_MGR_TRIAGE   = 'PENDING_MGR_TRIAGE'
    STATUS_AWAITING_CONTAINMENT = 'AWAITING_CONTAINMENT'
    STATUS_CONTAINMENT_REPORTED = 'CONTAINMENT_REPORTED'
    # ── Direct-to-Owner fast path (any severity) ─────────────────────── #
    # A T1 handling route that skips the System Admin entirely: the analyst
    # contacts the asset owner directly (e.g. by phone) and the owner remediates
    # it themselves — no admin ticket, no containment email. The case is still
    # tracked (AWAITING_OWNER) and always passes mandatory Tier 2 verification
    # (OWNER_REMEDIATED → PENDING_T2_REVIEW); emergency tickets additionally
    # pass the SOC manager (PENDING_T2_REVIEW → PENDING_MANAGER). See the
    # deterministic emergency split in can_transition_to / transition_to.
    STATUS_AWAITING_OWNER       = 'AWAITING_OWNER'
    STATUS_OWNER_REMEDIATED     = 'OWNER_REMEDIATED'
    STATUS_PENDING_T2_REVIEW    = 'PENDING_T2_REVIEW'
    STATUS_PENDING_MANAGER      = 'PENDING_MANAGER'
    STATUS_APPROVED             = 'APPROVED'
    STATUS_CLOSED_EVENT         = 'CLOSED_EVENT'

    STATUS_CHOICES = [
        (STATUS_NEW,                  'แจ้งเหตุใหม่'),
        (STATUS_ESCALATED_T2,         'ส่งต่อให้ Tier 2'),
        (STATUS_T1_REVIEW,            'รอ Tier 1 ทบทวน'),
        (STATUS_PENDING_MGR_TRIAGE,   'รอผู้จัดการ SOC ตรวจ (ก่อนมอบหมาย)'),
        (STATUS_AWAITING_CONTAINMENT, 'รอการจัดการจากผู้ดูแลระบบ'),
        (STATUS_CONTAINMENT_REPORTED, 'รายงานการควบคุมแล้ว'),
        (STATUS_AWAITING_OWNER,       'รอเจ้าของระบบดำเนินการเอง'),
        (STATUS_OWNER_REMEDIATED,     'เจ้าของแจ้งแก้ไขแล้ว — รอ SOC ตรวจ'),
        (STATUS_PENDING_T2_REVIEW,    'รอ Tier 2 ตรวจสอบ'),
        (STATUS_PENDING_MANAGER,      'รอผู้จัดการตรวจสอบ'),
        (STATUS_APPROVED,             'อนุมัติแล้ว'),
        (STATUS_CLOSED_EVENT,         'ปิด (Event)'),
    ]

    # States where no further action is possible
    TERMINAL_STATUSES = frozenset({STATUS_APPROVED, STATUS_CLOSED_EVENT})

    # ------------------------------------------------------------------ #
    # Status pill colors — SINGLE SOURCE OF TRUTH                          #
    #                                                                     #
    # Every status color-coded surface (dashboard + executive pills,      #
    # the ticket-list badge, and the Tier-2 queue stage badges) reads     #
    # from this map via `status_pill_css`, so a status always renders the #
    # same color everywhere. Each entry is (background, text-color).       #
    #                                                                     #
    # Ordering follows the workflow and "whose court the ball is in":     #
    # SOC intake/review (blue/cyan/purple) → blocked on an external actor #
    # (orange = admin, pink = owner) → work reported / verifying (teal    #
    # pair) → awaiting sign-off (steel = T2, amber = manager) → terminal  #
    # (green = approved, gray = closed event).                            #
    #                                                                     #
    # Red (#dc3545) is deliberately RESERVED for danger signals —         #
    # Critical severity, Emergency, and OLA breach — and is never used    #
    # as a status color, so those alarms stay unambiguous.                #
    # ------------------------------------------------------------------ #
    STATUS_PILL_COLORS = {
        STATUS_NEW:                  ('#0d6efd', '#ffffff'),  # blue — open, awaiting triage
        STATUS_ESCALATED_T2:         ('#6f42c1', '#ffffff'),  # purple — up to Tier 2
        STATUS_T1_REVIEW:            ('#0dcaf0', '#212529'),  # cyan — back to Tier 1
        STATUS_PENDING_MGR_TRIAGE:   ('#d4a017', '#212529'),  # goldenrod — SOC Manager pre-containment review
        STATUS_AWAITING_CONTAINMENT: ('#fd7e14', '#ffffff'),  # orange — blocked on System Admin
        STATUS_CONTAINMENT_REPORTED: ('#20c997', '#212529'),  # teal — admin reported, verifying
        STATUS_AWAITING_OWNER:       ('#d63384', '#ffffff'),  # pink — blocked on System Owner
        STATUS_OWNER_REMEDIATED:     ('#0d9488', '#ffffff'),  # deep teal — owner reported, verifying
        STATUS_PENDING_T2_REVIEW:    ('#3d5a80', '#ffffff'),  # steel — awaiting Tier 2 sign-off
        STATUS_PENDING_MANAGER:      ('#ffc107', '#212529'),  # amber — awaiting manager sign-off
        STATUS_APPROVED:             ('#198754', '#ffffff'),  # green — resolved / approved
        STATUS_CLOSED_EVENT:         ('#6c757d', '#ffffff'),  # gray — closed as event
    }

    @property
    def status_pill_css(self):
        """Inline ``background``/``color`` for this ticket's status pill.

        Shared by all status color-coded surfaces so a status looks the
        same everywhere. Unknown statuses fall back to neutral gray.
        """
        bg, fg = self.STATUS_PILL_COLORS.get(self.status, ('#6c757d', '#ffffff'))
        return f'background:{bg};color:{fg};'

    @property
    def status_color(self):
        """Base hex for this ticket's status — for dot/stripe accents."""
        return self.STATUS_PILL_COLORS.get(self.status, ('#6c757d', '#ffffff'))[0]

    @property
    def status_pill_soft_css(self):
        """Soft (tinted) status style for dense tables.

        A lighter 'material' than the solid severity badge — a 10% tint of
        the status hue with a darkened, readable ink — so a status column
        never reads as another severity column. Same hue as
        :attr:`status_pill_css`, just a quieter treatment.
        """
        bg = self.status_color
        return f'background:{bg}1a;color:{self._mix_hex(bg, 0.55)};border:1px solid {bg}33;'

    @staticmethod
    def _mix_hex(hex_color, factor):
        """Darken ``#rrggbb`` toward black by ``factor`` (0-1). Returns hex."""
        h = hex_color.lstrip('#')
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        return '#{:02x}{:02x}{:02x}'.format(*(int(c * factor) for c in (r, g, b)))

    # ------------------------------------------------------------------ #
    # Event / Incident classification (replaces the old TP/FP disposition) #
    #   INCIDENT — actionable case that proceeds to containment (was TP)   #
    #   EVENT    — benign case that gets closed (was FP)                   #
    # Set by Tier 1 in the create flow; may be revised by Tier 2 on an     #
    # escalated ticket. Every ticket carries an explicit value.            #
    # ------------------------------------------------------------------ #
    CLASSIFICATION_INCIDENT = 'INCIDENT'
    CLASSIFICATION_EVENT    = 'EVENT'

    CLASSIFICATION_CHOICES = [
        (CLASSIFICATION_INCIDENT, 'Incident (เหตุการณ์จริง)'),
        (CLASSIFICATION_EVENT,    'Event (ไม่เป็นภัย)'),
    ]

    # ------------------------------------------------------------------ #
    # Tier-1 handling route for an Incident — chosen by Tier 1, then      #
    # remembered so the SOC Manager pre-containment review can forward    #
    # the ticket to the predetermined lane without being able to change   #
    # it. ADMIN → AWAITING_CONTAINMENT, OWNER → AWAITING_OWNER.           #
    # Blank until Tier 1 commits an Incident to PENDING_MGR_TRIAGE.        #
    # ------------------------------------------------------------------ #
    T1_ROUTE_ADMIN = 'ADMIN'
    T1_ROUTE_OWNER = 'OWNER'

    T1_ROUTE_CHOICES = [
        (T1_ROUTE_ADMIN, 'มอบหมายผู้ดูแลระบบ (System Admin)'),
        (T1_ROUTE_OWNER, 'ให้เจ้าของระบบแก้ไขเอง (Direct-to-Owner)'),
    ]

    # ------------------------------------------------------------------ #
    # State-machine: legal transitions                                    #
    # ------------------------------------------------------------------ #
    ALLOWED_TRANSITIONS = {
        STATUS_NEW: [
            STATUS_PENDING_MGR_TRIAGE,     # Incident → SOC Manager pre-containment review
            STATUS_ESCALATED_T2,           # Event or Incident → escalate to Tier 2
        ],
        STATUS_ESCALATED_T2: [
            STATUS_T1_REVIEW,              # Incident → T2 returns to Tier 1
            STATUS_CLOSED_EVENT,           # Event    → T2 confirms & closes (no manager)
        ],
        STATUS_T1_REVIEW: [
            STATUS_PENDING_MGR_TRIAGE,     # T1 reviews → SOC Manager pre-containment review
        ],
        # ── SOC Manager pre-containment review (blocking, Incident-only) ─ #
        STATUS_PENDING_MGR_TRIAGE: [
            STATUS_AWAITING_CONTAINMENT,   # manager forwards → admin lane (t1_route=ADMIN)
            STATUS_AWAITING_OWNER,         # manager forwards → owner lane (t1_route=OWNER)
        ],
        STATUS_AWAITING_CONTAINMENT: [
            STATUS_CONTAINMENT_REPORTED,   # admin submits report → Tier 2 verifies
        ],
        STATUS_CONTAINMENT_REPORTED: [
            STATUS_AWAITING_CONTAINMENT,   # T2: not contained → back to admin (loop)
            STATUS_PENDING_MANAGER,        # T2 verified + emergency → SOC Manager
            STATUS_APPROVED,               # T2 verified + not emergency → close
            STATUS_CLOSED_EVENT,           # T2 reclassifies as Event → close (no manager)
        ],
        # ── Direct-to-Owner path ─────────────────────────────────────── #
        STATUS_AWAITING_OWNER: [
            STATUS_OWNER_REMEDIATED,       # T1 records owner-confirmed fix
        ],
        STATUS_OWNER_REMEDIATED: [
            STATUS_AWAITING_OWNER,         # not actually fixed → keep tracking (loop)
            STATUS_PENDING_T2_REVIEW,      # always → Tier 2 verifies (mandatory)
        ],
        STATUS_PENDING_T2_REVIEW: [
            STATUS_APPROVED,               # T2 verified + not emergency → close
            STATUS_PENDING_MANAGER,        # T2 verified + emergency → SOC Manager
            STATUS_AWAITING_OWNER,         # Tier 2 rejects → back to owner
            STATUS_CLOSED_EVENT,           # T2 reclassifies as Event → close (no manager)
        ],
        STATUS_PENDING_MANAGER: [
            STATUS_APPROVED,               # manager verifies → close
        ],
        STATUS_APPROVED:     [],
        STATUS_CLOSED_EVENT: [],
    }

    # ------------------------------------------------------------------ #
    # Permission map: (from, to) → required permission token             #
    #   TIER1_CREATOR — profile.is_tier1 AND user == created_by           #
    #   TIER2         — profile.is_tier2                                   #
    #   ASSIGNED_ADMIN— user == assigned_admin                            #
    #   MANAGER       — profile.is_soc_manager                            #
    # ------------------------------------------------------------------ #
    TRANSITION_PERMISSIONS = {
        (STATUS_NEW,                  STATUS_PENDING_MGR_TRIAGE):   'TIER1_CREATOR',
        (STATUS_NEW,                  STATUS_ESCALATED_T2):         'TIER1_CREATOR',
        (STATUS_ESCALATED_T2,         STATUS_T1_REVIEW):           'TIER2',
        (STATUS_ESCALATED_T2,         STATUS_CLOSED_EVENT):        'TIER2',
        (STATUS_T1_REVIEW,            STATUS_PENDING_MGR_TRIAGE):   'TIER1_CREATOR',
        # SOC Manager pre-containment review forwards to the fixed lane.
        (STATUS_PENDING_MGR_TRIAGE,   STATUS_AWAITING_CONTAINMENT): 'MANAGER',
        (STATUS_PENDING_MGR_TRIAGE,   STATUS_AWAITING_OWNER):       'MANAGER',
        (STATUS_AWAITING_CONTAINMENT, STATUS_CONTAINMENT_REPORTED): 'ASSIGNED_ADMIN',
        # Containment verification is Tier 2's job (any Tier 2, not the creator).
        (STATUS_CONTAINMENT_REPORTED, STATUS_AWAITING_CONTAINMENT): 'TIER2',
        (STATUS_CONTAINMENT_REPORTED, STATUS_PENDING_MANAGER):      'TIER2',
        (STATUS_CONTAINMENT_REPORTED, STATUS_APPROVED):             'TIER2',
        (STATUS_CONTAINMENT_REPORTED, STATUS_CLOSED_EVENT):         'TIER2',
        # Direct-to-Owner path
        (STATUS_AWAITING_OWNER,       STATUS_OWNER_REMEDIATED):     'TIER1_CREATOR',
        (STATUS_OWNER_REMEDIATED,     STATUS_AWAITING_OWNER):       'TIER1_CREATOR',
        (STATUS_OWNER_REMEDIATED,     STATUS_PENDING_T2_REVIEW):    'TIER1_CREATOR',
        (STATUS_PENDING_T2_REVIEW,    STATUS_APPROVED):             'TIER2',
        (STATUS_PENDING_T2_REVIEW,    STATUS_PENDING_MANAGER):      'TIER2',
        (STATUS_PENDING_T2_REVIEW,    STATUS_AWAITING_OWNER):       'TIER2',
        (STATUS_PENDING_T2_REVIEW,    STATUS_CLOSED_EVENT):         'TIER2',
        (STATUS_PENDING_MANAGER,      STATUS_APPROVED):             'MANAGER',
    }

    # Statuses on the Tier 1 side of the lifecycle that are gated to the
    # ticket's original creator (same analyst who opened it). Used both by
    # transition_to and the same-status note guard.
    CREATOR_REVIEW_STATUSES = frozenset({
        STATUS_T1_REVIEW,
        # Direct-to-Owner tracking sits with the opening analyst too. (The
        # CONTAINMENT_REPORTED and PENDING_T2_REVIEW queues are deliberately NOT
        # here — they are Tier 2 verification queues, so a non-creator Tier 2
        # must be able to act on and annotate them.)
        STATUS_AWAITING_OWNER, STATUS_OWNER_REMEDIATED,
    })

    # Statuses that sit in the Tier 2 work queue: escalation triage plus the
    # two verification stages (admin containment / owner remediation).
    TIER2_QUEUE_STATUSES = (
        STATUS_ESCALATED_T2, STATUS_CONTAINMENT_REPORTED, STATUS_PENDING_T2_REVIEW,
    )

    # Statuses that sit in the SOC Manager work queue: the pre-containment
    # review (flag Emergency + forward) and the post-verification approval.
    MANAGER_QUEUE_STATUSES = (
        STATUS_PENDING_MGR_TRIAGE, STATUS_PENDING_MANAGER,
    )

    # Edges that close a benign Event — require classification == EVENT.
    # Tier 2 confirms an Event and closes directly; the SOC Manager is never
    # involved in an Event. The two mid-containment edges let Tier 2 reclassify
    # an in-flight Incident as an Event (after flipping classification → EVENT)
    # and close it without the manager, even when the emergency flag is set.
    EVENT_CLOSE_TRANSITIONS = frozenset({
        (STATUS_ESCALATED_T2,         STATUS_CLOSED_EVENT),
        (STATUS_CONTAINMENT_REPORTED, STATUS_CLOSED_EVENT),
        (STATUS_PENDING_T2_REVIEW,    STATUS_CLOSED_EVENT),
    })

    # Edges that commit to handling an Incident — require classification == INCIDENT.
    # (NEW→ESCALATED_T2 is deliberately NOT here: an escalation carries either
    # classification to Tier 2, which then decides Event-close or Incident.)
    INCIDENT_TRANSITIONS = frozenset({
        (STATUS_NEW,          STATUS_PENDING_MGR_TRIAGE),
        (STATUS_ESCALATED_T2, STATUS_T1_REVIEW),
    })

    # ------------------------------------------------------------------ #
    # Other choice sets                                                   #
    # ------------------------------------------------------------------ #
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High',     'High'),
        ('Medium',   'Medium'),
        ('Low',      'Low'),
        # Unknown = analyst cannot yet classify severity. It is unclassified,
        # NOT low-risk, so it sits below Low only for queue ordering. Severity
        # never routes to the manager — only the emergency flag does.
        # Human-assigned only (not Wazuh ingest).
        ('Unknown',  'Unknown'),
    ]

    # Ordered severity ranks for queue ordering. Unknown ranks 0 (lowest) so it
    # sorts last. Severities not in this map (e.g. blank) also rank 0.
    SEVERITY_RANK = {'Unknown': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}

    # NCSA (สกมช.) statutory threat-severity level — the 3-tier classification
    # required on the official incident report, distinct from the SIEM-derived
    # ``severity`` above. Optional: the analyst may not be able to assign it at
    # intake. See the NCSA Act B.E. 2562 threat-level definitions.
    NCSA_SEVERITY_CRITICAL   = 'CRITICAL'
    NCSA_SEVERITY_SEVERE     = 'SEVERE'
    NCSA_SEVERITY_NON_SEVERE = 'NON_SEVERE'
    NCSA_SEVERITY_CHOICES = [
        (NCSA_SEVERITY_CRITICAL,   'วิกฤต (Critical)'),
        (NCSA_SEVERITY_SEVERE,     'ร้ายแรง (Severe)'),
        (NCSA_SEVERITY_NON_SEVERE, 'ไม่ร้ายแรง (Non-Severe)'),
    ]

    ASSET_TYPE_CHOICES = [
        ('Computer',       'Computer'),
        ('Server',         'Server'),
        ('Network Device', 'Network Device'),
    ]

    DETAILED_ISSUE_CHOICES = [
        ('Training', 'เหตุการณ์จำลอง และ การฝึกจู่โจม ของหน่วยงานเอง (Training and Exercises)'),
        ('Unsuccessful Attempt', 'การพยายามเข้าถึงระบบที่ไม่สำเร็จ (Unsuccessful Activity Attempt)'),
        ('Reconnaissance', 'การพยายามบุกรุกเพื่อสำรวจข้อมูลองค์กรเพื่อโจมตี (Reconnaissance)'),
        ('Non-Compliance', 'การดำเนินการที่ไม่เป็นไปตามมาตรฐานความปลอดภัยที่หน่วยงานกำหนด (Non-Compliance Activity)'),
        ('Malicious Logic', 'การบุกรุกโดยการใช้มัลแวร์ (Malicious Logic)'),
        ('User Intrusion', 'การบุกรุกในระดับผู้ใช้งาน (User Level Intrusion)'),
        ('Root Intrusion', 'การบุกรุกในระดับผู้ควบคุมระบบ (Root Level Intrusion)'),
        ('DoS', 'การบุกรุกที่ทำให้ไม่สามารถเข้าไปใช้บริการได้ (Denial of Service)'),
        ('Investigating', 'เหตุการณ์ที่อยู่ระหว่างการวิเคราะห์สอบสวน (Investigating)'),
        ('Explained Anomaly', 'เหตุการณ์ผิดปกติที่ได้รับการวิเคราะห์แล้วว่าไม่ใช่เหตุการณ์ที่เป็นภัยคุกคาม (Explained Anomaly)'),
        ('SIEM Other', 'อื่นๆ (SIEM Other)'),
        ('Admin Unsuccessful', '(Admin) การพยายามเข้าถึงระบบที่ไม่สำเร็จ (Unsuccessful Activity Attempt)'),
        ('Admin Reconnaissance', '(Admin) การพยายามบุกรุกเพื่อสำรวจข้อมูลองค์กรเพื่อโจมตี (Reconnaissance)'),
        ('Admin Non-Compliance', '(Admin) การดำเนินการที่ไม่เป็นไปตามมาตรฐานความปลอดภัยที่หน่วยงานกำหนด (Non-Compliance Activity)'),
        ('Admin Malicious Logic', '(Admin) การบุกรุกโดยการใช้มัลแวร์ (Malicious Logic)'),
        ('Admin User Intrusion', '(Admin) การบุกรุกในระดับผู้ใช้งาน (User Level Intrusion)'),
        ('Admin Root Intrusion', '(Admin) การบุกรุกในระดับผู้ควบคุมระบบ (Root Level Intrusion)'),
        ('Admin DoS', '(Admin) การบุกรุกที่ทำให้ไม่สามารถเข้าไปใช้บริการได้ (Denial of Service)'),
        ('Admin Explained Anomaly', '(Admin) เหตุการณ์ผิดปกติที่ได้รับการวิเคราะห์แล้วว่าไม่ใช่เหตุการณ์ที่เป็นภัยคุกคาม (Explained Anomaly)'),
        ('TI IOC', 'แจ้งเตือน IOC (Indicators of Compromise)'),
        ('TI Other', 'อื่นๆ (TI Other)'),
        ('Data Leak', 'พบข้อมูลรั่วไหล'),
        ('Vulnerability', 'พบช่องโหว่ของอุปกรณ์หรือระบบงาน'),
        ('Attack Attempt', 'พบความพยายามในการไปโจมตีผู้อื่น'),
        ('External Other', 'อื่นๆ (External Other)'),
    ]

    RAW_DETAILED_ISSUES = [
        ('Simulated Phishing', 'พบการยิง simulated phishing campaign จากทีม security'),
        ('Brute Force', 'Red Team ทำการ brute force test กับระบบ'),
        ('Internal Scan', 'การสแกนช่องโหว่จากเครื่องมือภายใน เช่น Nexus / OpenVAS'),
        ('Whitelisted Log', 'Log แสดง activity จาก IP ภายในที่ถูก whitelist เป็น "test range"'),
        ('Training Other', 'Other (Training and Exercises)'),
        ('Failed Login', 'Login ล้มเหลวหลายครั้ง (failed login) จากบัญชีเดียวกัน'),
        ('Admin Panel Attempt', 'การพยายามเข้าถึง URL/admin panel และได้ 403/401'),
        ('Firewall Block', 'Firewall block การเชื่อมต่อจาก IP ที่ต้องสงสัย'),
        ('SSH Failed', 'SSH login failed หลายครั้ง (brute force attempt)'),
        ('Unsuccessful Other', 'Other (Unsuccessful Activity Attempt)'),
        ('Port Scanning', 'Port scanning จาก IP ภายนอก (เช่น scan port 22, 80, 443)'),
        ('DNS Enumeration', 'DNS enumeration (query domain ย่อยจำนวนมาก)'),
        ('Web Scanning', 'Web scanning เช่น /admin, /backup, /test'),
        ('User Enumeration', 'User enumeration เช่น ลอง login ด้วย username หลายๆ แบบ'),
        ('Recon Other', 'Other (Reconnaissance)'),
        ('USB Policy', 'User ใช้ USB storage ทั้งที่ policy ห้าม'),
        ('Unauthorized Software', 'ติดตั้ง software ที่ไม่ได้รับอนุญาต'),
        ('Antivirus Off', 'ปิด antivirus / endpoint protection'),
        ('Weak Password', 'ใช้ password ที่ไม่ตรง policy (เช่น ไม่มี complexity)'),
        ('Compliance Other', 'Other (Non-Compliance Activity)'),
        ('Malware EDR', 'ตรวจพบ malware จาก EDR (เช่น Trojan, ransomware)'),
        ('C2 Server', 'มีการเรียก command & control (C2) server'),
        ('Ransomware Behavior', 'ไฟล์ถูก encrypt จำนวนมาก (ransomware behavior)'),
        ('Suspicious PowerShell', 'PowerShell execution ที่ suspicious (encoded command)'),
        ('Malicious Other', 'Other (Malicious Logic)'),
        ('Impossible Travel', 'Login สำเร็จจาก location แปลก (Impossible travel)'),
        ('Abnormal Account', 'มีการใช้บัญชี user รับคำสั่งผิดปกติ'),
        ('Data Exfiltration', 'Access ไฟล์สำคัญจำนวนมากในเวลาสั้น (data exfiltration)'),
        ('Spam Account', 'Email account ถูกใช้ส่ง spam/phishing'),
        ('User Level Other', 'Other (User Level Intrusion)'),
        ('Privilege Escalation', 'มีการใช้ sudo / privilege escalation สำเร็จ'),
        ('Unauthorized Admin', 'สร้าง admin account ใหม่โดยไม่ได้รับอนุญาต'),
        ('System Config Change', 'แก้ไข system binaries หรือ config สำคัญ'),
        ('Log Service Off', 'ปิด log / security service'),
        ('Root Level Other', 'Other (Root Level Intrusion)'),
        ('HTTP Flood', 'Traffic เข้ามาจำนวนมากผิดปกติ (HTTP flood)'),
        ('SYN Flood', 'SYN flood attack'),
        ('Server Spike', 'CPU / Memory server พุ่งสูงผิดปกติ'),
        ('DDoS', 'มี request ซ้ำๆ จำนวนมากจากหลาย IP (DDoS)'),
        ('DoS Other', 'Other (Denial of Service)'),
        ('Unconfirmed Login', 'SIEM alert ว่า "suspicious login" แต่ยังไม่ confirm'),
        ('Anomaly Correlation', 'พบ anomaly แต่ยังต้อง correlation เพิ่ม'),
        ('SOC Escalate', 'Event ถูก escalate ไป SOC analyst'),
        ('Log Gathering', 'กำลังรวบรวม log จากหลายแหล่ง (Firewall, endpoint, AD)'),
        ('Investigating Other', 'Other (Investigating)'),
        ('VPN Login', 'User login จากต่างประเทศ แต่จริงๆ คือ VPN ของบริษัท'),
        ('Deploy Traffic', 'Traffic สูงเพราะมีการ deploy ระบบ / backup'),
        ('Vulnerability Scanner', 'Scan มาจาก vulnerability scanner ภายใน'),
        ('Admin Maintenance', 'Admin ทำงาน maintenance นอกเวลาปกติ'),
        ('Explained Other', 'Other (Explained Anomaly)'),
        ('SIEM Other Detail', 'อื่นๆ (SIEM Other)'),
        ('Admin Failed Login', '(Admin) Login ล้มเหลวหลายครั้ง (failed login) จากบัญชีเดียวกัน'),
        ('Admin Panel Block', '(Admin) การพยายามเข้าถึง URL/admin panel และได้ 403/401'),
        ('TI IOC Detail', '(TI) แจ้งเตือน IOC (Indicators of Compromise)'),
        ('TI Malicious IP', '(TI) พบการติดต่อกับ IP อันตราย (Malicious IP Communication)'),
        ('Data Leak Detail', '(External) พบข้อมูลรั่วไหล'),
        ('Vulnerability Found', '(External) พบช่องโหว่ของอุปกรณ์หรือระบบงาน'),
        ('Attack Attempt Detail', '(External) พบความพยายามในการไปโจมตีผู้อื่น'),
        ('External Other Detail', '(External) อื่นๆ (External Other)'),
    ]

    DETAILED_ISSUE_CHOICES2 = sorted(RAW_DETAILED_ISSUES, key=lambda x: x[1])

    # ── Threat-type hierarchy: detailed_issue → detailed_issue2 ──────── #
    # The 10 "clean" threat categories and their specific sub-types. Only
    # these are offered on the forms; the source-flavoured legacy categories
    # in DETAILED_ISSUE_CHOICES (SIEM Other, Admin *, TI *, External *) are
    # kept solely so existing tickets still display, and are hidden from new
    # selection. Single source of truth for the form choices, the create-form
    # parent auto-fill, and the JS cascade in _detailed_issue_cascade.html.
    DETAILED_ISSUE_HIERARCHY = {
        'Training':             ['Simulated Phishing', 'Brute Force', 'Internal Scan', 'Whitelisted Log', 'Training Other'],
        'Unsuccessful Attempt': ['Failed Login', 'Admin Panel Attempt', 'Firewall Block', 'SSH Failed', 'Unsuccessful Other'],
        'Reconnaissance':       ['Port Scanning', 'DNS Enumeration', 'Web Scanning', 'User Enumeration', 'Recon Other'],
        'Non-Compliance':       ['USB Policy', 'Unauthorized Software', 'Antivirus Off', 'Weak Password', 'Compliance Other'],
        'Malicious Logic':      ['Malware EDR', 'C2 Server', 'Ransomware Behavior', 'Suspicious PowerShell', 'Malicious Other'],
        'User Intrusion':       ['Impossible Travel', 'Abnormal Account', 'Data Exfiltration', 'Spam Account', 'User Level Other'],
        'Root Intrusion':       ['Privilege Escalation', 'Unauthorized Admin', 'System Config Change', 'Log Service Off', 'Root Level Other'],
        'DoS':                  ['HTTP Flood', 'SYN Flood', 'Server Spike', 'DDoS', 'DoS Other'],
        'Investigating':        ['Unconfirmed Login', 'Anomaly Correlation', 'SOC Escalate', 'Log Gathering', 'Investigating Other'],
        'Explained Anomaly':    ['VPN Login', 'Deploy Traffic', 'Vulnerability Scanner', 'Admin Maintenance', 'Explained Other'],
    }

    @classmethod
    def detailed_issue_form_choices(cls):
        """(code, label) for the clean threat categories offered on forms."""
        labels = dict(cls.DETAILED_ISSUE_CHOICES)
        return [(p, labels.get(p, p)) for p in cls.DETAILED_ISSUE_HIERARCHY]

    @classmethod
    def detailed_issue2_form_choices(cls):
        """(code, label) for every specific sub-type under a clean category."""
        labels = dict(cls.DETAILED_ISSUE_CHOICES2)
        return [(c, labels.get(c, c))
                for children in cls.DETAILED_ISSUE_HIERARCHY.values()
                for c in children]

    @classmethod
    def parent_of_detailed_issue2(cls, child):
        """The detailed_issue category a given detailed_issue2 belongs to."""
        for parent, children in cls.DETAILED_ISSUE_HIERARCHY.items():
            if child in children:
                return parent
        return None

    @classmethod
    def detailed_issue_cascade(cls):
        """{parent: [[child_code, child_label], …]} consumed by the JS cascade."""
        labels = dict(cls.DETAILED_ISSUE_CHOICES2)
        return {p: [[c, labels.get(c, c)] for c in children]
                for p, children in cls.DETAILED_ISSUE_HIERARCHY.items()}

    # ------------------------------------------------------------------ #
    # Fields                                                              #
    # ------------------------------------------------------------------ #
    ticket_id = models.CharField(max_length=20, unique=True, editable=False, blank=True)

    # ── Section 1: General Information ──────────────────────────────── #
    # Short human-readable name for the case (ชื่อ incident/event on the NCSA
    # report). Optional — the structured fields below carry the real detail;
    # this is a one-line handle for lists, exports and the report header.
    incident_name = models.CharField(
        max_length=255, blank=True, default='',
        verbose_name='ชื่อเหตุการณ์ (Incident/Event Name)',
    )
    severity = models.CharField(
        max_length=10, choices=SEVERITY_CHOICES, default='High',
        verbose_name='ระดับความรุนแรง',
    )
    # NCSA (สกมช.) statutory severity level — reported alongside the SIEM
    # ``severity``. Blank until an analyst assigns it.
    ncsa_severity = models.CharField(
        max_length=20, choices=NCSA_SEVERITY_CHOICES, blank=True, default='',
        verbose_name='ระดับความรุนแรงตาม สกมช.',
    )
    incident_datetime = models.DateTimeField(
        null=True, blank=True,
        verbose_name='วันและเวลาที่ตรวจพบเหตุการณ์',
    )
    reference_id = models.CharField(
        max_length=50, blank=True, default='',
        verbose_name='Reference',
    )
    # Free-text name of the log source the alert came from (แหล่งข้อมูล on the
    # NCSA report) — e.g. "Palo Alto Firewall", "Windows Security Event Log".
    # Distinct from issue_type (the coarse reporting channel). Required at the
    # form level, not the DB, so non-form creation paths (Wazuh ingest, seeders)
    # are unaffected.
    log_source = models.CharField(
        max_length=150, blank=True, default='',
        verbose_name='แหล่งข้อมูล (Log Source)',
    )

    # ── Case Bundling (Project Incident) ─────────────────────────────── #
    # When one incident affects several systems it is fanned out into one
    # ticket per system, all pointing at the same ProjectIncident. Members
    # keep their own status/OLA; the bundle is the grouping + rollup unit.
    project_incident = models.ForeignKey(
        ProjectIncident, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='member_tickets', verbose_name='Project Incident (Case Bundle)',
    )
    bundle_suffix = models.CharField(
        max_length=4, blank=True, default='',
        verbose_name='ลำดับในกลุ่ม (A, B, C …)',
    )

    # ── Section 3: Description ───────────────────────────────────────── #
    device_name = models.CharField(max_length=100, verbose_name='ระบบ / บริการ (System/Service)')
    issue_description = models.TextField(verbose_name='รายละเอียดเหตุการณ์')

    # ── Section 4: Scope / Affected Asset ───────────────────────────── #
    # null=True with blank=False: forms still require an IP, but tickets
    # imported from the pre-system TrendMicro tracker have none to give.
    ip_address = models.GenericIPAddressField(
        null=True, verbose_name='IP Address ของทรัพย์สิน',
    )
    mac_address = models.CharField(
        max_length=50, blank=True, default='',
        verbose_name='MAC Address',
    )
    asset_type = models.CharField(
        max_length=20, choices=ASSET_TYPE_CHOICES, blank=True, default='',
        verbose_name='ประเภทของทรัพย์สิน',
    )
    operating_system = models.CharField(
        max_length=100, blank=True, default='',
        verbose_name='ระบบปฏิบัติการ (Operating System)',
    )
    # Free-text owning unit/department of the affected asset (หน่วยงานเจ้าของ
    # ทรัพย์สิน on the report). Deliberately NOT the system_owner FK — this is a
    # descriptive label typed by the analyst, independent of whether that unit
    # has a registered System Owner account in the system.
    asset_owner = models.CharField(
        max_length=150, blank=True, default='',
        verbose_name='หน่วยงานเจ้าของทรัพย์สิน',
    )
    spread_to_others = models.BooleanField(
        null=True, blank=True,
        verbose_name='มีการกระจายไปยังจุดอื่น',
    )

    # ── Section 5: IoC ──────────────────────────────────────────────── #
    destination_ip = models.CharField(
        max_length=100, blank=True, default='',
        verbose_name='IP Address ปลายทางที่น่าสงสัย',
    )
    ioc_details = models.TextField(
        blank=True, default='',
        verbose_name='Indicators of Compromise (IoC)',
    )

    # ── Section 6: MITRE ATT&CK ─────────────────────────────────────── #
    MITRE_PHASE_CHOICES = [
        ('Reconnaissance',       'Reconnaissance'),
        ('Resource Development', 'Resource Development'),
        ('Initial Access',       'Initial Access'),
        ('Execution',            'Execution'),
        ('Persistence',          'Persistence'),
        ('Privilege Escalation', 'Privilege Escalation'),
        ('Defense Evasion',      'Defense Evasion'),
        ('Credential Access',    'Credential Access'),
        ('Discovery',            'Discovery'),
        ('Lateral Movement',     'Lateral Movement'),
        ('Collection',           'Collection'),
        ('Command and Control',  'Command and Control'),
        ('Exfiltration',         'Exfiltration'),
        ('Impact',               'Impact'),
    ]
    # An incident can span several ATT&CK phases, so this stores a
    # comma-separated list of MITRE_PHASE_CHOICES codes (set via the multi-select
    # form field). Read it through ``mitre_phase_list`` / ``mitre_phase_labels``
    # rather than parsing the raw string.
    mitre_phase = models.CharField(
        max_length=500, blank=True, default='',
        verbose_name='Phase การโจมตีตาม MITRE ATT&CK',
    )

    # ── Section 7: Recommended Actions ──────────────────────────────── #
    action_required = models.TextField(
        blank=True, default='',
        verbose_name='สิ่งที่ต้องดำเนินการ',
    )
    action_precautions = models.TextField(
        blank=True, default='',
        verbose_name='ข้อควรระวังในการดำเนินการ',
    )
    # Per-item done-state for the สิ่งที่ต้องดำเนินการ checklist the assigned
    # System Admin ticks while containing the incident. A non-mandatory aid:
    # [{"text": "<item line>", "done": true|false}, ...]. Restored by text match
    # across the Tier 2 rejection loop; see ``containment_checklist_display``.
    containment_checklist = models.JSONField(default=list, blank=True)

    # Report-only prose: lets analysts polish the official document wording
    # without overloading lifecycle logs or containment fields.
    actions_taken_summary = models.TextField(
        blank=True, default='',
        verbose_name='สรุปเรื่องที่ดำเนินการแล้ว',
    )
    next_steps_summary = models.TextField(
        blank=True, default='',
        verbose_name='สรุปการดำเนินการลำดับถัดไป',
    )

    # ── Section 9: Remediation ──────────────────────────────────────── #
    remediation_summary = models.TextField(
        blank=True, default='',
        verbose_name='สรุปผลการดำเนินการแก้ไข',
    )

    status = models.CharField(
        max_length=30, choices=STATUS_CHOICES, default=STATUS_NEW,
    )
    classification = models.CharField(
        max_length=20, choices=CLASSIFICATION_CHOICES, blank=True, default='',
        verbose_name='การจัดประเภท (Event/Incident)',
    )
    # The handling lane Tier 1 chose for an Incident (ADMIN / OWNER). Set when
    # Tier 1 routes a ticket into PENDING_MGR_TRIAGE; read by the SOC Manager
    # forward step to send the ticket to its fixed lane. Blank for Events and
    # for tickets still awaiting a route decision.
    t1_route = models.CharField(
        max_length=10, choices=T1_ROUTE_CHOICES, blank=True, default='',
        verbose_name='เส้นทางที่ Tier 1 เลือก (Admin/Owner)',
    )
    containment_report = models.TextField(
        blank=True, default='',
        verbose_name='รายงานการควบคุม',
    )

    # Set to True the first time a ticket enters ESCALATED_T2 and never cleared
    # — the authoritative record of "this ticket was escalated to Tier 2 at some
    # point", used to gate the Tier 1 emergency-flag permission.
    escalated_to_t2_at = models.DateTimeField(
        null=True, blank=True, verbose_name='เวลาที่ส่งต่อ Tier 2 ครั้งแรก',
    )

    # Emergency marker — decided by the SOC Manager at the pre-containment
    # review (PENDING_MGR_TRIAGE) and adjustable by the manager at any later
    # stage; no other role may set it (see set_emergency / can_set_emergency).
    # Feeds requires_manager_verification.
    is_emergency = models.BooleanField(
        default=False, verbose_name='เหตุฉุกเฉิน (Emergency)',
    )

    # ── System Owner ─────────────────────────────────────────────────── #
    # FK to the registered System Owner user account.  Their email and
    # department are read from their User / UserProfile at notification time.
    #
    # DORMANT (2026-07-07): the NCSA-report form redesign dropped the System
    # Owner picker from every user-facing form in favour of the free-text
    # ``asset_owner`` unit label. New tickets created via the forms therefore
    # leave this null, so the owner-notification emails
    # (notify_system_owner_created / notify_system_owner_closed) and the System
    # Owner dashboard visibility (TicketQuerySet.visible_to → system_owner) no
    # longer fire for them. The field/wiring are kept intact for legacy tickets
    # and admin use; re-introduce a picker (or map asset_owner → a recipient)
    # to reactivate owner notifications.
    system_owner = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='owned_tickets',
        verbose_name='เจ้าของระบบ / หน่วยงาน',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # Timestamp of the last *status change* (set on creation, then updated by
    # transition_to whenever the status actually changes). Unlike updated_at
    # (auto_now — bumps on any save, incl. note edits / emergency toggles),
    # this tracks only lifecycle transitions, so it answers "when did this
    # ticket last move state?".
    status_changed_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่อัปเดตสถานะ',
    )

    # ── Lifecycle timestamps (dashboard metrics) ─────────────────────── #
    # acknowledged_at — when an analyst picked the case up (วันที่รับเคส).
    #   Backfilled by the TrendMicro import; for tickets born in this system
    #   creation is the ack, so queries coalesce to created_at.
    # report_issued_at — first hand-off to the system admin (วันที่ออกรายงาน).
    #   Stamped by transition_to on first entry to AWAITING_CONTAINMENT.
    # closed_at — terminal close on EITHER path. approved_at only covers
    #   APPROVED; CLOSED_EVENT tickets would otherwise have no close time.
    acknowledged_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่รับเคส',
    )
    report_issued_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่ออกรายงาน',
    )
    # ── Direct-to-Owner path bookkeeping ─────────────────────────────── #
    # owner_contacted_at — first entry to AWAITING_OWNER (analogous to
    #   report_issued_at on the admin path); the point the owner was told to fix
    #   it themselves. Write-once, set by transition_to.
    # direct_owner_remediation — permanent marker that this ticket was handled by
    #   the asset owner directly (no System Admin ticket / email), for dashboard
    #   segmentation and reporting. Set by transition_to on AWAITING_OWNER.
    owner_contacted_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่ติดต่อเจ้าของระบบ',
    )
    direct_owner_remediation = models.BooleanField(
        default=False, verbose_name='ให้เจ้าของระบบแก้ไขเอง (ไม่ผ่านผู้ดูแลระบบ)',
    )
    closed_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่ปิดเคส',
    )
    # Raw detection score from the source alert (TrendMicro Workbench 0–100).
    alert_score = models.PositiveSmallIntegerField(
        null=True, blank=True, verbose_name='คะแนน Alert (TrendMicro)',
    )

    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='assigned_tickets',
    )
    assigned_admin = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='admin_tickets',
        verbose_name='ผู้ดูแลระบบที่รับผิดชอบ',
    )
    verified_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='verified_tickets',
        verbose_name='ผู้ตรวจสอบ',
    )
    verified_at = models.DateTimeField(null=True, blank=True, verbose_name='วันที่ตรวจสอบ')
    approved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='approved_tickets',
        verbose_name='ผู้อนุมัติ',
    )
    approved_at = models.DateTimeField(null=True, blank=True, verbose_name='วันที่อนุมัติ')

    # Report export metadata. These are audit fields for the latest generated
    # report artifact (report_format says whether that artifact was DOCX or
    # PDF), not the canonical ticket content itself.
    report_template_version = models.CharField(max_length=20, blank=True, default='')
    report_format = models.CharField(max_length=8, blank=True, default='')
    report_generated_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='generated_ticket_reports',
    )
    report_generated_at = models.DateTimeField(null=True, blank=True)
    report_ticket_updated_at = models.DateTimeField(null=True, blank=True)
    report_sha256 = models.CharField(max_length=64, blank=True, default='')

    update_notes = models.TextField(blank=True, null=True, verbose_name='บันทึกการติดตามงาน')
    ola_triage_deadline = models.DateTimeField(
        null=True, blank=True, verbose_name='OLA Triage Deadline')
    ola_contain_deadline = models.DateTimeField(
        null=True, blank=True, verbose_name='OLA Contain Deadline')
    # Reporting channel the incident arrived through. Shares SOURCE_CHOICES
    # with TriageRecord.source so a manual-triage record maps straight onto the
    # ticket it creates.
    issue_type = models.CharField(
        max_length=50, choices=SOURCE_CHOICES, default=SOURCE_SIEM,
        verbose_name='Source',
    )
    detailed_issue = models.CharField(
        max_length=255, choices=DETAILED_ISSUE_CHOICES, default='Investigating',
        verbose_name='เหตุการณ์ที่พบ (Detailed Issue)',
    )
    detailed_issue2 = models.CharField(
        max_length=255, choices=DETAILED_ISSUE_CHOICES2, default='Investigating Other',
        verbose_name='เรื่องที่แจ้ง',
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        verbose_name='ผู้เปิดงาน',
    )

    # ── Source Wazuh alert (optional) ────────────────────────────────── #
    wazuh_alert = models.OneToOneField(
        'wazuh_ingest.WazuhAlert', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket', verbose_name='Wazuh Alert',
    )

    # Analyst response time: how long from the source alert becoming actionable
    # (wazuh_alert.ingested_at) until this ticket was raised (created_at).
    # Stamped once at creation and never recomputed, so it survives the alert
    # row being nulled (wazuh_alert is on_delete=SET_NULL). Null for tickets
    # created manually with no source alert — those have no conversion time.
    alert_conversion_duration = models.DurationField(
        null=True, blank=True,
        verbose_name='เวลาตอบสนอง (Alert พร้อมรับ → เปิด Ticket)',
        help_text='created_at − wazuh_alert.ingested_at, stamped once at creation.',
    )

    # OLA policy per severity: (triage_target, contain_target).
    #   triage  = time to raise/send the ticket (measured from incident time).
    #   contain = time to resolve; None = notification-only (no resolve deadline).
    # Unknown mirrors Critical. This dict is the single place to change the OLA
    # policy values.
    OLA_TARGETS = {
        'Critical': (timedelta(minutes=30), timedelta(hours=4)),
        'High':     (timedelta(hours=2),    timedelta(hours=24)),
        'Medium':   (timedelta(hours=24),   None),
        'Low':      (timedelta(hours=24),   None),
        'Unknown':  (timedelta(minutes=30), timedelta(hours=4)),
    }

    # ------------------------------------------------------------------ #
    # Properties                                                          #
    # ------------------------------------------------------------------ #

    @property
    def is_event(self):
        """Benign Event (was False Positive) — the close-without-action path."""
        return self.classification == self.CLASSIFICATION_EVENT

    @property
    def is_incident(self):
        """Actionable Incident (was True Positive) — proceeds to containment."""
        return self.classification == self.CLASSIFICATION_INCIDENT

    # Lines like "1) ...", "1. ...", "- ..." or "• ..." are checklist items;
    # anything else (the หมายเหตุ coordination note, free prose) is trailing text.
    _CHECKLIST_ITEM_RE = re.compile(r'^\s*(?:\d+[.)]|[-•])\s+\S')

    @classmethod
    def parse_checklist_items(cls, text):
        """Split action_required text into (item_lines, trailing_lines)."""
        items, trailing = [], []
        for line in (text or '').splitlines():
            if cls._CHECKLIST_ITEM_RE.match(line):
                items.append(line.strip())
            elif line.strip():
                trailing.append(line.rstrip())
        return items, trailing

    def containment_checklist_display(self):
        """Checklist for the *current* action_required with done-states restored.

        Returns ``(items, trailing)`` where items is ``[{'text', 'done'}]`` and
        trailing is the non-item text. Done-states are matched by item text
        against the saved ``containment_checklist`` so a Tier 2 rejection keeps
        prior ticks (an item whose wording changed comes back unticked).
        """
        saved = {
            entry.get('text'): bool(entry.get('done'))
            for entry in (self.containment_checklist or [])
        }
        item_lines, trailing_lines = self.parse_checklist_items(self.action_required)
        items = [{'text': line, 'done': saved.get(line, False)} for line in item_lines]
        return items, '\n'.join(trailing_lines)

    @property
    def mitre_phase_list(self):
        """MITRE ATT&CK phase codes recorded on this ticket (multi-select)."""
        return [p for p in self.mitre_phase.split(',') if p]

    @property
    def mitre_phase_labels(self):
        """Human labels for the recorded MITRE ATT&CK phases."""
        labels = dict(self.MITRE_PHASE_CHOICES)
        return [labels.get(p, p) for p in self.mitre_phase_list]

    @property
    def was_escalated_to_t2(self):
        """True if this ticket was escalated to Tier 2 at any point in its life."""
        return self.escalated_to_t2_at is not None

    @property
    def is_bundled(self):
        """Part of a multi-system Project Incident (case bundle)."""
        return self.project_incident_id is not None

    @property
    def bundle_ref(self):
        """Trackable id within a bundle, e.g. 'PI-260706-01-C'. '' if unbundled."""
        if self.project_incident_id and self.bundle_suffix:
            return f'{self.project_incident.project_code}-{self.bundle_suffix}'
        return ''

    @property
    def display_id(self):
        """The stable public Ticket Reference, regardless of bundle membership."""
        return self.ticket_id

    @property
    def requires_manager_verification(self):
        """Single rule deciding whether a verified ticket must additionally be
        approved by the SOC manager before it can close.

        True only when the emergency flag is set. Severity alone never routes
        to the manager — Tier 2 verification is the standard closing gate.
        """
        return self.is_emergency

    @property
    def is_ola_triage_breached(self):
        """
        Triage OLA: was the ticket raised later than its triage/send deadline?
        Fixed at issue time (created_at), not a live countdown against now().
        """
        if self.ola_triage_deadline and self.created_at:
            return self.created_at > self.ola_triage_deadline
        return False

    # Backwards-compatible alias — "OLA breached" has always meant the
    # raise-in-time (triage) breach that templates highlight.
    @property
    def is_ola_breached(self):
        return self.is_ola_triage_breached

    @property
    def is_ola_contain_breached(self):
        """
        Contain OLA: an active ticket now past its contain/resolve deadline
        (live vs now()). False when there is no contain deadline (Medium/Low
        are notification-only) or the ticket is already terminal.
        """
        if self.ola_contain_deadline and self.status not in self.TERMINAL_STATUSES:
            return timezone.now() > self.ola_contain_deadline
        return False

    @property
    def ola_remaining(self):
        """Triage margin left at the moment the ticket was issued (fixed, not live)."""
        if self.ola_triage_deadline and self.created_at:
            return self.ola_triage_deadline - self.created_at
        return None

    @property
    def is_ola_urgent(self):
        """Triaged within OLA, but with less than 1 hour of margin to spare."""
        remaining = self.ola_remaining
        if remaining is None:
            return False
        return timedelta() < remaining <= timedelta(hours=1)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.ticket_id} - {self.device_name}'

    # ------------------------------------------------------------------ #
    # Save                                                                #
    # ------------------------------------------------------------------ #

    # How many times to regenerate ticket_id when a concurrent insert wins the
    # unique-constraint race before giving up.
    _ID_MAX_RETRIES = 5

    @staticmethod
    def ticket_id_prefix(when):
        """Return the monthly public-reference prefix for ``when``."""
        return f'SOC-{when.year:04d}{when.month:02d}-'

    def _assign_ticket_id(self):
        """Compute the next monthly Ticket Reference: SOC-YYYYMM-NNNN.

        This read-then-write is racy on its own; ``save()`` retries after a
        unique-constraint collision to close the window against committed rows.
        """
        now = timezone.now()
        prefix = self.ticket_id_prefix(now)
        last = (
            Ticket.objects.filter(ticket_id__startswith=prefix)
            .order_by('-ticket_id')
            .first()
        )
        if last:
            try:
                seq = int(last.ticket_id.rsplit('-', 1)[1]) + 1
            except (ValueError, IndexError):
                seq = 1
        else:
            seq = 1

        self.ticket_id = f'{prefix}{seq:04d}'
        while Ticket.objects.filter(ticket_id=self.ticket_id).exists():
            seq += 1
            self.ticket_id = f'{prefix}{seq:04d}'

    def save(self, *args, **kwargs):
        if not self.pk:
            # OLA clocks start when the alert/incident occurred, not when the
            # ticket is filed — fall back to now() if T1 left it blank. Targets
            # are per-severity (OLA_TARGETS); Medium/Low have no contain target.
            base_time = self.incident_datetime or timezone.now()
            triage_target, contain_target = self.OLA_TARGETS.get(
                self.severity, self.OLA_TARGETS['Unknown'])
            if not self.ola_triage_deadline and triage_target is not None:
                self.ola_triage_deadline = base_time + triage_target
            if not self.ola_contain_deadline and contain_target is not None:
                self.ola_contain_deadline = base_time + contain_target

        if not self.pk and not self.status_changed_at:
            # A brand-new ticket enters its initial status now; seed the
            # status-change clock so the field is never null going forward.
            self.status_changed_at = timezone.now()

        # Already-id'd rows (updates, or an explicit id) save straight through.
        if self.ticket_id and self.ticket_id.strip():
            super().save(*args, **kwargs)
            return

        # New ticket needing a generated id: the per-month sequence is a
        # read-then-write, so two concurrent inserts can compute the same NN and
        # one then violates the unique id. Retry with a freshly recomputed id;
        # each attempt runs in a savepoint so the failed INSERT doesn't poison
        # the caller's surrounding transaction (see ProjectIncident.save).
        for attempt in range(self._ID_MAX_RETRIES):
            self._assign_ticket_id()
            try:
                with transaction.atomic():
                    super().save(*args, **kwargs)
                return
            except IntegrityError:
                if attempt == self._ID_MAX_RETRIES - 1:
                    raise

    # ------------------------------------------------------------------ #
    # State machine                                                       #
    # ------------------------------------------------------------------ #

    def can_transition_to(self, new_status):
        """Return True if new_status is a legal next state for this ticket,
        honoring the Event/Incident classification gate and the manager-routing
        rule but ignoring per-user permissions.
        """
        edge = (self.status, new_status)
        if new_status not in self.ALLOWED_TRANSITIONS.get(self.status, []):
            return False
        if edge in self.EVENT_CLOSE_TRANSITIONS and not self.is_event:
            return False
        if edge in self.INCIDENT_TRANSITIONS and not self.is_incident:
            return False
        # SOC Manager forward at the pre-containment review: the manager can only
        # send the ticket to the lane Tier 1 already chose (t1_route), never the
        # other one. This keeps the case "on the way either way" — the manager
        # flags Emergency but cannot divert it.
        if (edge == (self.STATUS_PENDING_MGR_TRIAGE, self.STATUS_AWAITING_CONTAINMENT)
                and self.t1_route != self.T1_ROUTE_ADMIN):
            return False
        if (edge == (self.STATUS_PENDING_MGR_TRIAGE, self.STATUS_AWAITING_OWNER)
                and self.t1_route != self.T1_ROUTE_OWNER):
            return False
        # Emergency split at Tier 2 verification (both lanes): an emergency
        # ticket must additionally pass the SOC manager; a non-emergency ticket
        # is closed by Tier 2 directly and never reaches the manager.
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            return False
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            return False
        if (edge == (self.STATUS_PENDING_T2_REVIEW, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            return False
        if (edge == (self.STATUS_PENDING_T2_REVIEW, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            return False
        return True

    def transition_to(self, new_status, user, note=''):
        status_map = dict(self.STATUS_CHOICES)

        # ── 1. Validate new_status is a known code ────────────────────── #
        if new_status not in status_map:
            raise ValidationError(f"'{new_status}' ไม่ใช่สถานะที่ถูกต้อง")

        # ── 2. Same-status = note-only update (SOC only; creator-gated) ─ #
        if new_status == self.status:
            profile = getattr(user, 'profile', None)
            if not user.is_superuser and (profile is None or not profile.is_soc):
                raise ValidationError(
                    'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเพิ่มบันทึกได้'
                )
            if (
                not user.is_superuser
                and self.status in self.CREATOR_REVIEW_STATUSES
                and user.pk != self.created_by_id
            ):
                raise ValidationError(
                    'เฉพาะผู้เปิด Ticket นี้เท่านั้นที่สามารถตรวจสอบ/เพิ่มบันทึกในขั้นตอนนี้ได้'
                )
            self.save()
            TicketLog.objects.create(
                ticket=self, note=note, status_at_time=self.status, author=user,
            )
            return

        # ── 3. Check legal transition ─────────────────────────────────── #
        if new_status not in self.ALLOWED_TRANSITIONS.get(self.status, []):
            raise ValidationError(
                f"ไม่สามารถเปลี่ยนสถานะจาก "
                f"'{status_map.get(self.status, self.status)}' "
                f"เป็น '{status_map.get(new_status, new_status)}' ได้"
            )

        prev_status = self.status
        edge = (prev_status, new_status)

        # ── 4. Event/Incident classification gate ─────────────────────── #
        if edge in self.EVENT_CLOSE_TRANSITIONS and not self.is_event:
            raise ValidationError(
                'ต้องจัดประเภทเป็น Event ก่อนจึงจะปิดแบบ Event ได้'
            )
        if edge in self.INCIDENT_TRANSITIONS and not self.is_incident:
            raise ValidationError(
                'ต้องจัดประเภทเป็น Incident ก่อนจึงจะส่งต่อ/ดำเนินการได้'
            )

        # ── 5. Manager-routing gate (deterministic, view-proof) ───────── #
        # 5a. SOC Manager forward honors Tier 1's fixed lane (t1_route): the
        # manager reviews and forwards, but cannot swap Admin ↔ Owner.
        if (edge == (self.STATUS_PENDING_MGR_TRIAGE, self.STATUS_AWAITING_CONTAINMENT)
                and self.t1_route != self.T1_ROUTE_ADMIN):
            raise ValidationError(
                'Ticket นี้ถูกกำหนดเส้นทางเป็น "เจ้าของระบบ" — ส่งให้ผู้ดูแลระบบไม่ได้'
            )
        if (edge == (self.STATUS_PENDING_MGR_TRIAGE, self.STATUS_AWAITING_OWNER)
                and self.t1_route != self.T1_ROUTE_OWNER):
            raise ValidationError(
                'Ticket นี้ถูกกำหนดเส้นทางเป็น "ผู้ดูแลระบบ" — ส่งให้เจ้าของระบบไม่ได้'
            )
        # 5b. Emergency tickets must pass the SOC manager after Tier 2 verifies;
        # non-emergency tickets are closed by Tier 2 and never reach the manager.
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            raise ValidationError(
                'Ticket ฉุกเฉินต้องผ่านการตรวจสอบจากผู้จัดการ SOC ก่อนปิด'
            )
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            raise ValidationError(
                'Ticket นี้ไม่จำเป็นต้องส่งให้ผู้จัดการ — Tier 2 ปิดได้ทันที'
            )
        if (edge == (self.STATUS_PENDING_T2_REVIEW, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            raise ValidationError(
                'Ticket ฉุกเฉินต้องผ่านการตรวจสอบจากผู้จัดการ SOC ก่อนปิด'
            )
        if (edge == (self.STATUS_PENDING_T2_REVIEW, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            raise ValidationError(
                'Ticket นี้ไม่จำเป็นต้องส่งให้ผู้จัดการ — Tier 2 ปิดได้ทันที'
            )

        # ── 6. Check permission ───────────────────────────────────────── #
        required_perm = self.TRANSITION_PERMISSIONS.get(edge)
        profile = getattr(user, 'profile', None)

        if user.is_superuser:
            pass
        elif required_perm == 'TIER1_CREATOR':
            if profile is None or not profile.is_tier1:
                raise ValidationError(
                    'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถดำเนินการนี้ได้'
                )
            if user.pk != self.created_by_id:
                raise ValidationError(
                    'เฉพาะผู้เปิด Ticket นี้ (Tier 1) เท่านั้นที่สามารถดำเนินการต่อได้'
                )
        elif required_perm == 'TIER2':
            if profile is None or not profile.is_tier2:
                raise ValidationError(
                    'เฉพาะเจ้าหน้าที่ SOC Tier 2 เท่านั้นที่สามารถดำเนินการนี้ได้'
                )
        elif required_perm == 'MANAGER':
            if profile is None or not profile.is_soc_manager:
                raise ValidationError(
                    'เฉพาะผู้จัดการ SOC เท่านั้นที่สามารถอนุมัติได้'
                )
        elif required_perm == 'ASSIGNED_ADMIN':
            if self.assigned_admin_id is None or user.pk != self.assigned_admin_id:
                raise ValidationError(
                    'เฉพาะผู้ดูแลระบบที่รับผิดชอบ Ticket นี้เท่านั้น'
                    'ที่สามารถส่งรายงานการควบคุมได้'
                )

        # ── 7. Apply transition ───────────────────────────────────────── #
        self.status = new_status
        now = timezone.now()

        # Record when the status actually changed. We only reach here for a real
        # transition (the same-status note-only path returns at step 2), so this
        # field tracks lifecycle moves exactly — never note edits or emergency
        # toggles, which both keep the status unchanged.
        self.status_changed_at = now

        # Stamp the first-ever escalation to Tier 2 (never cleared afterwards).
        if new_status == self.STATUS_ESCALATED_T2 and self.escalated_to_t2_at is None:
            self.escalated_to_t2_at = now

        # First hand-off to the system admin = the containment report going
        # out (write-once, mirrors the tracker's วันที่ออกรายงาน).
        if (new_status == self.STATUS_AWAITING_CONTAINMENT
                and self.report_issued_at is None):
            self.report_issued_at = now

        # Direct-to-Owner: mark the case as owner-handled and stamp the first
        # owner contact (write-once). The flag is a permanent record of "this
        # ticket took the owner path", used for dashboard segmentation.
        if new_status == self.STATUS_AWAITING_OWNER:
            self.direct_owner_remediation = True
            if self.owner_contacted_at is None:
                self.owner_contacted_at = now

        # Terminal close on either path — approved_at alone misses CLOSED_EVENT.
        if new_status in self.TERMINAL_STATUSES and self.closed_at is None:
            self.closed_at = now

        # Tier 2 verification sign-off (write-once): set when Tier 2 confirms
        # the containment/remediation was effective and moves the case forward
        # — whether it closes directly or routes to the SOC manager.
        if (
            prev_status in (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_PENDING_T2_REVIEW)
            and new_status in (self.STATUS_PENDING_MANAGER, self.STATUS_APPROVED)
            and self.verified_by_id is None
        ):
            self.verified_by = user
            self.verified_at = now

        # Final approval sign-off (write-once).
        if new_status == self.STATUS_APPROVED and self.approved_by_id is None:
            self.approved_by = user
            self.approved_at = now

        self.save()
        TicketLog.objects.create(
            ticket=self, note=note, status_at_time=new_status, author=user,
        )

    # ------------------------------------------------------------------ #
    # Emergency flag                                                      #
    # ------------------------------------------------------------------ #

    def can_set_emergency(self, user):
        """Who may toggle ``is_emergency``.

        SOC Manager only (superuser always may). The canonical decision point
        is the pre-containment review (PENDING_MGR_TRIAGE), where the manager
        rules Emergency yes/no before forwarding to the handling lane — but the
        manager may still correct or raise the flag at any later stage if the
        situation changes. No other role may touch it.
        """
        if user.is_superuser:
            return True
        profile = getattr(user, 'profile', None)
        return profile is not None and profile.is_soc_manager

    def set_emergency(self, value, user, note=''):
        """Set/clear the emergency flag with permission check + audit log.

        Mutable at ANY lifecycle stage (including terminal). Writes a TicketLog
        recording who toggled it and the old→new value.
        """
        value = bool(value)
        if not self.can_set_emergency(user):
            raise ValidationError(
                'คุณไม่มีสิทธิ์เปลี่ยนสถานะฉุกเฉินของ Ticket นี้'
            )
        if value == self.is_emergency:
            return  # no-op — don't pollute the audit trail
        old = self.is_emergency
        self.is_emergency = value
        self.save(update_fields=['is_emergency', 'updated_at'])
        action = 'ตั้งค่า' if value else 'ยกเลิก'
        audit = f'🚨 {action}สถานะฉุกเฉิน (Emergency: {old} → {value})'
        if note:
            audit = f'{audit} — {note}'
        TicketLog.objects.create(
            ticket=self, note=audit, status_at_time=self.status, author=user,
        )


class TicketLog(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='logs')
    note = models.TextField(verbose_name='บันทึกรายละเอียด')
    status_at_time = models.CharField(max_length=30, verbose_name='สถานะขณะบันทึก')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    author = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket_logs', verbose_name='ผู้บันทึก',
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'Log for {self.ticket.ticket_id} - {self.ticket.device_name}'

    @property
    def status_display(self):
        """Human label for the status code recorded at log time."""
        return dict(Ticket.STATUS_CHOICES).get(self.status_at_time, self.status_at_time)


# ======================================================================= #
# Pre-ticket triage                                                        #
# ======================================================================= #

class TriageRecord(models.Model):
    """
    Logs a T1/T2 triage decision BEFORE a ticket is created.

    Three outcomes:
      FP         — False Positive, case closed, no ticket.
      TP         — True Positive, ticket created (linked via .ticket FK).
      ESCALATED  — T1 was unsure; case handed to T2 for final judgment.
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
    # _can_create_ticket_from_triage).
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
    def is_pending_t2(self):
        """True if waiting for T2 to respond to an escalation."""
        return self.decision == self.DECISION_ESCALATED and not self.t2_decision

    @property
    def final_decision(self):
        """Resolved decision: T2's if escalated, else T1's."""
        if self.decision == self.DECISION_ESCALATED:
            return self.t2_decision or 'PENDING'
        return self.decision


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

    TYPE_INVESTIGATION = 'INVESTIGATION'
    TYPE_COUNTERMEASURE = 'COUNTERMEASURE'

    TYPE_CHOICES = [
        (TYPE_INVESTIGATION, 'Investigation'),
        (TYPE_COUNTERMEASURE, 'Countermeasure'),
    ]

    STATUS_OPEN = 'OPEN'
    STATUS_IN_PROGRESS = 'IN_PROGRESS'
    STATUS_DONE = 'DONE'

    STATUS_CHOICES = [
        (STATUS_OPEN, 'เปิด'),
        (STATUS_IN_PROGRESS, 'กำลังดำเนินการ'),
        (STATUS_DONE, 'เสร็จสิ้น'),
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
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='created_subtasks', verbose_name='ผู้สร้าง',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'[{self.get_subtask_type_display()}] {self.title} ({self.ticket.ticket_id})'

    @property
    def is_done(self):
        return self.status == self.STATUS_DONE


# ======================================================================= #
# Notification templates                                                   #
# ======================================================================= #

class NotificationTemplate(models.Model):
    """
    Editable email subject/body for the automated SOC notifications.

    The body and subject are plain strings using Python ``str.format()``
    placeholders — see ``PLACEHOLDERS`` for what each key supports.  If no
    template row exists for a key, the calling code falls back to its
    built-in default text.
    """

    KEY_CONTAINMENT_REQUIRED = 'CONTAINMENT_REQUIRED'
    KEY_CONTAINMENT_SUBMITTED = 'CONTAINMENT_SUBMITTED'
    KEY_MANAGER_TRIAGE_PENDING = 'MANAGER_TRIAGE_PENDING'
    KEY_OWNER_CREATED = 'OWNER_CREATED'
    KEY_OWNER_CLOSED = 'OWNER_CLOSED'

    KEY_CHOICES = [
        (KEY_CONTAINMENT_REQUIRED, 'แจ้งผู้ดูแลระบบ — ต้องดำเนินการควบคุม (Containment required)'),
        (KEY_CONTAINMENT_SUBMITTED, 'แจ้งเจ้าหน้าที่ SOC — ผู้ดูแลระบบส่งรายงานการควบคุมแล้ว'),
        (KEY_MANAGER_TRIAGE_PENDING, 'แจ้งผู้จัดการ SOC — มี Incident รอตรวจก่อนมอบหมาย'),
        (KEY_OWNER_CREATED, 'แจ้งเจ้าของระบบ — เปิด Ticket ใหม่'),
        (KEY_OWNER_CLOSED, 'แจ้งเจ้าของระบบ — ปิด Ticket แล้ว'),
    ]

    # Placeholders available to each template key, shown to admins as a hint.
    PLACEHOLDERS = {
        KEY_CONTAINMENT_REQUIRED: [
            'ticket_id', 'ticket_url', 'issue_type', 'summary', 'reason_block',
        ],
        KEY_MANAGER_TRIAGE_PENDING: [
            'ticket_id', 'ticket_url', 'issue_type', 'summary', 'severity', 'route',
        ],
        KEY_CONTAINMENT_SUBMITTED: [
            'ticket_id', 'ticket_url', 'issue_type', 'summary',
            'admin_name', 'classification', 'containment_report',
        ],
        KEY_OWNER_CREATED: [
            'ticket_id', 'ticket_url', 'owner_name', 'department', 'department_suffix',
            'issue_type', 'device_name', 'summary',
        ],
        KEY_OWNER_CLOSED: [
            'ticket_id', 'ticket_url', 'owner_name', 'department', 'department_suffix',
            'issue_type', 'device_name', 'outcome',
        ],
    }

    key = models.CharField(max_length=50, choices=KEY_CHOICES, unique=True, verbose_name='ประเภทการแจ้งเตือน')
    subject = models.CharField(max_length=255, verbose_name='หัวข้ออีเมล')
    body = models.TextField(verbose_name='เนื้อหาอีเมล')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['key']

    def __str__(self):
        return self.get_key_display()


# ======================================================================= #
# File attachments                                                         #
# ======================================================================= #

# Per-file upload cap — guards against disk-exhaustion DoS from oversized
# uploads. Django has no built-in per-file size limit, so it is enforced
# explicitly in BOTH upload paths (AttachmentForm.clean_file and the
# create_ticket evidence loop). Bump if SOC evidence (pcaps, memory dumps)
# legitimately needs more headroom.
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024  # 25 MB

# Extension allowlist for uploaded evidence. This is a SOC evidence store, so
# the default is deliberately broad — logs, captures, documents, images and
# archives are all legitimate evidence — but it still blocks active-web content
# (.html/.svg/.xhtml/.js …) that could be socially engineered into a stored-XSS
# vector. It is only a second line of defence: download_attachment already
# forces `Content-Disposition: attachment` + `nosniff` so nothing is rendered
# as same-origin script. Override with ATTACHMENT_ALLOWED_EXTENSIONS in .env/
# settings if a deployment needs a different set (e.g. malware-sample intake).
DEFAULT_ALLOWED_ATTACHMENT_EXTENSIONS = frozenset({
    # documents
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'rtf',
    # text / structured logs
    'txt', 'log', 'csv', 'tsv', 'json', 'yaml', 'yml', 'md',
    # images (screenshots) — content is magic-byte verified below
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',
    # archives / captures
    'zip', 'gz', 'tgz', '7z', 'rar', 'tar', 'pcap', 'pcapng', 'cap',
    # mail evidence
    'eml', 'msg',
})

# Leading magic bytes for the renderable types we accept, so a spoofed
# `evil.svg` renamed to `.png` (still active content) is rejected on content,
# not just on its extension.
_ATTACHMENT_MAGIC_BYTES = {
    'png':  (b'\x89PNG\r\n\x1a\n',),
    'gif':  (b'GIF87a', b'GIF89a'),
    'jpg':  (b'\xff\xd8\xff',),
    'jpeg': (b'\xff\xd8\xff',),
    'bmp':  (b'BM',),
    'pdf':  (b'%PDF',),
    # WEBP is a RIFF container: bytes 0-3 'RIFF', bytes 8-11 'WEBP'.
    'webp': (b'RIFF',),
}


def _attachment_extension(name):
    """Lower-cased final extension of ``name`` (no dot), or '' if none."""
    _, _, ext = (name or '').rpartition('.')
    return ext.lower() if ext and '.' in (name or '') else ''


def validate_attachment_size(uploaded_file):
    """Raise ValidationError if an uploaded file exceeds MAX_ATTACHMENT_SIZE."""
    if uploaded_file is not None and uploaded_file.size > MAX_ATTACHMENT_SIZE:
        raise ValidationError(
            f'ไฟล์มีขนาดใหญ่เกินไป — สูงสุด {MAX_ATTACHMENT_SIZE // (1024 * 1024)} MB'
        )


def validate_attachment_type(uploaded_file):
    """Reject disallowed file types by extension, and verify content magic bytes
    for the renderable types (images / PDF) to catch spoofed content.

    Defence-in-depth: uploads are always served as forced downloads with
    ``nosniff`` (see download_attachment), so this guards against social
    engineering and accidental active-content uploads rather than direct code
    execution.
    """
    if uploaded_file is None:
        return

    allowed = getattr(
        settings, 'ATTACHMENT_ALLOWED_EXTENSIONS',
        DEFAULT_ALLOWED_ATTACHMENT_EXTENSIONS,
    )
    ext = _attachment_extension(uploaded_file.name)
    if not ext:
        raise ValidationError('ไฟล์ต้องมีนามสกุล (extension) ที่ชัดเจน')
    if ext not in allowed:
        raise ValidationError(
            f'ชนิดไฟล์ ".{ext}" ไม่ได้รับอนุญาต — '
            f'รองรับเฉพาะเอกสาร รูปภาพ log และไฟล์หลักฐานทั่วไป'
        )

    signatures = _ATTACHMENT_MAGIC_BYTES.get(ext)
    if signatures:
        pos = uploaded_file.tell() if hasattr(uploaded_file, 'tell') else 0
        try:
            uploaded_file.seek(0)
            header = uploaded_file.read(16)
        finally:
            uploaded_file.seek(pos)
        if not any(header.startswith(sig) for sig in signatures):
            raise ValidationError(
                f'เนื้อหาของไฟล์ไม่ตรงกับชนิด ".{ext}" ที่ระบุ — '
                f'ไฟล์อาจถูกปลอมนามสกุล'
            )


def validate_attachment(uploaded_file):
    """Run every attachment guard (size + type/content). Single entry point for
    both upload paths so they can never drift apart."""
    validate_attachment_size(uploaded_file)
    validate_attachment_type(uploaded_file)


def attachment_upload_path(instance, filename):
    return f'ticket_attachments/{instance.ticket.ticket_id}/{filename}'


class TicketAttachment(models.Model):
    """File attached to a ticket — evidence, reports, screenshots, etc."""

    ticket       = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='attachments')
    file         = models.FileField(upload_to=attachment_upload_path)
    original_name = models.CharField(max_length=255)
    description  = models.CharField(max_length=255, blank=True, default='')
    uploaded_by  = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='uploaded_attachments',
    )
    uploaded_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['uploaded_at']

    def __str__(self):
        return f'{self.original_name} → {self.ticket.ticket_id}'


class ThreatGuidance(models.Model):
    """Standard containment guidance per threat category (admin-editable).

    Backing data for the "แทรกแนวทางมาตรฐาน" button on the create-ticket form:
    the analyst picks a threat category (``detailed_issue``) and can insert the
    category's standard สิ่งที่ต้องดำเนินการ / ข้อควรระวัง text, then edit it.
    Content lives here (not in code) so the SOC lead can revise the playbook
    wording in Django admin without a deploy. Seeded by migration 0041.
    """

    detailed_issue = models.CharField(
        max_length=50, unique=True, choices=Ticket.DETAILED_ISSUE_CHOICES,
        verbose_name='หมวดหมู่ภัยคุกคาม',
    )
    action_required = models.TextField(
        blank=True, default='',
        verbose_name='สิ่งที่ต้องดำเนินการ (มาตรฐาน)',
    )
    action_precautions = models.TextField(
        blank=True, default='',
        verbose_name='ข้อควรระวังในการดำเนินการ (มาตรฐาน)',
    )
    is_active = models.BooleanField(default=True, verbose_name='ใช้งาน')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['detailed_issue']
        verbose_name = 'แนวทางมาตรฐานตามหมวดหมู่ภัยคุกคาม'
        verbose_name_plural = 'แนวทางมาตรฐานตามหมวดหมู่ภัยคุกคาม'

    def __str__(self):
        return self.get_detailed_issue_display()
