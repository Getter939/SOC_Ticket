from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from datetime import timedelta


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


class Ticket(models.Model):
    objects = TicketQuerySet.as_manager()

    # ------------------------------------------------------------------ #
    # Status choices — redesigned SOC workflow                            #
    # ------------------------------------------------------------------ #
    STATUS_NEW                  = 'NEW'
    STATUS_ESCALATED_T2         = 'ESCALATED_T2'
    STATUS_T1_REVIEW            = 'T1_REVIEW'
    STATUS_AWAITING_CONTAINMENT = 'AWAITING_CONTAINMENT'
    STATUS_CONTAINMENT_REPORTED = 'CONTAINMENT_REPORTED'
    STATUS_PENDING_MANAGER      = 'PENDING_MANAGER'
    STATUS_APPROVED             = 'APPROVED'
    STATUS_CLOSED_EVENT         = 'CLOSED_EVENT'

    STATUS_CHOICES = [
        (STATUS_NEW,                  'แจ้งเหตุใหม่'),
        (STATUS_ESCALATED_T2,         'ส่งต่อให้ Tier 2'),
        (STATUS_T1_REVIEW,            'รอ Tier 1 ทบทวน'),
        (STATUS_AWAITING_CONTAINMENT, 'รอการจัดการจากผู้ดูแลระบบ'),
        (STATUS_CONTAINMENT_REPORTED, 'รายงานการควบคุมแล้ว'),
        (STATUS_PENDING_MANAGER,      'รอผู้จัดการตรวจสอบ'),
        (STATUS_APPROVED,             'อนุมัติแล้ว'),
        (STATUS_CLOSED_EVENT,         'ปิด (Event)'),
    ]

    # States where no further action is possible
    TERMINAL_STATUSES = frozenset({STATUS_APPROVED, STATUS_CLOSED_EVENT})

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
    # State-machine: legal transitions                                    #
    # ------------------------------------------------------------------ #
    ALLOWED_TRANSITIONS = {
        STATUS_NEW: [
            STATUS_AWAITING_CONTAINMENT,   # Incident → assign admin directly
            STATUS_ESCALATED_T2,           # Incident → escalate to Tier 2
            STATUS_CLOSED_EVENT,           # Event    → T1 closes
        ],
        STATUS_ESCALATED_T2: [
            STATUS_T1_REVIEW,              # Incident → T2 returns to Tier 1
            STATUS_CLOSED_EVENT,           # Event    → T2 closes
        ],
        STATUS_T1_REVIEW: [
            STATUS_AWAITING_CONTAINMENT,   # T1 reviews → assign admin
        ],
        STATUS_AWAITING_CONTAINMENT: [
            STATUS_CONTAINMENT_REPORTED,   # admin returns to T1
        ],
        STATUS_CONTAINMENT_REPORTED: [
            STATUS_AWAITING_CONTAINMENT,   # not contained → back to admin (loop)
            STATUS_PENDING_MANAGER,        # contained + needs manager verification
            STATUS_APPROVED,               # contained + no manager needed → T1 closes
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
        (STATUS_NEW,                  STATUS_AWAITING_CONTAINMENT): 'TIER1_CREATOR',
        (STATUS_NEW,                  STATUS_ESCALATED_T2):         'TIER1_CREATOR',
        (STATUS_NEW,                  STATUS_CLOSED_EVENT):         'TIER1_CREATOR',
        (STATUS_ESCALATED_T2,         STATUS_T1_REVIEW):           'TIER2',
        (STATUS_ESCALATED_T2,         STATUS_CLOSED_EVENT):        'TIER2',
        (STATUS_T1_REVIEW,            STATUS_AWAITING_CONTAINMENT): 'TIER1_CREATOR',
        (STATUS_AWAITING_CONTAINMENT, STATUS_CONTAINMENT_REPORTED): 'ASSIGNED_ADMIN',
        (STATUS_CONTAINMENT_REPORTED, STATUS_AWAITING_CONTAINMENT): 'TIER1_CREATOR',
        (STATUS_CONTAINMENT_REPORTED, STATUS_PENDING_MANAGER):      'TIER1_CREATOR',
        (STATUS_CONTAINMENT_REPORTED, STATUS_APPROVED):             'TIER1_CREATOR',
        (STATUS_PENDING_MANAGER,      STATUS_APPROVED):             'MANAGER',
    }

    # Statuses on the Tier 1 side of the lifecycle that are gated to the
    # ticket's original creator (same analyst who opened it). Used both by
    # transition_to and the same-status note guard.
    CREATOR_REVIEW_STATUSES = frozenset({
        STATUS_T1_REVIEW, STATUS_CONTAINMENT_REPORTED,
    })

    # Edges that close a benign Event — require classification == EVENT.
    EVENT_CLOSE_TRANSITIONS = frozenset({
        (STATUS_NEW,          STATUS_CLOSED_EVENT),
        (STATUS_ESCALATED_T2, STATUS_CLOSED_EVENT),
    })

    # Edges that commit to handling an Incident — require classification == INCIDENT.
    INCIDENT_TRANSITIONS = frozenset({
        (STATUS_NEW,          STATUS_AWAITING_CONTAINMENT),
        (STATUS_NEW,          STATUS_ESCALATED_T2),
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
    ]

    # Ordered severity ranks for the manager-routing floor. Severities not in
    # this map (e.g. unknown/blank) rank 0 and never meet the floor.
    SEVERITY_RANK = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}

    # Manager-verification floor (config constant). A ticket at or above this
    # severity always routes to the SOC manager. Default Critical → High/Unknown
    # reach the manager only via the emergency flag. Override in settings.
    SEVERITY_FLOOR = 'Critical'

    ASSET_TYPE_CHOICES = [
        ('Computer',       'Computer'),
        ('Server',         'Server'),
        ('Network Device', 'Network Device'),
    ]

    CATEGORY_CHOICES = [
        ('Cyber Event', 'Cyber Event'),
        ('Incident', 'Incident'),
        ('Cyber Event/Incident', 'Cyber Event/Incident'),
    ]

    TYPE_CHOICES = [
        ('SIEM', 'ระบบเฝ้าระวัง (SIEM)'),
        ('Admin', 'ผู้ดูแลระบบ (Admin)'),
        ('TI', 'Threat Intelligence (TI)'),
        ('External', 'หน่วยงานภายนอก (External organization)'),
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

    # ------------------------------------------------------------------ #
    # Fields                                                              #
    # ------------------------------------------------------------------ #
    ticket_id = models.CharField(max_length=20, unique=True, editable=False, blank=True)

    # ── Section 1: General Information ──────────────────────────────── #
    severity = models.CharField(
        max_length=10, choices=SEVERITY_CHOICES, default='High',
        verbose_name='ระดับความรุนแรง',
    )
    incident_datetime = models.DateTimeField(
        null=True, blank=True,
        verbose_name='วันและเวลาที่ตรวจพบเหตุการณ์',
    )
    reference_id = models.CharField(
        max_length=50, blank=True, default='',
        verbose_name='Reference',
    )

    # ── Section 3: Description ───────────────────────────────────────── #
    device_name = models.CharField(max_length=100, verbose_name='ระบบ / บริการ (System/Service)')
    issue_description = models.TextField(verbose_name='รายละเอียดเหตุการณ์')

    # ── Section 4: Scope / Affected Asset ───────────────────────────── #
    ip_address = models.GenericIPAddressField(verbose_name='IP Address ของทรัพย์สิน')
    mac_address = models.CharField(
        max_length=50, blank=True, default='',
        verbose_name='MAC Address',
    )
    asset_type = models.CharField(
        max_length=20, choices=ASSET_TYPE_CHOICES, blank=True, default='',
        verbose_name='ประเภทของทรัพย์สิน',
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
    mitre_phase = models.CharField(
        max_length=200, blank=True, default='',
        choices=MITRE_PHASE_CHOICES,
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

    # Emergency marker — mutable at ANY lifecycle stage (see set_emergency /
    # can_set_emergency). Feeds requires_manager_verification.
    is_emergency = models.BooleanField(
        default=False, verbose_name='เหตุฉุกเฉิน (Emergency)',
    )

    # ── System Owner ─────────────────────────────────────────────────── #
    # FK to the registered System Owner user account.  Their email and
    # department are read from their User / UserProfile at notification time.
    system_owner = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='owned_tickets',
        verbose_name='เจ้าของระบบ / หน่วยงาน',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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

    update_notes = models.TextField(blank=True, null=True, verbose_name='บันทึกการติดตามงาน')
    sla_deadline = models.DateTimeField(null=True, blank=True, verbose_name='SLA Deadline')
    category = models.CharField(
        max_length=50, choices=CATEGORY_CHOICES, default='Cyber Event',
        verbose_name='Category',
    )
    issue_type = models.CharField(
        max_length=50, choices=TYPE_CHOICES, default='SIEM',
        verbose_name='Type',
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

    SLA_HOURS = 4

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

    @property
    def was_escalated_to_t2(self):
        """True if this ticket was escalated to Tier 2 at any point in its life."""
        return self.escalated_to_t2_at is not None

    @property
    def requires_manager_verification(self):
        """Single tunable rule deciding whether a contained ticket must be
        verified by the SOC manager before it can close.

        True when the severity is at or above ``SEVERITY_FLOOR`` (default
        Critical, override via ``settings.SOC_SEVERITY_FLOOR``) OR the emergency
        flag is set. No other auto-triggers.
        """
        floor = getattr(settings, 'SOC_SEVERITY_FLOOR', self.SEVERITY_FLOOR)
        severity_meets_floor = (
            self.SEVERITY_RANK.get(self.severity, 0)
            >= self.SEVERITY_RANK.get(floor, 99)
        )
        return severity_meets_floor or self.is_emergency

    @property
    def is_sla_breached(self):
        """
        SLA clock stops once the ticket is issued (created) — containment
        progress afterwards no longer affects this. Breach is therefore a
        fixed fact about whether the ticket was raised within SLA, not a
        live countdown against now().
        """
        if self.sla_deadline and self.created_at:
            return self.created_at > self.sla_deadline
        return False

    @property
    def sla_remaining(self):
        """Time margin left at the moment the ticket was issued (fixed, not live)."""
        if self.sla_deadline and self.created_at:
            return self.sla_deadline - self.created_at
        return None

    @property
    def is_sla_urgent(self):
        """Issued within SLA, but with less than 1 hour of margin to spare."""
        remaining = self.sla_remaining
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

    def save(self, *args, **kwargs):
        if not self.pk and not self.sla_deadline:
            # SLA clock starts when the alert/incident occurred, not when
            # the ticket is filed — fall back to now() if T1 left it blank.
            base_time = self.incident_datetime or timezone.now()
            self.sla_deadline = base_time + timedelta(hours=self.SLA_HOURS)

        if not self.ticket_id or self.ticket_id.strip() == '':
            now = timezone.now()
            prefix = f'{now.year % 100:02d}{now.month:02d}'  # e.g. '2606' for June 2026
            last = (
                Ticket.objects.filter(ticket_id__startswith=prefix)
                .order_by('-ticket_id')
                .first()
            )
            if last:
                try:
                    seq = int(last.ticket_id[4:]) + 1
                except (ValueError, IndexError):
                    seq = 1
            else:
                seq = 1

            self.ticket_id = f'{prefix}{seq:02d}'
            while Ticket.objects.filter(ticket_id=self.ticket_id).exists():
                seq += 1
                self.ticket_id = f'{prefix}{seq:02d}'

        super().save(*args, **kwargs)

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
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            return False
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_PENDING_MANAGER)
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
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            raise ValidationError(
                'Ticket นี้ต้องผ่านการตรวจสอบจากผู้จัดการ SOC ก่อนปิด'
            )
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            raise ValidationError(
                'Ticket นี้ไม่จำเป็นต้องส่งให้ผู้จัดการ — Tier 1 ปิดได้ทันที'
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

        # Stamp the first-ever escalation to Tier 2 (never cleared afterwards).
        if new_status == self.STATUS_ESCALATED_T2 and self.escalated_to_t2_at is None:
            self.escalated_to_t2_at = now

        # T1 verification sign-off (write-once): set when Tier 1 marks a
        # contained ticket done — whether it routes to the manager or closes.
        if (
            prev_status == self.STATUS_CONTAINMENT_REPORTED
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

        Any authenticated role may set/clear it EXCEPT a Tier 1 analyst, who may
        only do so on a ticket that was escalated to Tier 2 at some point
        (``was_escalated_to_t2``). Superuser always may.
        """
        if user.is_superuser:
            return True
        profile = getattr(user, 'profile', None)
        if profile is None:
            return False
        if profile.is_tier1:
            return self.was_escalated_to_t2
        return True

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

    SOURCE_EMAIL = 'EMAIL'
    SOURCE_PHONE = 'PHONE'
    SOURCE_USER_REPORT = 'USER_REPORT'
    SOURCE_EXTERNAL = 'EXTERNAL'
    SOURCE_OTHER = 'OTHER'

    SOURCE_CHOICES = [
        (SOURCE_EMAIL, 'Email'),
        (SOURCE_PHONE, 'Phone / Hotline'),
        (SOURCE_USER_REPORT, 'User / Internal Report'),
        (SOURCE_EXTERNAL, 'External Organization'),
        (SOURCE_OTHER, 'Other'),
    ]

    T1_DECISION_CHOICES = [
        (DECISION_FP,        'False Positive — ปิดทันที'),
        (DECISION_TP,        'True Positive — สร้าง Ticket'),
        (DECISION_ESCALATED, 'ไม่แน่ใจ — Escalate ไปยัง T2'),
    ]

    T2_DECISION_CHOICES = [
        (DECISION_FP, 'False Positive — ปิด'),
        (DECISION_TP, 'True Positive — สร้าง Ticket'),
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
        max_length=20, choices=T1_DECISION_CHOICES, verbose_name='การตัดสินใจ T1',
    )
    notes = models.TextField(blank=True, default='', verbose_name='บันทึก T1')
    created_at = models.DateTimeField(auto_now_add=True)

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
    KEY_OWNER_CREATED = 'OWNER_CREATED'
    KEY_OWNER_CLOSED = 'OWNER_CLOSED'

    KEY_CHOICES = [
        (KEY_CONTAINMENT_REQUIRED, 'แจ้งผู้ดูแลระบบ — ต้องดำเนินการควบคุม (Containment required)'),
        (KEY_CONTAINMENT_SUBMITTED, 'แจ้งเจ้าหน้าที่ SOC — ผู้ดูแลระบบส่งรายงานการควบคุมแล้ว'),
        (KEY_OWNER_CREATED, 'แจ้งเจ้าของระบบ — เปิด Ticket ใหม่'),
        (KEY_OWNER_CLOSED, 'แจ้งเจ้าของระบบ — ปิด Ticket แล้ว'),
    ]

    # Placeholders available to each template key, shown to admins as a hint.
    PLACEHOLDERS = {
        KEY_CONTAINMENT_REQUIRED: [
            'ticket_id', 'ticket_url', 'category', 'issue_type', 'summary', 'reason_block',
        ],
        KEY_CONTAINMENT_SUBMITTED: [
            'ticket_id', 'ticket_url', 'category', 'issue_type', 'summary',
            'admin_name', 'classification', 'containment_report',
        ],
        KEY_OWNER_CREATED: [
            'ticket_id', 'ticket_url', 'owner_name', 'department', 'department_suffix',
            'category', 'issue_type', 'device_name', 'summary',
        ],
        KEY_OWNER_CLOSED: [
            'ticket_id', 'ticket_url', 'owner_name', 'department', 'department_suffix',
            'category', 'issue_type', 'device_name', 'outcome',
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


def validate_attachment_size(uploaded_file):
    """Raise ValidationError if an uploaded file exceeds MAX_ATTACHMENT_SIZE."""
    if uploaded_file is not None and uploaded_file.size > MAX_ATTACHMENT_SIZE:
        raise ValidationError(
            f'ไฟล์มีขนาดใหญ่เกินไป — สูงสุด {MAX_ATTACHMENT_SIZE // (1024 * 1024)} MB'
        )


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
