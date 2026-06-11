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
    # Status choices — SOC containment workflow                           #
    # ------------------------------------------------------------------ #
    STATUS_NEW                  = 'NEW'
    STATUS_AWAITING_CONTAINMENT = 'AWAITING_CONTAINMENT'
    STATUS_CONTAINMENT_REPORTED = 'CONTAINMENT_REPORTED'
    STATUS_UNDER_REVIEW         = 'UNDER_REVIEW'
    STATUS_VERIFIED             = 'VERIFIED'
    STATUS_APPROVED             = 'APPROVED'
    STATUS_CLOSED_FP            = 'CLOSED_FP'

    STATUS_CHOICES = [
        (STATUS_NEW,                  'แจ้งเหตุใหม่'),
        (STATUS_AWAITING_CONTAINMENT, 'รอการจัดการจากผู้ดูแลระบบ'),
        (STATUS_CONTAINMENT_REPORTED, 'รายงานการควบคุมแล้ว'),
        (STATUS_UNDER_REVIEW,         'กำลังตรวจสอบ'),
        (STATUS_VERIFIED,             'ตรวจสอบแล้ว'),
        (STATUS_APPROVED,             'อนุมัติแล้ว'),
        (STATUS_CLOSED_FP,            'ปิด (เหตุการณ์ปลอม)'),
    ]

    # States where no further action is possible
    TERMINAL_STATUSES = frozenset({STATUS_APPROVED, STATUS_CLOSED_FP})

    # ------------------------------------------------------------------ #
    # Disposition choices                                                  #
    # ------------------------------------------------------------------ #
    DISP_TRUE_POSITIVE  = 'TRUE_POSITIVE'
    DISP_FALSE_POSITIVE = 'FALSE_POSITIVE'

    DISPOSITION_CHOICES = [
        (DISP_TRUE_POSITIVE,  'เหตุการณ์จริง (True Positive)'),
        (DISP_FALSE_POSITIVE, 'เหตุการณ์ปลอม (False Positive)'),
    ]

    # ------------------------------------------------------------------ #
    # State-machine: legal transitions                                    #
    # ------------------------------------------------------------------ #
    ALLOWED_TRANSITIONS = {
        STATUS_NEW:                  [STATUS_AWAITING_CONTAINMENT],
        STATUS_AWAITING_CONTAINMENT: [STATUS_CONTAINMENT_REPORTED],
        STATUS_CONTAINMENT_REPORTED: [STATUS_UNDER_REVIEW],
        STATUS_UNDER_REVIEW:         [STATUS_VERIFIED, STATUS_AWAITING_CONTAINMENT, STATUS_CLOSED_FP],
        STATUS_VERIFIED:             [STATUS_APPROVED],
        STATUS_APPROVED:             [],
        STATUS_CLOSED_FP:            [],
    }

    # ------------------------------------------------------------------ #
    # Permission map: (from, to) → required permission                   #
    # ------------------------------------------------------------------ #
    TRANSITION_PERMISSIONS = {
        (STATUS_NEW,                  STATUS_AWAITING_CONTAINMENT): 'SOC',
        (STATUS_AWAITING_CONTAINMENT, STATUS_CONTAINMENT_REPORTED): 'ASSIGNED_ADMIN',
        (STATUS_CONTAINMENT_REPORTED, STATUS_UNDER_REVIEW):         'SOC',
        (STATUS_UNDER_REVIEW,         STATUS_VERIFIED):             'SOC',
        (STATUS_UNDER_REVIEW,         STATUS_AWAITING_CONTAINMENT): 'SOC',
        (STATUS_UNDER_REVIEW,         STATUS_CLOSED_FP):            'SOC',
        (STATUS_VERIFIED,             STATUS_APPROVED):             'MANAGER',
    }

    # ------------------------------------------------------------------ #
    # Other choice sets                                                   #
    # ------------------------------------------------------------------ #
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High',     'High'),
        ('Medium',   'Medium'),
        ('Low',      'Low'),
    ]

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
    mitre_phase = models.CharField(
        max_length=200, blank=True, default='',
        verbose_name='Phase การโจมตีตาม MITRE ATT&CK',
    )

    # ── Section 9: Remediation ──────────────────────────────────────── #
    remediation_summary = models.TextField(
        blank=True, default='',
        verbose_name='สรุปผลการดำเนินการแก้ไข',
    )

    status = models.CharField(
        max_length=30, choices=STATUS_CHOICES, default=STATUS_NEW,
    )
    disposition = models.CharField(
        max_length=20, choices=DISPOSITION_CHOICES, blank=True, default='',
        verbose_name='การวินิจฉัยเหตุการณ์',
    )
    containment_report = models.TextField(
        blank=True, default='',
        verbose_name='รายงานการควบคุม',
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
    wazuh_alert = models.ForeignKey(
        'wazuh_ingest.WazuhAlert', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='tickets', verbose_name='Wazuh Alert',
    )

    SLA_HOURS = 48

    # ------------------------------------------------------------------ #
    # Properties                                                          #
    # ------------------------------------------------------------------ #

    @property
    def is_false_positive(self):
        return self.disposition == self.DISP_FALSE_POSITIVE

    @property
    def is_sla_breached(self):
        if self.status in self.TERMINAL_STATUSES:
            return False
        if self.sla_deadline:
            return timezone.now() > self.sla_deadline
        return False

    @property
    def sla_remaining(self):
        if self.sla_deadline:
            return self.sla_deadline - timezone.now()
        return None

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.ticket_id} - {self.device_name}'

    # ------------------------------------------------------------------ #
    # Save                                                                #
    # ------------------------------------------------------------------ #

    def save(self, *args, **kwargs):
        if not self.pk and not self.sla_deadline:
            self.sla_deadline = timezone.now() + timedelta(hours=self.SLA_HOURS)

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
        """Return True if new_status is a legal next state (ignores permissions).
        Exception: FP tickets can only transition to CLOSED_FP, nothing else.
        """
        if self.is_false_positive and new_status != self.STATUS_CLOSED_FP:
            return False
        return new_status in self.ALLOWED_TRANSITIONS.get(self.status, [])

    def transition_to(self, new_status, user, note=''):
        status_map = dict(self.STATUS_CHOICES)

        # ── 1. FP gate (allow CLOSED_FP transition through) ──────────── #
        if self.is_false_positive and new_status != self.STATUS_CLOSED_FP:
            raise ValidationError(
                'Ticket นี้เป็น False Positive (เหตุการณ์ปลอม) '
                'ใช้ "ปิด (False Positive)" เพื่อปิด Ticket'
            )

        # ── 2. Validate new_status is a known code ────────────────────── #
        if new_status not in status_map:
            raise ValidationError(f"'{new_status}' ไม่ใช่สถานะที่ถูกต้อง")

        # ── 3. Same-status = note-only update (SOC only, TP tickets) ──── #
        if new_status == self.status:
            profile = getattr(user, 'profile', None)
            if profile is None or not profile.is_soc:
                raise ValidationError(
                    'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเพิ่มบันทึกได้'
                )
            self.save()
            TicketLog.objects.create(
                ticket=self, note=note, status_at_time=self.status, author=user,
            )
            return

        # ── 4. Check legal transition ─────────────────────────────────── #
        if new_status not in self.ALLOWED_TRANSITIONS.get(self.status, []):
            raise ValidationError(
                f"ไม่สามารถเปลี่ยนสถานะจาก "
                f"'{status_map.get(self.status, self.status)}' "
                f"เป็น '{status_map.get(new_status, new_status)}' ได้"
            )

        # ── 5. Check permission ───────────────────────────────────────── #
        required_perm = self.TRANSITION_PERMISSIONS.get((self.status, new_status))
        profile = getattr(user, 'profile', None)

        if required_perm == 'SOC':
            if profile is None or not profile.is_soc:
                raise ValidationError(
                    'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถดำเนินการนี้ได้'
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

        # ── 6. Apply transition ───────────────────────────────────────── #
        self.status = new_status

        now = timezone.now()
        if new_status == self.STATUS_VERIFIED and self.verified_by_id is None:
            self.verified_by = user
            self.verified_at = now
        if new_status == self.STATUS_APPROVED and self.approved_by_id is None:
            self.approved_by = user
            self.approved_at = now

        self.save()
        TicketLog.objects.create(
            ticket=self, note=note, status_at_time=new_status, author=user,
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
# File attachments                                                         #
# ======================================================================= #

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
