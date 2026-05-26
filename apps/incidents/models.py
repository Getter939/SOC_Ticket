from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from datetime import timedelta


class Ticket(models.Model):
    STATUS_CHOICES = [
        ('Open', 'รอดำเนินการ'),
        ('In Progress', 'กำลังแก้ไข'),
        ('Resolved', 'แก้ไขแล้ว'),
        ('Closed', 'ปิดงาน'),
    ]

    ALLOWED_TRANSITIONS = {
        'Open':        ['In Progress', 'Resolved'],
        'In Progress': ['Open', 'Resolved'],
        'Resolved':    ['In Progress', 'Closed'],
        'Closed':      [],
    }

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

    # Fields
    ticket_id = models.CharField(max_length=20, unique=True, editable=False, blank=True)
    device_name = models.CharField(max_length=100, verbose_name="IP Source")
    ip_address = models.GenericIPAddressField(verbose_name="IP Destination")
    issue_description = models.TextField(verbose_name="รายละเอียด")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Open')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='assigned_tickets',
    )
    update_notes = models.TextField(blank=True, null=True, verbose_name="บันทึกการติดตามงาน")
    sla_deadline = models.DateTimeField(null=True, blank=True, verbose_name="SLA Deadline")
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='Cyber Event', verbose_name="Category")
    issue_type = models.CharField(max_length=50, choices=TYPE_CHOICES, default='SIEM', verbose_name="Type")
    detailed_issue = models.CharField(
        max_length=255, choices=DETAILED_ISSUE_CHOICES, default='Investigating', verbose_name="เหตุการณ์ที่พบ (Detailed Issue)"
    )
    detailed_issue2 = models.CharField(
        max_length=255, choices=DETAILED_ISSUE_CHOICES2, default='Investigating Other', verbose_name="เรื่องที่แจ้ง"
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="ผู้เปิดงาน"
    )

    SLA_HOURS = 48  # Default SLA: 48 hours

    @property
    def is_sla_breached(self):
        if self.status in ('Resolved', 'Closed'):
            return False
        if self.sla_deadline:
            return timezone.now() > self.sla_deadline
        return False

    @property
    def sla_remaining(self):
        """Returns timedelta remaining, negative if breached."""
        if self.sla_deadline:
            return self.sla_deadline - timezone.now()
        return None

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.ticket_id} - {self.device_name}"

    def save(self, *args, **kwargs):
        # Auto-set SLA deadline on first save
        if not self.pk and not self.sla_deadline:
            self.sla_deadline = timezone.now() + timedelta(hours=self.SLA_HOURS)

        if not self.ticket_id or self.ticket_id.strip() == "":
            last_ticket = Ticket.objects.filter(ticket_id__startswith="SOC-").order_by('-ticket_id').first()
            if last_ticket:
                try:
                    last_no = int(last_ticket.ticket_id.split('-')[-1])
                    new_no = last_no + 1
                except (ValueError, IndexError):
                    new_no = 1
            else:
                new_no = 1

            self.ticket_id = f"SOC-{new_no:04d}"
            while Ticket.objects.filter(ticket_id=self.ticket_id).exists():
                new_no += 1
                self.ticket_id = f"SOC-{new_no:04d}"

        super().save(*args, **kwargs)

    def can_transition_to(self, new_status):
        return new_status in self.ALLOWED_TRANSITIONS.get(self.status, [])

    def transition_to(self, new_status, user, note):
        """Change status and record a TicketLog. Same-status is allowed (note-only update)."""
        valid_codes = {code for code, _ in self.STATUS_CHOICES}
        if new_status not in valid_codes:
            raise ValidationError(f"'{new_status}' ไม่ใช่สถานะที่ถูกต้อง")
        if new_status != self.status and not self.can_transition_to(new_status):
            current_label = self.get_status_display()
            new_label = dict(self.STATUS_CHOICES).get(new_status, new_status)
            raise ValidationError(
                f"ไม่สามารถเปลี่ยนสถานะจาก '{current_label}' เป็น '{new_label}' ได้"
            )
        self.status = new_status
        self.save()
        TicketLog.objects.create(
            ticket=self,
            note=note,
            status_at_time=new_status,
            author=user,
        )


class TicketLog(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='logs')
    note = models.TextField(verbose_name="บันทึกรายละเอียด")
    status_at_time = models.CharField(max_length=20, verbose_name="สถานะขณะบันทึก")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    author = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket_logs', verbose_name="ผู้บันทึก",
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Log for {self.ticket.ticket_id} - {self.ticket.device_name}"
