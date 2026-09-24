
from django.db import models

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
    KEY_RESPONSE_REQUEST_CREATED = 'RESPONSE_REQUEST_CREATED'
    KEY_RESPONSE_REQUEST_COMPLETED = 'RESPONSE_REQUEST_COMPLETED'

    KEY_CHOICES = [
        (KEY_CONTAINMENT_REQUIRED, 'แจ้งผู้ดูแลระบบ — ต้องดำเนินการควบคุม (Containment required)'),
        (KEY_CONTAINMENT_SUBMITTED, 'แจ้งเจ้าหน้าที่ SOC — ผู้ดูแลระบบส่งรายงานการควบคุมแล้ว'),
        (KEY_MANAGER_TRIAGE_PENDING, 'แจ้งผู้จัดการ SOC — มี Incident รอตรวจก่อนมอบหมาย'),
        (KEY_OWNER_CREATED, 'แจ้งเจ้าของระบบ — เปิด Ticket ใหม่'),
        (KEY_OWNER_CLOSED, 'แจ้งเจ้าของระบบ — ปิด Ticket แล้ว'),
        (KEY_RESPONSE_REQUEST_CREATED, 'แจ้งทีมตอบสนอง — มีคำขอใหม่ (Forensic Analyst / Red Team Manager)'),
        (KEY_RESPONSE_REQUEST_COMPLETED, 'แจ้งผู้จัดการ SOC — คำขอทีมตอบสนองเสร็จสิ้น'),
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
        KEY_RESPONSE_REQUEST_CREATED: [
            'ticket_id', 'ticket_url', 'request_url', 'request_type', 'title',
            'description', 'summary', 'requested_by',
        ],
        KEY_RESPONSE_REQUEST_COMPLETED: [
            'ticket_id', 'ticket_url', 'request_url', 'request_type', 'title',
            'result_notes', 'report_number', 'completed_by',
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
