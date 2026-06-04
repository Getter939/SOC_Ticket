from django.contrib import admin
from .models import Ticket, TicketLog, TriageRecord


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = (
        'ticket_id', 'device_name', 'status', 'disposition',
        'category', 'issue_type',
        'assigned_to', 'assigned_admin', 'created_by', 'created_at',
        'system_owner_name',
    )
    list_filter = ('status', 'disposition', 'category', 'issue_type', 'created_at')
    search_fields = (
        'ticket_id', 'device_name', 'ip_address',
        'assigned_to__username', 'assigned_admin__username',
        'system_owner_name', 'system_owner_email',
    )
    readonly_fields = (
        'ticket_id', 'created_at', 'updated_at',
        'verified_by', 'verified_at',
        'approved_by', 'approved_at',
    )
    raw_id_fields = ('assigned_to', 'assigned_admin', 'created_by')

    fieldsets = (
        ('ข้อมูลทั่วไป', {
            'fields': (
                'ticket_id', 'device_name', 'ip_address',
                'category', 'issue_type', 'detailed_issue', 'detailed_issue2',
                'issue_description', 'update_notes',
            ),
        }),
        ('เจ้าของระบบ', {
            'fields': ('system_owner_name', 'system_owner_email'),
        }),
        ('สถานะและการวินิจฉัย', {
            'fields': ('status', 'disposition', 'containment_report'),
        }),
        ('การมอบหมาย', {
            'fields': ('assigned_to', 'assigned_admin', 'created_by'),
        }),
        ('การรับรอง / อนุมัติ (อ่านอย่างเดียว)', {
            'fields': ('verified_by', 'verified_at', 'approved_by', 'approved_at'),
        }),
        ('SLA และวันที่', {
            'fields': ('sla_deadline', 'created_at', 'updated_at'),
        }),
    )


@admin.register(TicketLog)
class TicketLogAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'author', 'status_at_time', 'created_at')
    list_filter = ('status_at_time',)
    search_fields = ('ticket__ticket_id', 'author__username', 'note')
    raw_id_fields = ('author', 'ticket')


@admin.register(TriageRecord)
class TriageRecordAdmin(admin.ModelAdmin):
    list_display = ('pk', 'analyst', 'decision', 'source_ip', 'escalated_to', 't2_decision', 'created_at')
    list_filter = ('decision', 't2_decision')
    search_fields = ('alert_description', 'source_ip', 'analyst__username')
    readonly_fields = ('created_at', 't2_decided_at')
    raw_id_fields = ('analyst', 'escalated_to', 'ticket')
