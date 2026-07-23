from django.contrib import admin
from .models import (
    NotificationTemplate, ProjectIncident, ThreatGuidance, Ticket,
    TicketAttachment, TicketLog, TicketSubtask, TriageRecord,
)


@admin.register(ProjectIncident)
class ProjectIncidentAdmin(admin.ModelAdmin):
    list_display = ('project_code', 'title', 'member_count', 'created_by', 'created_at')
    search_fields = ('project_code', 'title', 'summary')
    readonly_fields = ('project_code', 'created_at', 'updated_at')
    raw_id_fields = ('created_by',)


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = (
        'ticket_id', 'device_name', 'status', 'classification', 'is_emergency',
        'issue_type',
        'assigned_to', 'assigned_admin', 'created_by', 'created_at',
        'system_owner',
    )
    list_filter = ('status', 'classification', 'is_emergency', 'issue_type', 'created_at')
    search_fields = (
        'ticket_id', 'device_name', 'ip_address',
        'assigned_to__username', 'assigned_admin__username',
        'system_owner__username', 'system_owner__first_name',
    )
    readonly_fields = (
        'ticket_id', 'created_at', 'updated_at', 'escalated_to_t2_at',
        'verified_by', 'verified_at',
        'approved_by', 'approved_at',
        'report_template_version', 'report_generated_by', 'report_generated_at',
        'report_ticket_updated_at', 'report_sha256',
    )
    raw_id_fields = (
        'assigned_to', 'assigned_admin', 'created_by', 'system_owner',
        'project_incident', 'report_generated_by',
    )

    fieldsets = (
        ('ข้อมูลทั่วไป', {
            'fields': (
                'ticket_id', 'device_name', 'ip_address',
                'issue_type', 'detailed_issue', 'detailed_issue2',
                'issue_description', 'actions_taken_summary',
                'next_steps_summary', 'update_notes',
            ),
        }),
        ('เจ้าของระบบ', {
            'fields': ('system_owner',),
        }),
        ('สถานะและการจัดประเภท', {
            'fields': ('status', 'classification', 'is_emergency',
                       'escalated_to_t2_at', 'containment_report', 'remediation_summary'),
        }),
        ('การมอบหมาย', {
            'fields': ('assigned_to', 'assigned_admin', 'created_by'),
        }),
        ('Project Incident (Case Bundle)', {
            'fields': ('project_incident', 'bundle_suffix'),
        }),
        ('การรับรอง / อนุมัติ (อ่านอย่างเดียว)', {
            'fields': ('verified_by', 'verified_at', 'approved_by', 'approved_at'),
        }),
        ('Report export metadata (read-only)', {
            'fields': (
                'report_template_version', 'report_generated_by',
                'report_generated_at', 'report_ticket_updated_at', 'report_sha256',
            ),
        }),
        ('OLA และวันที่', {
            'fields': ('ola_triage_deadline', 'ola_contain_deadline',
                       'created_at', 'updated_at'),
        }),
    )


@admin.register(TicketLog)
class TicketLogAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'author', 'status_at_time', 'created_at')
    list_filter = ('status_at_time',)
    search_fields = ('ticket__ticket_id', 'author__username', 'note')
    raw_id_fields = ('author', 'ticket')


@admin.register(TicketSubtask)
class TicketSubtaskAdmin(admin.ModelAdmin):
    list_display = (
        'ticket', 'subtask_type', 'title', 'status', 'assigned_to', 'created_by', 'created_at',
    )
    list_filter = ('subtask_type', 'status')
    search_fields = ('ticket__ticket_id', 'title', 'description')
    raw_id_fields = ('ticket', 'assigned_to', 'created_by')


@admin.register(TicketAttachment)
class TicketAttachmentAdmin(admin.ModelAdmin):
    list_display = (
        'original_name', 'ticket', 'subtask', 'uploaded_by', 'uploaded_at',
        'deleted_by', 'deleted_at',
    )
    list_filter = ('uploaded_at', 'deleted_at')
    search_fields = ('original_name', 'ticket__ticket_id', 'description')
    # subtask lets a forensic/VA report file be tied to the response request it
    # was produced for; ticket stays authoritative for access control.
    raw_id_fields = ('ticket', 'subtask', 'uploaded_by', 'deleted_by')
    readonly_fields = ('uploaded_at', 'deleted_at', 'deleted_by')

    def get_queryset(self, request):
        return TicketAttachment.all_objects.all()


@admin.register(NotificationTemplate)
class NotificationTemplateAdmin(admin.ModelAdmin):
    list_display = ('key', 'subject', 'updated_at')
    readonly_fields = ('updated_at',)

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if obj:
            placeholders = NotificationTemplate.PLACEHOLDERS.get(obj.key, [])
            hint = ', '.join(f'{{{p}}}' for p in placeholders)
            form.base_fields['body'].help_text = f'Placeholders ที่ใช้ได้: {hint}'
        return form


@admin.register(TriageRecord)
class TriageRecordAdmin(admin.ModelAdmin):
    list_display = (
        'pk', 'source', 'source_reference', 'analyst', 'decision',
        'source_ip', 'escalated_to', 't2_decision', 'created_at',
    )
    list_filter = ('source', 'decision', 't2_decision')
    search_fields = (
        'source_reference', 'alert_description', 'source_ip', 'analyst__username',
    )
    readonly_fields = ('created_at', 't2_decided_at')
    raw_id_fields = ('analyst', 'escalated_to', 'ticket', 'project_incident')


@admin.register(ThreatGuidance)
class ThreatGuidanceAdmin(admin.ModelAdmin):
    list_display = ('detailed_issue', 'is_active', 'updated_at')
    list_filter = ('is_active',)
    search_fields = ('detailed_issue', 'action_required', 'action_precautions')
    readonly_fields = ('updated_at',)
