from django.contrib import admin

from .models import IngestWatermark, WazuhAlert


@admin.register(WazuhAlert)
class WazuhAlertAdmin(admin.ModelAdmin):
    list_display = [
        'opensearch_id', 'agent_name', 'rule_level', 'rule_description', 'timestamp',
        'triage_status', 'claimed_by', 'claimed_at', 'triaged_by', 'triaged_at',
        'incident_category', 'escalated_to_tier',
    ]
    list_filter = ['rule_level', 'agent_name', 'triage_status', 'incident_category']
    search_fields = ['opensearch_id', 'alert_id', 'rule_id', 'rule_description', 'agent_name']
    readonly_fields = ['ingested_at', 'claimed_by', 'claimed_at', 'triaged_by', 'triaged_at']
    raw_id_fields = ['project_incident']


@admin.register(IngestWatermark)
class IngestWatermarkAdmin(admin.ModelAdmin):
    list_display = ['id', 'last_timestamp', 'updated_at']
