from django.contrib import admin

from .models import IngestWatermark, WazuhAlert


@admin.register(WazuhAlert)
class WazuhAlertAdmin(admin.ModelAdmin):
    list_display = ['opensearch_id', 'agent_name', 'rule_level', 'rule_description', 'timestamp']
    list_filter = ['rule_level', 'agent_name']
    search_fields = ['opensearch_id', 'alert_id', 'rule_id', 'rule_description', 'agent_name']
    readonly_fields = ['ingested_at']


@admin.register(IngestWatermark)
class IngestWatermarkAdmin(admin.ModelAdmin):
    list_display = ['id', 'last_timestamp', 'updated_at']
