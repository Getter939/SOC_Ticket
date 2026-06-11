from django.db import models


class WazuhAlert(models.Model):
    """A single Wazuh alert pulled from the OpenSearch `wazuh-alerts-*` indices."""

    opensearch_id = models.CharField(
        max_length=64, unique=True, db_index=True,
        help_text='OpenSearch document _id — used for deduplication.',
    )
    alert_id = models.CharField(max_length=64, blank=True, default='')
    timestamp = models.DateTimeField()

    agent_id = models.CharField(max_length=16, blank=True, default='')
    agent_name = models.CharField(max_length=128, blank=True, default='')
    agent_ip = models.GenericIPAddressField(null=True, blank=True)

    rule_id = models.CharField(max_length=32, blank=True, default='')
    rule_level = models.PositiveSmallIntegerField()
    rule_description = models.TextField(blank=True, default='')
    rule_groups = models.JSONField(default=list, blank=True)

    mitre_techniques = models.JSONField(default=list, blank=True)
    mitre_tactics = models.JSONField(default=list, blank=True)
    mitre_ids = models.JSONField(default=list, blank=True)

    raw_data = models.JSONField(default=dict, blank=True)
    decoder_name = models.CharField(max_length=64, blank=True, default='')

    ingested_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'[{self.rule_level}] {self.rule_description} ({self.agent_name})'


class IngestWatermark(models.Model):
    """Single-row table tracking the last successfully ingested alert timestamp."""

    last_timestamp = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'Watermark: {self.last_timestamp}'
