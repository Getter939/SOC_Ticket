from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


class WazuhAlert(models.Model):
    """A single Wazuh alert pulled from the OpenSearch `wazuh-alerts-*` indices."""

    TRIAGE_PENDING = 'PENDING'
    TRIAGE_TRIAGING = 'TRIAGING'
    TRIAGE_TRUE_POSITIVE = 'TRUE_POSITIVE'
    TRIAGE_FALSE_POSITIVE = 'FALSE_POSITIVE'
    TRIAGE_ESCALATED = 'ESCALATED'
    TRIAGE_STATUS_CHOICES = [
        (TRIAGE_PENDING, 'Pending'),
        (TRIAGE_TRIAGING, 'Triaging'),
        (TRIAGE_TRUE_POSITIVE, 'Incident'),
        (TRIAGE_FALSE_POSITIVE, 'Event'),
        (TRIAGE_ESCALATED, 'Escalated'),
    ]

    TIER_T1 = 'T1'
    TIER_T2 = 'T2'
    TIER_MANAGER = 'MANAGER'
    TIER_CHOICES = [
        (TIER_T1, 'T1'),
        (TIER_T2, 'T2'),
        (TIER_MANAGER, 'Manager'),
    ]

    CATEGORY_MALWARE = 'Malware'
    CATEGORY_PHISHING = 'Phishing'
    CATEGORY_UNAUTHORIZED_ACCESS = 'Unauthorized Access'
    CATEGORY_DATA_EXFILTRATION = 'Data Exfiltration'
    CATEGORY_DOS = 'Denial of Service'
    CATEGORY_RECONNAISSANCE = 'Reconnaissance'
    CATEGORY_POLICY_VIOLATION = 'Policy Violation'
    CATEGORY_OTHER = 'Other'
    CATEGORY_CHOICES = [
        (CATEGORY_MALWARE, 'Malware'),
        (CATEGORY_PHISHING, 'Phishing'),
        (CATEGORY_UNAUTHORIZED_ACCESS, 'Unauthorized Access'),
        (CATEGORY_DATA_EXFILTRATION, 'Data Exfiltration'),
        (CATEGORY_DOS, 'Denial of Service'),
        (CATEGORY_RECONNAISSANCE, 'Reconnaissance'),
        (CATEGORY_POLICY_VIOLATION, 'Policy Violation'),
        (CATEGORY_OTHER, 'Other'),
    ]

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

    # ── Triage state ─────────────────────────────────────────────────── #
    triage_status = models.CharField(
        max_length=16, choices=TRIAGE_STATUS_CHOICES, default=TRIAGE_PENDING,
    )
    triaged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='triaged_alerts',
    )
    triaged_at = models.DateTimeField(null=True, blank=True)
    triage_note = models.TextField(blank=True, default='')
    # Reason captured when a Tier 1 analyst releases a claimed alert back to the
    # queue (required by release_alert). Holds the most recent release reason.
    release_reason = models.TextField(blank=True, default='')
    escalated_to_tier = models.CharField(
        max_length=10, choices=TIER_CHOICES, null=True, blank=True,
    )
    incident_category = models.CharField(
        max_length=32, choices=CATEGORY_CHOICES, null=True, blank=True,
    )

    # ── Claim (in-progress work tracking) ───────────────────────────── #
    claimed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='claimed_alerts',
    )
    claimed_at = models.DateTimeField(null=True, blank=True)

    # Must match incidents.Ticket.SLA_HOURS — the triage decision must be
    # made within this window of the alert appearing (alert.timestamp).
    SLA_HOURS = 4

    UNTRIAGED_STATUSES = (TRIAGE_PENDING, TRIAGE_TRIAGING)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'[{self.rule_level}] {self.rule_description} ({self.agent_name})'

    # ------------------------------------------------------------------ #
    # SLA — clock runs from the alert appearing until it is triaged       #
    # ------------------------------------------------------------------ #

    @property
    def sla_deadline(self):
        return self.timestamp + timedelta(hours=self.SLA_HOURS)

    @property
    def is_sla_breached(self):
        """Still untriaged and past the SLA deadline (live — counts up until triaged)."""
        if self.triage_status not in self.UNTRIAGED_STATUSES:
            return False
        return timezone.now() > self.sla_deadline

    @property
    def is_sla_urgent(self):
        """Still untriaged, not yet breached, but less than 1 hour of margin left."""
        if self.triage_status not in self.UNTRIAGED_STATUSES:
            return False
        remaining = self.sla_deadline - timezone.now()
        return timedelta() < remaining <= timedelta(hours=1)

    @property
    def triage_duration(self):
        """Time taken to triage — fixed once triaged_at is set."""
        if self.triaged_at:
            return self.triaged_at - self.timestamp
        return None

    @property
    def triage_within_sla(self):
        duration = self.triage_duration
        if duration is None:
            return None
        return duration <= timedelta(hours=self.SLA_HOURS)


class IngestWatermark(models.Model):
    """Single-row table tracking the last successfully ingested alert timestamp."""

    last_timestamp = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'Watermark: {self.last_timestamp}'
