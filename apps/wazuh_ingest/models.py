from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

# ola holds no model imports, so this stays a one-way dependency.
from apps.incidents.ola import badge_for


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

    # ── Alert kind ──────────────────────────────────────────────────── #
    # Wazuh's vulnerability detector emits one alert per (host, package, CVE)
    # on every scan, so a single unpatched kernel lands as hundreds of level-13
    # alerts — 771 of 849 rows in the 2026-09 production queue were 188 CVEs on
    # two kernel packages across five hosts. Those are a standing vulnerability
    # inventory, not discrete events: there is no per-row triage decision to
    # make, the 4-hour triage OLA (OLA_HOURS) is meaningless against them, and
    # rule_level 13 would open every one as a Critical ticket.
    #
    # They are still ingested and kept — vulnerability state is SOC business —
    # but they are routed out of the Tier 1 triage queue. Only KIND_DETECTION
    # rows are triage work.
    KIND_DETECTION = 'DETECTION'
    KIND_VULNERABILITY = 'VULNERABILITY'
    KIND_CHOICES = [
        (KIND_DETECTION, 'Detection'),
        (KIND_VULNERABILITY, 'Vulnerability'),
    ]

    # The rule group Wazuh tags every vulnerability-detector alert with. This is
    # the classifier input, deliberately NOT rule_id: 23506 is the rule seen in
    # production, but the group is the stable contract across Wazuh versions and
    # covers the sibling vulnerability rules too.
    VULNERABILITY_RULE_GROUP = 'vulnerability-detector'

    kind = models.CharField(
        max_length=16, choices=KIND_CHOICES, default=KIND_DETECTION, db_index=True,
        help_text='Whether this alert is triage work or vulnerability inventory.',
    )

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

    # ── Case Bundling origin ─────────────────────────────────────────── #
    # Set when this alert is triaged into a multi-system Project Incident
    # (case bundle) rather than a single ticket. The alert is the origin of the
    # whole bundle, so it points at the ProjectIncident, not one member ticket
    # (the single-ticket path still uses the Ticket.wazuh_alert OneToOne).
    project_incident = models.ForeignKey(
        'incidents.ProjectIncident', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='source_alerts',
        verbose_name='Project Incident (Case Bundle)',
    )

    # ── Claim (in-progress work tracking) ───────────────────────────── #
    claimed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='claimed_alerts',
    )
    claimed_at = models.DateTimeField(null=True, blank=True)

    # Alert-triage OLA (separate from the ticket OLA policy in
    # incidents.Ticket.OLA_TARGETS): the triage decision must be made within
    # this flat window of the alert appearing (alert.timestamp).
    OLA_HOURS = 4

    UNTRIAGED_STATUSES = (TRIAGE_PENDING, TRIAGE_TRIAGING)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'[{self.rule_level}] {self.rule_description} ({self.agent_name})'

    @classmethod
    def classify_kind(cls, rule_groups):
        """Which queue an alert belongs to, derived from its Wazuh rule groups.

        Kept a classmethod on the model so ingestion and the 0007 backfill
        cannot drift apart on what counts as a vulnerability alert.
        """
        if cls.VULNERABILITY_RULE_GROUP in (rule_groups or []):
            return cls.KIND_VULNERABILITY
        return cls.KIND_DETECTION

    # ------------------------------------------------------------------ #
    # OLA — clock runs from the alert appearing until it is triaged       #
    # ------------------------------------------------------------------ #

    @property
    def ola_deadline(self):
        return self.timestamp + timedelta(hours=self.OLA_HOURS)

    @property
    def is_ola_breached(self):
        """Still untriaged and past the OLA deadline (live — counts up until triaged)."""
        if self.triage_status not in self.UNTRIAGED_STATUSES:
            return False
        return timezone.now() > self.ola_deadline

    @property
    def is_ola_urgent(self):
        """Still untriaged, not yet breached, but less than 1 hour of margin left."""
        if self.triage_status not in self.UNTRIAGED_STATUSES:
            return False
        remaining = self.ola_deadline - timezone.now()
        return timedelta() < remaining <= timedelta(hours=1)

    @property
    def ola_badge(self):
        """Live triage-OLA pill for the queue table (incidents/_ola_badge.html).

        Drops away once the alert is triaged — the clock has stopped, and
        triage_duration is the meaningful figure from then on.
        """
        return badge_for(
            self.ola_deadline,
            done=self.triage_status not in self.UNTRIAGED_STATUSES,
        )

    @property
    def triage_duration(self):
        """Time taken to triage — fixed once triaged_at is set."""
        if self.triaged_at:
            return self.triaged_at - self.timestamp
        return None

    @property
    def triage_within_ola(self):
        duration = self.triage_duration
        if duration is None:
            return None
        return duration <= timedelta(hours=self.OLA_HOURS)


class IngestWatermark(models.Model):
    """Single-row table tracking the last successfully ingested alert timestamp."""

    last_timestamp = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'Watermark: {self.last_timestamp}'
