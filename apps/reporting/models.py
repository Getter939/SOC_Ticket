"""Reporting-layer (Layer ③) ORM access.

These are UNMANAGED models — Django never creates, alters, or drops them. The
underlying objects are a SQL view and a materialized view created by
``migrations/0001`` in a dedicated ``mart`` schema. The models exist only so the
dashboard (and tests) can read the mart through the ORM.

The ``db_table = 'mart"."<name>'`` quoting is the Django idiom for targeting a
non-``public`` schema: it renders as ``"mart"."<name>"`` in generated SQL.
"""
from django.db import models


class FactTicket(models.Model):
    """One row per ticket — denormalized dimensions, the D3 detection clock,
    computed durations, and OLA outcome flags. Backed by ``mart.fact_ticket``
    (a plain view, always live — no refresh)."""

    id = models.BigIntegerField(primary_key=True)
    ticket_id = models.CharField(max_length=20)

    # Dimensions
    severity = models.CharField(max_length=10)
    classification = models.CharField(max_length=20)
    status = models.CharField(max_length=30)
    source = models.CharField(max_length=50)            # incidents_ticket.issue_type
    threat_category = models.CharField(max_length=255)  # incidents_ticket.detailed_issue
    t1_route = models.CharField(max_length=10)
    is_emergency = models.BooleanField()
    direct_owner_remediation = models.BooleanField()
    project_incident_id = models.IntegerField(null=True)
    is_bundled = models.BooleanField()
    # Stable identity of the real-world incident: the bundle for a member, the
    # ticket itself otherwise. Lets aggregates count incidents rather than rows.
    incident_key = models.IntegerField(null=True)
    is_closed = models.BooleanField()
    is_cancelled = models.BooleanField()
    contain_ola_applicable = models.BooleanField()
    contain_ola_met = models.BooleanField()

    # Detection clock (D3)
    detected_at = models.DateTimeField(null=True)
    mttr_clock_source = models.CharField(max_length=10)  # siem | analyst | created

    # Durations
    time_to_resolve = models.DurationField(null=True)    # MTTR: closed − detected
    time_to_ack = models.DurationField(null=True)        # MTTA: acked − detected
    handling_time = models.DurationField(null=True)      # secondary: closed − acked
    total_system_time = models.DurationField(null=True)  # closed − created
    alert_conversion_duration = models.DurationField(null=True)

    # Local (Asia/Bangkok) calendar dates
    opened_date_local = models.DateField(null=True)
    closed_date_local = models.DateField(null=True)

    class Meta:
        managed = False
        db_table = 'mart"."fact_ticket'
        verbose_name = 'Ticket fact'
        verbose_name_plural = 'Ticket facts'


class AggTicketDaily(models.Model):
    """Daily ticket aggregate, grain = (closed local date × severity ×
    classification × source). Backed by the ``mart.agg_ticket_daily``
    materialized view; refresh with ``manage.py refresh_reporting``.

    Keyed on CLOSED tickets only — still-open cases are the queue snapshot's job
    (Phase 2), never this aggregate's."""

    pk = models.CompositePrimaryKey('day', 'severity', 'classification', 'source')
    day = models.DateField()
    severity = models.CharField(max_length=10)
    classification = models.CharField(max_length=20)
    source = models.CharField(max_length=50)

    closed_count = models.BigIntegerField()
    incident_count = models.BigIntegerField()
    event_count = models.BigIntegerField()
    ola_applicable = models.BigIntegerField()
    ola_met = models.BigIntegerField()
    avg_handling_time = models.DurationField(null=True)

    class Meta:
        managed = False
        db_table = 'mart"."agg_ticket_daily'
        verbose_name = 'Ticket daily aggregate'
        verbose_name_plural = 'Ticket daily aggregates'


class SnapshotQueueDaily(models.Model):
    """Point-in-time open-queue backlog, captured once per day. MANAGED (Django
    owns this real table in the ``mart`` schema) and APPEND-ONLY in spirit — its
    history cannot be reconstructed after the fact, so the daily job must run
    from day one, before any dashboard consumes it.

    Grain: (snapshot_date × status × severity × age_bucket × ola_bucket). The
    OLA buckets reuse ``apps.incidents.ola`` so they match the live dashboard;
    ``ola_bucket='none'`` marks notification-only tickets (no contain deadline)."""

    snapshot_date = models.DateField()
    status = models.CharField(max_length=30)
    severity = models.CharField(max_length=10)
    age_bucket = models.CharField(max_length=10)   # 0-1d / 1-3d / 3-7d / 7d+
    ola_bucket = models.CharField(max_length=12)   # overdue/due_1h/due_4h/on_track/none
    open_count = models.PositiveIntegerField()

    class Meta:
        db_table = 'mart"."snapshot_queue_daily'
        verbose_name = 'Queue snapshot (daily)'
        verbose_name_plural = 'Queue snapshots (daily)'
        constraints = [
            models.UniqueConstraint(
                fields=['snapshot_date', 'status', 'severity', 'age_bucket', 'ola_bucket'],
                name='uq_snapshot_grain'),
        ]
        indexes = [models.Index(fields=['snapshot_date'], name='ix_snapshot_date')]


class AggDetectionDaily(models.Model):
    """Detection-plane rollup captured from the Wazuh Indexer (Layer ①). MANAGED.

    Because the Indexer only retains ~3 months, this is a snapshot in disguise —
    it cannot be recomputed once source data ages out, so capture begins in
    Phase 2 even though Grafana isn't repointed until Phase 4.

    Stores the NATIVE ``rule_level`` distribution; the canonical severity band is
    applied at read time via ``dim_severity_map`` (Phase 3), so this table has no
    dependency on the severity map yet. Grain: (local day × rule_level)."""

    day = models.DateField()
    rule_level = models.PositiveSmallIntegerField()
    alert_count = models.BigIntegerField()
    agent_count = models.IntegerField()

    class Meta:
        db_table = 'mart"."agg_detection_daily'
        verbose_name = 'Detection daily aggregate'
        verbose_name_plural = 'Detection daily aggregates'
        constraints = [
            models.UniqueConstraint(fields=['day', 'rule_level'],
                                    name='uq_detection_grain'),
        ]


# ── Phase 3 ─────────────────────────────────────────────────────────────── #

# Canonical severity bands — the app's own vocabulary (Ticket.SEVERITY_CHOICES).
CANONICAL_BANDS = ['Critical', 'High', 'Medium', 'Low', 'Unknown']


class DimSeverityMap(models.Model):
    """Admin-editable normalization of each source's native severity score to a
    canonical band. MANAGED. Mapping lives as DATA (not code) so onboarding a new
    SIEM is an INSERT, not a deploy — the same pattern as ThreatGuidance /
    NotificationTemplate.

    A row says: for ``source_system``, a native score in [min_value, max_value]
    maps to ``canonical_band``. ``fact_alert`` joins this to band Wazuh alerts;
    unmapped scores fall back to 'Unknown' (never silently 'Low'). Native scores
    are always preserved on the fact rows."""

    SOURCE_WAZUH = 'WAZUH'
    SOURCE_TRENDMICRO = 'TRENDMICRO'
    SOURCE_CHOICES = [
        (SOURCE_WAZUH, 'Wazuh (rule.level)'),
        (SOURCE_TRENDMICRO, 'TrendMicro (alert_score)'),
    ]
    BAND_CHOICES = [(b, b) for b in CANONICAL_BANDS if b != 'Unknown']

    source_system = models.CharField(max_length=32, choices=SOURCE_CHOICES)
    min_value = models.IntegerField(help_text='Inclusive lower bound of the native score.')
    max_value = models.IntegerField(help_text='Inclusive upper bound of the native score.')
    canonical_band = models.CharField(max_length=10, choices=BAND_CHOICES)

    class Meta:
        db_table = 'mart"."dim_severity_map'
        verbose_name = 'Severity mapping'
        verbose_name_plural = 'Severity mappings'
        ordering = ['source_system', '-min_value']
        constraints = [
            models.UniqueConstraint(fields=['source_system', 'min_value', 'max_value'],
                                    name='uq_sevmap_range'),
        ]

    def __str__(self):
        return f'{self.source_system} {self.min_value}-{self.max_value} → {self.canonical_band}'


class FactAlert(models.Model):
    """One row per ingested Wazuh alert — the triage-funnel base. Backed by
    ``mart.fact_alert`` (a plain view). ``severity_band`` is the canonical band
    from ``dim_severity_map``; ``rule_level`` (the native score) is preserved."""

    id = models.BigIntegerField(primary_key=True)
    opensearch_id = models.CharField(max_length=64)
    rule_level = models.PositiveSmallIntegerField()
    severity_band = models.CharField(max_length=10)
    triage_status = models.CharField(max_length=16)

    is_triaged = models.BooleanField()
    is_true_positive = models.BooleanField()
    is_false_positive = models.BooleanField()
    is_escalated = models.BooleanField()
    became_ticket = models.BooleanField()

    triage_duration = models.DurationField(null=True)
    triage_ola_applicable = models.BooleanField()
    triage_ola_met = models.BooleanField()
    alert_date_local = models.DateField(null=True)

    class Meta:
        managed = False
        db_table = 'mart"."fact_alert'
        verbose_name = 'Alert fact'
        verbose_name_plural = 'Alert facts'


class AggAlertDaily(models.Model):
    """Daily alert-triage funnel, grain = (local alert date × severity_band).
    Backed by the ``mart.agg_alert_daily`` materialized view; refresh with
    ``manage.py refresh_reporting``.

    Recomputed from raw alerts that ``purge_wazuh_alerts`` deletes after the
    retention window, so its older days shrink over time. For history, read
    ``HistAlertDaily`` (``mart.hist_alert_daily``) instead — never this view."""

    pk = models.CompositePrimaryKey('day', 'severity_band')
    day = models.DateField()
    severity_band = models.CharField(max_length=10)

    ingested_count = models.BigIntegerField()
    triaged_count = models.BigIntegerField()
    true_positive_count = models.BigIntegerField()
    false_positive_count = models.BigIntegerField()
    escalated_count = models.BigIntegerField()
    became_ticket_count = models.BigIntegerField()
    triage_ola_applicable = models.BigIntegerField()
    triage_ola_met = models.BigIntegerField()

    class Meta:
        managed = False
        db_table = 'mart"."agg_alert_daily'
        verbose_name = 'Alert daily aggregate'
        verbose_name_plural = 'Alert daily aggregates'


# ── Phase 3b: history that cannot be rebuilt later (2026-10-01) ─────────── #

class HistAlertDaily(models.Model):
    """Stored copy of the alert-triage funnel, one row per (local day ×
    severity_band). MANAGED and append-only in spirit.

    Why it exists: ``agg_alert_daily`` is a materialized view recomputed from the
    raw ``wazuh_ingest_wazuhalert`` rows, and ``purge_wazuh_alerts`` deletes those
    rows after ``WAZUH_RETENTION_DAYS``. Without this table every refresh after a
    purge would silently shrink or drop the purged days.

    ``refresh_reporting`` upserts only days still inside the retention window
    (minus a safety margin, see ``refresh_reporting.HIST_ALERT_MARGIN_DAYS``);
    older days are frozen — never overwritten, never deleted. Anything reading
    the alert funnel over time reads THIS table, not the materialized view."""

    day = models.DateField()
    severity_band = models.CharField(max_length=10)

    ingested_count = models.BigIntegerField()
    triaged_count = models.BigIntegerField()
    true_positive_count = models.BigIntegerField()
    false_positive_count = models.BigIntegerField()
    escalated_count = models.BigIntegerField()
    became_ticket_count = models.BigIntegerField()
    triage_ola_applicable = models.BigIntegerField()
    triage_ola_met = models.BigIntegerField()
    captured_at = models.DateTimeField()

    COUNT_FIELDS = [
        'ingested_count', 'triaged_count', 'true_positive_count',
        'false_positive_count', 'escalated_count', 'became_ticket_count',
        'triage_ola_applicable', 'triage_ola_met',
    ]

    class Meta:
        db_table = 'mart"."hist_alert_daily'
        verbose_name = 'Alert funnel history (daily)'
        verbose_name_plural = 'Alert funnel history (daily)'
        constraints = [
            models.UniqueConstraint(fields=['day', 'severity_band'],
                                    name='uq_hist_alert_grain'),
        ]


class SnapshotKpiDaily(models.Model):
    """One row per night: the open-queue figures the live dashboards show that
    ``snapshot_queue_daily`` cannot give (it has no assignee, emergency flag or
    response requests). Point-in-time, so it cannot be rebuilt later."""

    snapshot_date = models.DateField(unique=True)
    open_tickets = models.PositiveIntegerField()
    unassigned_open = models.PositiveIntegerField()
    emergency_open_tickets = models.PositiveIntegerField()
    # Incident grain (a Project Incident bundle counts once), the same rule as
    # the executive dashboard's Emergency KPI — TicketQuerySet.incident_count.
    emergency_open_incidents = models.PositiveIntegerField()
    oldest_open_hours = models.PositiveIntegerField(null=True)   # null = queue empty
    # Open response requests (Forensic / Red Team), same rule as the executive
    # dashboard: OPEN or IN_PROGRESS on a ticket that is not closed.
    response_open = models.PositiveIntegerField()
    response_aged_7d = models.PositiveIntegerField()
    captured_at = models.DateTimeField()

    class Meta:
        db_table = 'mart"."snapshot_kpi_daily'
        verbose_name = 'KPI snapshot (daily)'
        verbose_name_plural = 'KPI snapshots (daily)'


class SnapshotWorkloadDaily(models.Model):
    """Who held the open queue each night. Assignment is overwritten in place on
    the ticket and not logged anywhere, so this is the only workload history.

    Grain: (snapshot_date × kind × user_id × status × severity).
    ``kind='assigned'`` follows ``Ticket.assigned_to`` (user null = unassigned);
    ``kind='t2_claimed'`` follows ``Ticket.t2_claimed_by`` — the two holders the
    SOC dashboard's Analyst Workload heatmap counts. ``username`` is copied so a
    deleted account's history still reads. PERSONAL DATA: per-person rows — think
    before granting this table to an external read role (``reporting_ro``).

    The unique constraint cannot catch two unassigned (NULL user) rows for the
    same grain — PostgreSQL treats NULLs as distinct unless NULLS NOT DISTINCT
    (v15+) is available — so the writer guarantees one row per grain."""

    KIND_ASSIGNED = 'assigned'
    KIND_T2_CLAIMED = 't2_claimed'

    snapshot_date = models.DateField()
    kind = models.CharField(max_length=12)
    user_id = models.IntegerField(null=True)
    username = models.CharField(max_length=150, blank=True)
    status = models.CharField(max_length=30)
    severity = models.CharField(max_length=10)
    open_count = models.PositiveIntegerField()

    class Meta:
        db_table = 'mart"."snapshot_workload_daily'
        verbose_name = 'Workload snapshot (daily)'
        verbose_name_plural = 'Workload snapshots (daily)'
        constraints = [
            models.UniqueConstraint(
                fields=['snapshot_date', 'kind', 'user_id', 'status', 'severity'],
                name='uq_workload_grain'),
        ]
        indexes = [models.Index(fields=['snapshot_date'], name='ix_workload_date')]


class SnapshotResponseDaily(models.Model):
    """Open response requests (Forensic / Red Team) each night.

    Grain: (snapshot_date × subtask_type × status × aged_7d × hc_ticket).
    "Open" = OPEN or IN_PROGRESS on a ticket that is not closed (the executive
    dashboard's rule); ``aged_7d`` = created more than 7 days before the run;
    ``hc_ticket`` = the parent ticket is High or Critical."""

    snapshot_date = models.DateField()
    subtask_type = models.CharField(max_length=20)
    status = models.CharField(max_length=20)
    aged_7d = models.BooleanField()
    hc_ticket = models.BooleanField()
    open_count = models.PositiveIntegerField()

    class Meta:
        db_table = 'mart"."snapshot_response_daily'
        verbose_name = 'Response-request snapshot (daily)'
        verbose_name_plural = 'Response-request snapshots (daily)'
        constraints = [
            models.UniqueConstraint(
                fields=['snapshot_date', 'subtask_type', 'status', 'aged_7d', 'hc_ticket'],
                name='uq_response_snapshot_grain'),
        ]
        indexes = [models.Index(fields=['snapshot_date'], name='ix_response_snapshot_date')]
