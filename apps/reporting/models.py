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
    is_bundled = models.BooleanField()
    is_closed = models.BooleanField()
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
