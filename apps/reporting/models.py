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
