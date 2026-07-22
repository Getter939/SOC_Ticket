# Reporting layer (Layer ③) — Phase 1.
# Creates the `mart` schema, the `fact_ticket` view, and the `agg_ticket_daily`
# materialized view. The two CreateModel operations are for UNMANAGED models
# (managed=False) — they register ORM state only and perform NO database work;
# the RunSQL operations below create the actual objects.
#
# Purely additive: no existing table is touched. Fully reversible
# (`migrate reporting zero` drops the schema).

from django.db import migrations, models


FACT_TICKET_SQL = """
CREATE VIEW mart.fact_ticket AS
SELECT
    t.id,
    t.ticket_id,
    t.severity,
    t.classification,
    t.status,
    t.issue_type            AS source,
    t.detailed_issue        AS threat_category,
    t.t1_route,
    t.is_emergency,
    t.direct_owner_remediation,
    (t.project_incident_id IS NOT NULL)                      AS is_bundled,
    (t.status IN ('APPROVED', 'CLOSED_EVENT'))              AS is_closed,
    (t.ola_contain_deadline IS NOT NULL)                     AS contain_ola_applicable,
    (
        t.ola_contain_deadline IS NOT NULL
        AND t.closed_at IS NOT NULL
        AND t.closed_at <= t.ola_contain_deadline
    )                                                        AS contain_ola_met,
    COALESCE(w.timestamp, t.incident_datetime, t.created_at) AS detected_at,
    CASE
        WHEN w.timestamp IS NOT NULL         THEN 'siem'
        WHEN t.incident_datetime IS NOT NULL THEN 'analyst'
        ELSE 'created'
    END                                                      AS mttr_clock_source,
    (t.closed_at - COALESCE(w.timestamp, t.incident_datetime, t.created_at))
                                                             AS time_to_resolve,
    (t.acknowledged_at - COALESCE(w.timestamp, t.incident_datetime, t.created_at))
                                                             AS time_to_ack,
    (t.closed_at - t.acknowledged_at)                        AS handling_time,
    (t.closed_at - t.created_at)                             AS total_system_time,
    t.alert_conversion_duration,
    (t.created_at AT TIME ZONE 'Asia/Bangkok')::date         AS opened_date_local,
    (t.closed_at  AT TIME ZONE 'Asia/Bangkok')::date         AS closed_date_local
FROM incidents_ticket t
LEFT JOIN wazuh_ingest_wazuhalert w ON w.id = t.wazuh_alert_id;
"""

AGG_TICKET_DAILY_SQL = """
CREATE MATERIALIZED VIEW mart.agg_ticket_daily AS
SELECT
    f.closed_date_local                                    AS day,
    f.severity,
    f.classification,
    f.source,
    count(*)                                               AS closed_count,
    count(*) FILTER (WHERE f.classification = 'INCIDENT')  AS incident_count,
    count(*) FILTER (WHERE f.classification = 'EVENT')     AS event_count,
    count(*) FILTER (WHERE f.contain_ola_applicable)       AS ola_applicable,
    count(*) FILTER (WHERE f.contain_ola_met)              AS ola_met,
    avg(f.handling_time)                                   AS avg_handling_time
FROM mart.fact_ticket f
WHERE f.is_closed AND f.closed_date_local IS NOT NULL
GROUP BY f.closed_date_local, f.severity, f.classification, f.source
WITH DATA;

-- Unique index on the full grain — REQUIRED for REFRESH ... CONCURRENTLY.
CREATE UNIQUE INDEX agg_ticket_daily_grain
    ON mart.agg_ticket_daily (day, severity, classification, source);
"""


class Migration(migrations.Migration):

    # Not `initial` in the standalone sense — the view reads operational tables,
    # so it must apply after the apps that own them.
    dependencies = [
        ('incidents', '0046_alter_notificationtemplate_key'),
        ('wazuh_ingest', '0006_wazuhalert_project_incident'),
    ]

    operations = [
        # ── ORM state only (managed=False → no DB table is created) ──────── #
        migrations.CreateModel(
            name='AggTicketDaily',
            fields=[
                ('pk', models.CompositePrimaryKey('day', 'severity', 'classification', 'source', blank=True, editable=False, primary_key=True, serialize=False)),
                ('day', models.DateField()),
                ('severity', models.CharField(max_length=10)),
                ('classification', models.CharField(max_length=20)),
                ('source', models.CharField(max_length=50)),
                ('closed_count', models.BigIntegerField()),
                ('incident_count', models.BigIntegerField()),
                ('event_count', models.BigIntegerField()),
                ('ola_applicable', models.BigIntegerField()),
                ('ola_met', models.BigIntegerField()),
                ('avg_handling_time', models.DurationField(null=True)),
            ],
            options={
                'verbose_name': 'Ticket daily aggregate',
                'verbose_name_plural': 'Ticket daily aggregates',
                'db_table': 'mart"."agg_ticket_daily',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='FactTicket',
            fields=[
                ('id', models.BigIntegerField(primary_key=True, serialize=False)),
                ('ticket_id', models.CharField(max_length=20)),
                ('severity', models.CharField(max_length=10)),
                ('classification', models.CharField(max_length=20)),
                ('status', models.CharField(max_length=30)),
                ('source', models.CharField(max_length=50)),
                ('threat_category', models.CharField(max_length=255)),
                ('t1_route', models.CharField(max_length=10)),
                ('is_emergency', models.BooleanField()),
                ('direct_owner_remediation', models.BooleanField()),
                ('is_bundled', models.BooleanField()),
                ('is_closed', models.BooleanField()),
                ('contain_ola_applicable', models.BooleanField()),
                ('contain_ola_met', models.BooleanField()),
                ('detected_at', models.DateTimeField(null=True)),
                ('mttr_clock_source', models.CharField(max_length=10)),
                ('time_to_resolve', models.DurationField(null=True)),
                ('time_to_ack', models.DurationField(null=True)),
                ('handling_time', models.DurationField(null=True)),
                ('total_system_time', models.DurationField(null=True)),
                ('alert_conversion_duration', models.DurationField(null=True)),
                ('opened_date_local', models.DateField(null=True)),
                ('closed_date_local', models.DateField(null=True)),
            ],
            options={
                'verbose_name': 'Ticket fact',
                'verbose_name_plural': 'Ticket facts',
                'db_table': 'mart"."fact_ticket',
                'managed': False,
            },
        ),

        # ── The real database objects ────────────────────────────────────── #
        migrations.RunSQL(
            sql='CREATE SCHEMA IF NOT EXISTS mart;',
            reverse_sql='DROP SCHEMA IF EXISTS mart CASCADE;',
        ),
        migrations.RunSQL(
            sql=FACT_TICKET_SQL,
            reverse_sql='DROP VIEW IF EXISTS mart.fact_ticket;',
        ),
        migrations.RunSQL(
            sql=AGG_TICKET_DAILY_SQL,
            reverse_sql='DROP MATERIALIZED VIEW IF EXISTS mart.agg_ticket_daily;',
        ),
    ]
