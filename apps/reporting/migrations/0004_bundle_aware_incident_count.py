# Bundle-aware incident counting.
#
# `fact_ticket` exposed only the derived `is_bundled` boolean, never the bundle
# identity, so nothing downstream could tell WHICH bundle a member belonged to —
# the flag was unusable and `agg_ticket_daily.incident_count` counted member
# tickets. A Project Incident fans one real-world incident across N systems, so
# a 5-system bundle read as 5 incidents.
#
# This exposes `project_incident_id` on the fact view and makes `incident_count`
# count distinct incidents. `closed_count` / `event_count` stay at ticket grain:
# they answer "how many tickets closed", which is a workload figure.
#
# Both objects are replaced (the view is a plain VIEW; the aggregate is
# materialized and must be dropped before its source view can be recreated).

from django.db import migrations, models


DROP_SQL = """
DROP MATERIALIZED VIEW IF EXISTS mart.agg_ticket_daily;
DROP VIEW IF EXISTS mart.fact_ticket;
"""

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
    t.project_incident_id,
    (t.project_incident_id IS NOT NULL)                      AS is_bundled,
    -- Stable identity of the real-world incident this row belongs to: the
    -- bundle for a member, the ticket itself otherwise. Negated so a ticket pk
    -- can never collide with a project pk in the same key space.
    COALESCE(t.project_incident_id, -t.id)                   AS incident_key,
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
    -- Incident grain: members of one bundle collapse to a single incident.
    count(DISTINCT f.incident_key)
        FILTER (WHERE f.classification = 'INCIDENT')       AS incident_count,
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

# Reverse: the pre-bundle definitions, verbatim from 0001_initial.
REVERSE_FACT_TICKET_SQL = """
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

REVERSE_AGG_TICKET_DAILY_SQL = """
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

CREATE UNIQUE INDEX agg_ticket_daily_grain
    ON mart.agg_ticket_daily (day, severity, classification, source);
"""


class Migration(migrations.Migration):

    dependencies = [
        ('reporting', '0003_aggalertdaily_factalert_dimseveritymap'),
    ]

    operations = [
        # ORM state only — FactTicket is unmanaged, so this performs no DDL.
        migrations.AddField(
            model_name='factticket',
            name='project_incident_id',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='factticket',
            name='incident_key',
            field=models.IntegerField(null=True),
        ),
        migrations.RunSQL(
            sql=DROP_SQL + FACT_TICKET_SQL + AGG_TICKET_DAILY_SQL,
            reverse_sql=DROP_SQL + REVERSE_FACT_TICKET_SQL + REVERSE_AGG_TICKET_DAILY_SQL,
        ),
    ]
