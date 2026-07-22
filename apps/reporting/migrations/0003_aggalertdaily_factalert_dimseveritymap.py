# Reporting layer (Layer ③) — Phase 3: alert triage funnel + severity mapping.
#
#   dim_severity_map  managed table (admin-editable), seeded with Wazuh bands
#   fact_alert        view over wazuh_ingest_wazuhalert, banded via the map
#   agg_alert_daily   materialized view (grain: local day × severity_band)
#
# Operation order matters: the map table must exist and be seeded BEFORE the
# fact_alert view (which joins it), which must exist before the aggregate MV.

from django.db import migrations, models


# Initial Wazuh rule.level → canonical band. Aligned with the legacy
# wazuh-pipeline/dashboard_views.sql thresholds (>=14 Crit, >=12 High, >=7 Med)
# so the Phase 4 Grafana repoint is continuous. Editable in Django admin — these
# are just the starting values (D8-values), tune per environment.
WAZUH_BANDS = [
    ('WAZUH', 14, 999, 'Critical'),
    ('WAZUH', 12, 13, 'High'),
    ('WAZUH', 7, 11, 'Medium'),
    ('WAZUH', 0, 6, 'Low'),
]


def seed_severity_map(apps, schema_editor):
    Dim = apps.get_model('reporting', 'DimSeverityMap')
    for source, lo, hi, band in WAZUH_BANDS:
        Dim.objects.update_or_create(
            source_system=source, min_value=lo, max_value=hi,
            defaults={'canonical_band': band},
        )


def unseed_severity_map(apps, schema_editor):
    Dim = apps.get_model('reporting', 'DimSeverityMap')
    Dim.objects.filter(source_system='WAZUH').delete()


FACT_ALERT_SQL = """
CREATE VIEW mart.fact_alert AS
SELECT
    w.id,
    w.opensearch_id,
    w.rule_level,
    COALESCE(band.canonical_band, 'Unknown')            AS severity_band,
    w.triage_status,
    (w.triage_status NOT IN ('PENDING', 'TRIAGING'))    AS is_triaged,
    (w.triage_status = 'TRUE_POSITIVE')                 AS is_true_positive,
    (w.triage_status = 'FALSE_POSITIVE')                AS is_false_positive,
    (w.triage_status = 'ESCALATED')                     AS is_escalated,
    EXISTS (
        SELECT 1 FROM incidents_ticket t WHERE t.wazuh_alert_id = w.id
    )                                                   AS became_ticket,
    (w.triaged_at - w.timestamp)                        AS triage_duration,
    (w.triaged_at IS NOT NULL)                          AS triage_ola_applicable,
    (
        w.triaged_at IS NOT NULL
        AND (w.triaged_at - w.timestamp) <= interval '4 hours'   -- WazuhAlert.OLA_HOURS
    )                                                   AS triage_ola_met,
    (w.timestamp AT TIME ZONE 'Asia/Bangkok')::date     AS alert_date_local
FROM wazuh_ingest_wazuhalert w
-- One band per alert even if ranges overlap: pick the highest matching lower
-- bound (most specific), or NULL → 'Unknown'.
LEFT JOIN LATERAL (
    SELECT m.canonical_band
    FROM mart.dim_severity_map m
    WHERE m.source_system = 'WAZUH'
      AND w.rule_level BETWEEN m.min_value AND m.max_value
    ORDER BY m.min_value DESC
    LIMIT 1
) band ON true;
"""

AGG_ALERT_DAILY_SQL = """
CREATE MATERIALIZED VIEW mart.agg_alert_daily AS
SELECT
    f.alert_date_local                              AS day,
    f.severity_band,
    count(*)                                        AS ingested_count,
    count(*) FILTER (WHERE f.is_triaged)            AS triaged_count,
    count(*) FILTER (WHERE f.is_true_positive)      AS true_positive_count,
    count(*) FILTER (WHERE f.is_false_positive)     AS false_positive_count,
    count(*) FILTER (WHERE f.is_escalated)          AS escalated_count,
    count(*) FILTER (WHERE f.became_ticket)         AS became_ticket_count,
    count(*) FILTER (WHERE f.triage_ola_applicable) AS triage_ola_applicable,
    count(*) FILTER (WHERE f.triage_ola_met)        AS triage_ola_met
FROM mart.fact_alert f
WHERE f.alert_date_local IS NOT NULL
GROUP BY f.alert_date_local, f.severity_band
WITH DATA;

CREATE UNIQUE INDEX agg_alert_daily_grain
    ON mart.agg_alert_daily (day, severity_band);
"""


class Migration(migrations.Migration):

    dependencies = [
        ('reporting', '0002_aggdetectiondaily_snapshotqueuedaily'),
    ]

    operations = [
        # 1. The admin-editable mapping table (real, managed).
        migrations.CreateModel(
            name='DimSeverityMap',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_system', models.CharField(choices=[('WAZUH', 'Wazuh (rule.level)'), ('TRENDMICRO', 'TrendMicro (alert_score)')], max_length=32)),
                ('min_value', models.IntegerField(help_text='Inclusive lower bound of the native score.')),
                ('max_value', models.IntegerField(help_text='Inclusive upper bound of the native score.')),
                ('canonical_band', models.CharField(choices=[('Critical', 'Critical'), ('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')], max_length=10)),
            ],
            options={
                'verbose_name': 'Severity mapping',
                'verbose_name_plural': 'Severity mappings',
                'db_table': 'mart"."dim_severity_map',
                'ordering': ['source_system', '-min_value'],
                'constraints': [models.UniqueConstraint(fields=('source_system', 'min_value', 'max_value'), name='uq_sevmap_range')],
            },
        ),
        # 2. Seed the Wazuh bands (before the view that reads them).
        migrations.RunPython(seed_severity_map, unseed_severity_map),

        # 3. The alert fact view (joins the map).
        migrations.RunSQL(
            sql=FACT_ALERT_SQL,
            reverse_sql='DROP VIEW IF EXISTS mart.fact_alert;',
        ),
        # 4. The daily alert aggregate (reads the fact view).
        migrations.RunSQL(
            sql=AGG_ALERT_DAILY_SQL,
            reverse_sql='DROP MATERIALIZED VIEW IF EXISTS mart.agg_alert_daily;',
        ),

        # ── ORM state only (managed=False → no DB work) ──────────────────── #
        migrations.CreateModel(
            name='AggAlertDaily',
            fields=[
                ('pk', models.CompositePrimaryKey('day', 'severity_band', blank=True, editable=False, primary_key=True, serialize=False)),
                ('day', models.DateField()),
                ('severity_band', models.CharField(max_length=10)),
                ('ingested_count', models.BigIntegerField()),
                ('triaged_count', models.BigIntegerField()),
                ('true_positive_count', models.BigIntegerField()),
                ('false_positive_count', models.BigIntegerField()),
                ('escalated_count', models.BigIntegerField()),
                ('became_ticket_count', models.BigIntegerField()),
                ('triage_ola_applicable', models.BigIntegerField()),
                ('triage_ola_met', models.BigIntegerField()),
            ],
            options={
                'verbose_name': 'Alert daily aggregate',
                'verbose_name_plural': 'Alert daily aggregates',
                'db_table': 'mart"."agg_alert_daily',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='FactAlert',
            fields=[
                ('id', models.BigIntegerField(primary_key=True, serialize=False)),
                ('opensearch_id', models.CharField(max_length=64)),
                ('rule_level', models.PositiveSmallIntegerField()),
                ('severity_band', models.CharField(max_length=10)),
                ('triage_status', models.CharField(max_length=16)),
                ('is_triaged', models.BooleanField()),
                ('is_true_positive', models.BooleanField()),
                ('is_false_positive', models.BooleanField()),
                ('is_escalated', models.BooleanField()),
                ('became_ticket', models.BooleanField()),
                ('triage_duration', models.DurationField(null=True)),
                ('triage_ola_applicable', models.BooleanField()),
                ('triage_ola_met', models.BooleanField()),
                ('alert_date_local', models.DateField(null=True)),
            ],
            options={
                'verbose_name': 'Alert fact',
                'verbose_name_plural': 'Alert facts',
                'db_table': 'mart"."fact_alert',
                'managed': False,
            },
        ),
    ]
