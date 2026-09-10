"""Cancelled is terminal, but never a resolution or an OLA success."""
from importlib import import_module

from django.db import migrations, models

previous = import_module('apps.reporting.migrations.0004_bundle_aware_incident_count')
FACT_SQL = previous.FACT_TICKET_SQL.replace(
    "(t.status IN ('APPROVED', 'CLOSED_EVENT'))",
    "(t.status IN ('APPROVED', 'CLOSED_EVENT', 'CANCELLED'))",
).replace(
    '(t.ola_contain_deadline IS NOT NULL)',
    "(t.ola_contain_deadline IS NOT NULL AND t.status <> 'CANCELLED')",
).replace(
    'AND t.closed_at IS NOT NULL', "AND t.status <> 'CANCELLED' AND t.closed_at IS NOT NULL",
).replace(
    '(t.closed_at - COALESCE(w.timestamp, t.incident_datetime, t.created_at))',
    "(CASE WHEN t.status <> 'CANCELLED' THEN t.closed_at - COALESCE(w.timestamp, t.incident_datetime, t.created_at) END)",
).replace(
    '(t.closed_at - t.acknowledged_at)',
    "(CASE WHEN t.status <> 'CANCELLED' THEN t.closed_at - t.acknowledged_at END)",
).replace(
    'AS closed_date_local\n', "AS closed_date_local,\n    (t.status = 'CANCELLED') AS is_cancelled\n",
)
AGG_SQL = previous.AGG_TICKET_DAILY_SQL.replace(
    'WHERE f.is_closed AND', 'WHERE f.is_closed AND NOT f.is_cancelled AND',
)


class Migration(migrations.Migration):
    dependencies = [('reporting', '0004_bundle_aware_incident_count'),
                    ('incidents', '0073_ticket_cancellation')]
    operations = [
        migrations.AddField(model_name='factticket', name='is_cancelled', field=models.BooleanField()),
        migrations.RunSQL(
            previous.DROP_SQL + FACT_SQL + AGG_SQL,
            previous.DROP_SQL + previous.FACT_TICKET_SQL + previous.AGG_TICKET_DAILY_SQL,
        ),
    ]
