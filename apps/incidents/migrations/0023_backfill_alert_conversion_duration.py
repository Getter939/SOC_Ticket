from django.db import migrations


def backfill(apps, schema_editor):
    """Stamp alert_conversion_duration for existing alert-sourced tickets.

    Value = created_at - wazuh_alert.ingested_at (analyst-actionable -> ticket).
    Both operands are immutable (auto_now_add), so this is correct and
    idempotent. Manual tickets (no source alert) and any clock-skew rows
    (ingested_at after created_at) are deliberately left null.

    Done in Python rather than a bulk .update() because Django disallows
    joined-field F() references (wazuh_alert__ingested_at) in UPDATE. The set
    of alert-sourced tickets is small, so a loop + bulk_update is fine.
    """
    Ticket = apps.get_model('incidents', 'Ticket')
    qs = Ticket.objects.filter(
        wazuh_alert__isnull=False,
        alert_conversion_duration__isnull=True,
    ).select_related('wazuh_alert')

    to_update = []
    for ticket in qs:
        ingested_at = ticket.wazuh_alert.ingested_at
        if ingested_at and ticket.created_at and ingested_at <= ticket.created_at:
            ticket.alert_conversion_duration = ticket.created_at - ingested_at
            to_update.append(ticket)

    if to_update:
        Ticket.objects.bulk_update(to_update, ['alert_conversion_duration'])


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0022_ticket_alert_conversion_duration'),
        ('wazuh_ingest', '0005_alter_wazuhalert_triage_status'),
    ]

    operations = [
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
