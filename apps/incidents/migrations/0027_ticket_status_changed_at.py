from django.db import migrations, models


def backfill_status_changed_at(apps, schema_editor):
    """Seed status_changed_at for tickets that predate the field.

    Best available source is the TicketLog audit trail: the most recent log
    row whose status_at_time matches the ticket's *current* status approximates
    when it entered that status. Falls back to updated_at, then created_at, so
    every ticket gets a non-null value. (Imprecision here only affects historical
    rows — going forward transition_to stamps the exact moment.)
    """
    Ticket = apps.get_model('incidents', 'Ticket')
    TicketLog = apps.get_model('incidents', 'TicketLog')

    for ticket in Ticket.objects.all().iterator():
        log = (
            TicketLog.objects
            .filter(ticket=ticket, status_at_time=ticket.status)
            .order_by('-created_at')
            .values_list('created_at', flat=True)
            .first()
        )
        ticket.status_changed_at = log or ticket.updated_at or ticket.created_at
        ticket.save(update_fields=['status_changed_at'])


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0026_normalize_issue_type_source_values'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticket',
            name='status_changed_at',
            field=models.DateTimeField(
                blank=True, null=True, verbose_name='วันที่อัปเดตสถานะ'),
        ),
        migrations.RunPython(
            backfill_status_changed_at, migrations.RunPython.noop),
    ]
