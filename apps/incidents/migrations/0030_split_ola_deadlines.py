from datetime import timedelta

from django.db import migrations, models

# Mirror of Ticket.OLA_TARGETS at the time of this migration, kept local so the
# migration stays stable even if the model policy changes again later.
OLA_TARGETS = {
    'Critical': (timedelta(minutes=30), timedelta(hours=4)),
    'High':     (timedelta(hours=2),    timedelta(hours=24)),
    'Medium':   (timedelta(hours=24),   None),
    'Low':      (timedelta(hours=24),   None),
    'Unknown':  (timedelta(minutes=30), timedelta(hours=4)),
}


def backfill_ola_deadlines(apps, schema_editor):
    """Recompute both OLA deadlines for existing tickets under the new policy.

    Old rows carried a single flat 4h deadline (now renamed to
    ola_contain_deadline). Recompute per-severity: set the triage deadline for
    all, and the contain deadline only for severities that have one (Medium/Low
    are notification-only → null). Base time mirrors Ticket.save():
    incident_datetime, else created_at.
    """
    Ticket = apps.get_model('incidents', 'Ticket')
    for t in Ticket.objects.all().iterator():
        base = t.incident_datetime or t.created_at
        if base is None:
            continue
        triage, contain = OLA_TARGETS.get(t.severity, OLA_TARGETS['Unknown'])
        t.ola_triage_deadline = base + triage if triage is not None else None
        t.ola_contain_deadline = base + contain if contain is not None else None
        t.save(update_fields=['ola_triage_deadline', 'ola_contain_deadline'])


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0029_alter_ticket_ola_deadline'),
    ]

    operations = [
        migrations.RenameField(
            model_name='ticket',
            old_name='ola_deadline',
            new_name='ola_contain_deadline',
        ),
        migrations.AddField(
            model_name='ticket',
            name='ola_triage_deadline',
            field=models.DateTimeField(
                null=True, blank=True, verbose_name='OLA Triage Deadline'),
        ),
        migrations.AlterField(
            model_name='ticket',
            name='ola_contain_deadline',
            field=models.DateTimeField(
                null=True, blank=True, verbose_name='OLA Contain Deadline'),
        ),
        migrations.RunPython(backfill_ola_deadlines, migrations.RunPython.noop),
    ]
