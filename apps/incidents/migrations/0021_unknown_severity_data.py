# Data migration for the additive 'Unknown' severity level.
#
# Adding 'Unknown' to Ticket.SEVERITY_CHOICES is purely additive: no existing
# row carries a severity that must be remapped to Unknown, and no Unknown row
# can exist yet. There is therefore nothing to convert in either direction.
#
# This migration is intentionally a no-op. It exists to make the additive
# nature of the change explicit in the migration history (mirroring the
# convention of 0018, which did remap legacy values) and to give a stable
# anchor point for any future data adjustment tied to Unknown.

from django.db import migrations


def forwards(apps, schema_editor):
    # No-op: 'Unknown' is a new, human-assigned classification. Existing
    # tickets keep their current severity; none are converted to Unknown.
    pass


def backwards(apps, schema_editor):
    # No-op: nothing was changed on the way forward, so nothing to undo.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0020_alter_ticket_severity'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
