"""
Rename Ticket.disposition → Ticket.classification.

Part 1 of the workflow redesign: the TP/FP "disposition" becomes the
Event/Incident "classification". This migration only renames the column so the
existing data is preserved; 0017 updates the field definition / choices and
0018 converts the stored values (TRUE_POSITIVE→INCIDENT, FALSE_POSITIVE→EVENT).
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0015_alter_ticket_mitre_phase'),
    ]

    operations = [
        migrations.RenameField(
            model_name='ticket',
            old_name='disposition',
            new_name='classification',
        ),
    ]
