from django.db import migrations


# Change 2 unified Ticket.issue_type onto the shared SOURCE_CHOICES vocabulary.
# Two legacy ticket values need normalising to the UPPER_SNAKE codes; 'SIEM'
# and 'TI' are unchanged, and TriageRecord.source already used these codes.
RENAMES = [
    ('Admin', 'ADMIN'),
    ('External', 'EXTERNAL'),
]


def forwards(apps, schema_editor):
    Ticket = apps.get_model('incidents', 'Ticket')
    for old, new in RENAMES:
        Ticket.objects.filter(issue_type=old).update(issue_type=new)


def backwards(apps, schema_editor):
    Ticket = apps.get_model('incidents', 'Ticket')
    for old, new in RENAMES:
        Ticket.objects.filter(issue_type=new).update(issue_type=old)


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0025_alter_ticket_issue_type_alter_triagerecord_source'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
