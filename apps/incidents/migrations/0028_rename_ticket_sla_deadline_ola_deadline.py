from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0027_ticket_status_changed_at'),
    ]

    operations = [
        migrations.RenameField(
            model_name='ticket',
            old_name='sla_deadline',
            new_name='ola_deadline',
        ),
    ]
