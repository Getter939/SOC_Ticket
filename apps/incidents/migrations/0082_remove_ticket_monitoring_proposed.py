from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0081_ticket_event_summary'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ticket',
            name='monitoring_proposed',
        ),
    ]
