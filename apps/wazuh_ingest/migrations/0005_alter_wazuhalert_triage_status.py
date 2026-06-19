from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('wazuh_ingest', '0004_wazuhalert_release_reason'),
    ]

    operations = [
        migrations.AlterField(
            model_name='wazuhalert',
            name='triage_status',
            field=models.CharField(
                choices=[
                    ('PENDING', 'Pending'),
                    ('TRIAGING', 'Triaging'),
                    ('TRUE_POSITIVE', 'Incident'),
                    ('FALSE_POSITIVE', 'Event'),
                    ('ESCALATED', 'Escalated'),
                ],
                default='PENDING',
                max_length=16,
            ),
        ),
    ]
