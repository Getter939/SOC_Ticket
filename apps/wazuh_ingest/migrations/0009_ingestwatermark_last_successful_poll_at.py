from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wazuh_ingest', '0008_alter_wazuhalert_escalated_to_tier_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='ingestwatermark',
            name='last_successful_poll_at',
            field=models.DateTimeField(
                blank=True,
                null=True,
                verbose_name='เวลาที่ดึงข้อมูล Wazuh สำเร็จล่าสุด',
            ),
        ),
    ]
