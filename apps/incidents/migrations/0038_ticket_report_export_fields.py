from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('incidents', '0037_alter_ticket_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticket',
            name='actions_taken_summary',
            field=models.TextField(blank=True, default='', verbose_name='สรุปเรื่องที่ดำเนินการแล้ว'),
        ),
        migrations.AddField(
            model_name='ticket',
            name='next_steps_summary',
            field=models.TextField(blank=True, default='', verbose_name='สรุปการดำเนินการลำดับถัดไป'),
        ),
        migrations.AddField(
            model_name='ticket',
            name='report_generated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='ticket',
            name='report_generated_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='generated_ticket_reports', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='ticket',
            name='report_sha256',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AddField(
            model_name='ticket',
            name='report_template_version',
            field=models.CharField(blank=True, default='', max_length=20),
        ),
        migrations.AddField(
            model_name='ticket',
            name='report_ticket_updated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
