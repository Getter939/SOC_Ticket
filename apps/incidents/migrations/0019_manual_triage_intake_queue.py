from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('incidents', '0018_convert_classification_and_status_values'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='triagerecord',
            name='decision',
            field=models.CharField(
                blank=True,
                choices=[
                    ('FP', 'Event — ปิดเคส'),
                    ('TP', 'Incident — สร้าง Ticket'),
                    ('ESCALATED', 'ส่งต่อให้ Tier 2 (ข้อมูลเดิม)'),
                ],
                default='',
                max_length=20,
                verbose_name='ผลลัพธ์เดิมของ Manual Triage',
            ),
        ),
        migrations.AlterField(
            model_name='triagerecord',
            name='t2_decision',
            field=models.CharField(
                blank=True,
                choices=[('FP', 'Event — ปิดเคส'), ('TP', 'Incident — สร้าง Ticket')],
                default='',
                max_length=20,
                verbose_name='การตัดสินใจ T2',
            ),
        ),
        migrations.AddField(
            model_name='triagerecord',
            name='claimed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='triagerecord',
            name='claimed_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='claimed_manual_triages',
                to=settings.AUTH_USER_MODEL,
                verbose_name='ผู้รับรายการ Manual Triage',
            ),
        ),
        migrations.AddField(
            model_name='triagerecord',
            name='release_reason',
            field=models.TextField(blank=True, default='', verbose_name='เหตุผลที่คืนคิว'),
        ),
    ]
