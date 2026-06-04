from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0005_new_workflow_fields'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ── System Owner fields on Ticket ─────────────────────────────── #
        migrations.AddField(
            model_name='ticket',
            name='system_owner_name',
            field=models.CharField(
                blank=True, default='', max_length=100,
                verbose_name='ชื่อเจ้าของระบบ / หน่วยงาน',
            ),
        ),
        migrations.AddField(
            model_name='ticket',
            name='system_owner_email',
            field=models.EmailField(
                blank=True, default='',
                verbose_name='อีเมลเจ้าของระบบ',
            ),
        ),
        # ── TriageRecord model ────────────────────────────────────────── #
        migrations.CreateModel(
            name='TriageRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('alert_description', models.TextField(verbose_name='รายละเอียด Alert')),
                ('source_ip', models.CharField(blank=True, default='', max_length=50, verbose_name='IP Source')),
                ('decision', models.CharField(
                    choices=[
                        ('FP', 'False Positive — ปิดทันที'),
                        ('TP', 'True Positive — สร้าง Ticket'),
                        ('ESCALATED', 'ไม่แน่ใจ — Escalate ไปยัง T2'),
                    ],
                    max_length=20,
                    verbose_name='การตัดสินใจ T1',
                )),
                ('notes', models.TextField(blank=True, default='', verbose_name='บันทึก T1')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('t2_decision', models.CharField(
                    blank=True,
                    choices=[
                        ('FP', 'False Positive — ปิด'),
                        ('TP', 'True Positive — สร้าง Ticket'),
                    ],
                    default='',
                    max_length=20,
                    verbose_name='การตัดสินใจ T2',
                )),
                ('t2_notes', models.TextField(blank=True, default='', verbose_name='บันทึก T2')),
                ('t2_decided_at', models.DateTimeField(blank=True, null=True)),
                ('analyst', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='triage_records',
                    to=settings.AUTH_USER_MODEL,
                    verbose_name='นักวิเคราะห์ T1',
                )),
                ('escalated_to', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='escalated_triages',
                    to=settings.AUTH_USER_MODEL,
                    verbose_name='Escalate ไปยัง T2',
                )),
                ('ticket', models.OneToOneField(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='triage',
                    to='incidents.ticket',
                    verbose_name='Ticket ที่สร้าง',
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
