"""
Migration 0005: Replace old 4-state workflow with the 7-state SOC containment
workflow, and add the sign-off / containment fields introduced in Session 5.

Changes:
  1. Ticket.status       — new 7-state choices, default='NEW', max_length 20→30
  2. TicketLog.status_at_time — max_length 20→30  (mirrors Ticket.status)
  3. Ticket.disposition  — CharField 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | ''
  4. Ticket.containment_report — TextField
  5. Ticket.verified_by  — FK(User, SET_NULL, nullable)
  6. Ticket.verified_at  — DateTimeField nullable
  7. Ticket.approved_by  — FK(User, SET_NULL, nullable)
  8. Ticket.approved_at  — DateTimeField nullable

Data note: existing rows whose status no longer matches the new choices are left
as-is at the database level (Django choices are not DB constraints). On a
fresh dev SQLite this is not an issue.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0004_ticket_assigned_admin'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # 1. Replace status field
        migrations.AlterField(
            model_name='ticket',
            name='status',
            field=models.CharField(
                choices=[
                    ('NEW',                  'แจ้งเหตุใหม่'),
                    ('AWAITING_CONTAINMENT', 'รอการจัดการจากผู้ดูแลระบบ'),
                    ('CONTAINMENT_REPORTED', 'รายงานการควบคุมแล้ว'),
                    ('UNDER_REVIEW',         'กำลังตรวจสอบ'),
                    ('VERIFIED',             'ตรวจสอบแล้ว'),
                    ('APPROVED',             'อนุมัติแล้ว'),
                    ('CLOSED_FP',            'ปิด (เหตุการณ์ปลอม)'),
                ],
                default='NEW',
                max_length=30,
            ),
        ),

        # 2. TicketLog.status_at_time — widen to match
        migrations.AlterField(
            model_name='ticketlog',
            name='status_at_time',
            field=models.CharField(max_length=30, verbose_name='สถานะขณะบันทึก'),
        ),

        # 3. disposition
        migrations.AddField(
            model_name='ticket',
            name='disposition',
            field=models.CharField(
                blank=True,
                choices=[
                    ('TRUE_POSITIVE',  'เหตุการณ์จริง (True Positive)'),
                    ('FALSE_POSITIVE', 'เหตุการณ์ปลอม (False Positive)'),
                ],
                default='',
                max_length=20,
                verbose_name='การวินิจฉัยเหตุการณ์',
            ),
        ),

        # 4. containment_report
        migrations.AddField(
            model_name='ticket',
            name='containment_report',
            field=models.TextField(blank=True, default='', verbose_name='รายงานการควบคุม'),
        ),

        # 5. verified_by
        migrations.AddField(
            model_name='ticket',
            name='verified_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='verified_tickets',
                to=settings.AUTH_USER_MODEL,
                verbose_name='ผู้ตรวจสอบ',
            ),
        ),

        # 6. verified_at
        migrations.AddField(
            model_name='ticket',
            name='verified_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='วันที่ตรวจสอบ'),
        ),

        # 7. approved_by
        migrations.AddField(
            model_name='ticket',
            name='approved_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='approved_tickets',
                to=settings.AUTH_USER_MODEL,
                verbose_name='ผู้อนุมัติ',
            ),
        ),

        # 8. approved_at
        migrations.AddField(
            model_name='ticket',
            name='approved_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='วันที่อนุมัติ'),
        ),
    ]
