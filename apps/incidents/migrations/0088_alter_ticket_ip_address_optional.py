import apps.incidents.ip_addresses
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0087_subtask_report_number'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ticket',
            name='ip_address',
            field=models.TextField(
                blank=True,
                help_text='ระบุ IPv4 หรือ IPv6 ได้หลายรายการ คั่นด้วยจุลภาคหรือขึ้นบรรทัดใหม่',
                null=True,
                validators=[apps.incidents.ip_addresses.validate_ip_addresses],
                verbose_name='IP Addresses ของทรัพย์สิน',
            ),
        ),
    ]
