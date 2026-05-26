from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='role',
            field=models.CharField(
                choices=[
                    ('SOC_STAFF', 'SOC Staff'),
                    ('SOC_MANAGER', 'SOC Manager'),
                    ('SYSTEM_ADMIN', 'System Admin'),
                ],
                default='SOC_STAFF',
                max_length=20,
                verbose_name='บทบาท',
            ),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='tier',
            field=models.CharField(
                blank=True,
                choices=[('T1', 'T1'), ('T2', 'T2')],
                default='',
                max_length=5,
                verbose_name='ระดับ (Tier)',
            ),
        ),
    ]
