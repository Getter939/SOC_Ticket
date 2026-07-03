from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_systemowner_role'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(
                choices=[
                    ('SOC_STAFF', 'SOC Staff'),
                    ('SOC_MANAGER', 'SOC Manager'),
                    ('SYSTEM_ADMIN', 'System Admin'),
                    ('SYSTEM_OWNER', 'System Owner'),
                    ('EXECUTIVE', 'Executive'),
                ],
                default='SOC_STAFF',
                max_length=20,
                verbose_name='บทบาท',
            ),
        ),
    ]
