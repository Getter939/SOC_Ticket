from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_userprofile_role_tier'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(
                choices=[
                    ('SOC_STAFF',    'SOC Staff'),
                    ('SOC_MANAGER',  'SOC Manager'),
                    ('SYSTEM_ADMIN', 'System Admin'),
                    ('SYSTEM_OWNER', 'System Owner'),
                ],
                default='SOC_STAFF',
                max_length=20,
                verbose_name='บทบาท',
            ),
        ),
    ]
