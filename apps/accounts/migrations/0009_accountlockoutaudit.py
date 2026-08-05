# Generated manually for auditable, targeted django-axes lockout resets.

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('accounts', '0008_alter_userprofile_role'),
    ]

    operations = [
        migrations.CreateModel(
            name='AccountLockoutAudit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=150)),
                ('ip_address', models.GenericIPAddressField()),
                ('reason', models.TextField()),
                ('attempts_cleared', models.PositiveIntegerField()),
                ('unlocked_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='account_lockout_reset_actions', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='account_lockout_resets', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('-unlocked_at',),
            },
        ),
        migrations.AddIndex(
            model_name='accountlockoutaudit',
            index=models.Index(fields=['username', 'unlocked_at'], name='accounts_ac_usernam_de0f27_idx'),
        ),
        migrations.AddIndex(
            model_name='accountlockoutaudit',
            index=models.Index(fields=['ip_address', 'unlocked_at'], name='accounts_ac_ip_addr_75784d_idx'),
        ),
    ]
