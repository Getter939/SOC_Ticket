# Generated manually to add durable, password-free credential audit events.

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('accounts', '0006_alter_userprofile_role'),
    ]

    operations = [
        migrations.CreateModel(
            name='PasswordChangeAudit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source', models.CharField(choices=[('SELF_SERVICE_CHANGE', 'Self-service change'), ('SELF_SERVICE_RESET', 'Password-reset link'), ('ADMIN', 'Django admin'), ('SYSTEM', 'System / management command')], max_length=24)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='password_change_actions', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='password_change_audits', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('-created_at',),
            },
        ),
        migrations.AddIndex(
            model_name='passwordchangeaudit',
            index=models.Index(fields=['user', 'created_at'], name='accounts_pa_user_id_721122_idx'),
        ),
    ]
