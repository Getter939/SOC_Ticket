from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import apps.incidents.models


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0006_system_owner_and_triage'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ── Replace free-text system owner fields with a FK ───────────── #
        migrations.RemoveField(model_name='ticket', name='system_owner_name'),
        migrations.RemoveField(model_name='ticket', name='system_owner_email'),
        migrations.AddField(
            model_name='ticket',
            name='system_owner',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='owned_tickets',
                to=settings.AUTH_USER_MODEL,
                verbose_name='เจ้าของระบบ / หน่วยงาน',
            ),
        ),
        # ── TicketAttachment model ────────────────────────────────────── #
        migrations.CreateModel(
            name='TicketAttachment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('file', models.FileField(upload_to=apps.incidents.models.attachment_upload_path)),
                ('original_name', models.CharField(max_length=255)),
                ('description', models.CharField(blank=True, default='', max_length=255)),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('ticket', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='attachments',
                    to='incidents.ticket',
                )),
                ('uploaded_by', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='uploaded_attachments',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'ordering': ['uploaded_at']},
        ),
    ]
