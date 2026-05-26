import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Add Ticket.assigned_admin — the external System Admin this ticket is routed to.
    Nullable FK; no existing-data concern (table is empty on first deploy).
    """

    dependencies = [
        ('incidents', '0003_fk_assigned_to_and_author'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='ticket',
            name='assigned_admin',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='admin_tickets',
                to=settings.AUTH_USER_MODEL,
                verbose_name='ผู้ดูแลระบบที่รับผิดชอบ',
            ),
        ),
    ]
