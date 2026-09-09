"""Split the alert stream into triage work and vulnerability inventory.

Wazuh's vulnerability detector emits one alert per (host, package, CVE) on
every scan. In the 2026-09 production queue that was 771 of 849 rows — 188
CVEs on two kernel packages across five hosts — all at rule_level 13, all
past the 4-hour triage OLA, and all protected from the retention purge
because PENDING alerts are never deleted.

This adds `kind` and backfills it, so the triage queue can scope itself to
KIND_DETECTION. Nothing is deleted: the vulnerability rows stay, they just
stop being presented as triage work.
"""

from django.db import migrations, models

VULNERABILITY_RULE_GROUP = 'vulnerability-detector'


def set_kind_from_rule_groups(apps, schema_editor):
    """Backfill `kind` for alerts ingested before the column existed.

    Uses the jsonb `contains` lookup rather than importing
    WazuhAlert.classify_kind: a data migration must keep behaving the way it
    did the day it was written, and pulling in live model code would let a
    later change to the classifier silently rewrite what this migration means.
    The two are kept in step by test_migration_backfill_matches_classifier.
    """
    WazuhAlert = apps.get_model('wazuh_ingest', 'WazuhAlert')
    WazuhAlert.objects.filter(
        rule_groups__contains=[VULNERABILITY_RULE_GROUP],
    ).update(kind='VULNERABILITY')


class Migration(migrations.Migration):

    dependencies = [
        ('wazuh_ingest', '0006_wazuhalert_project_incident'),
    ]

    operations = [
        migrations.AddField(
            model_name='wazuhalert',
            name='kind',
            field=models.CharField(
                choices=[('DETECTION', 'Detection'), ('VULNERABILITY', 'Vulnerability')],
                db_index=True,
                default='DETECTION',
                help_text='Whether this alert is triage work or vulnerability inventory.',
                max_length=16,
            ),
        ),
        # Reverse is a no-op: un-applying drops the column, so there is nothing
        # to restore, and DETECTION is the field default for a re-apply.
        migrations.RunPython(set_kind_from_rule_groups, migrations.RunPython.noop),
    ]
