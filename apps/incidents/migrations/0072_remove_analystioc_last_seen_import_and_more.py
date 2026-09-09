"""Manual entry replaces the CSV import.

The note moves off AnalystIOC onto IOCReviewStatus (keyed by category+value) so
ticket-sourced indicators can carry one too — so the note column is added and the
existing values copied across BEFORE the old column is dropped. The import batch
model and its FKs go with the CSV importer.
"""

from django.db import migrations, models


def copy_notes_to_annotations(apps, schema_editor):
    AnalystIOC = apps.get_model('incidents', 'AnalystIOC')
    IOCReviewStatus = apps.get_model('incidents', 'IOCReviewStatus')
    for record in AnalystIOC.objects.exclude(note='').iterator():
        annotation, created = IOCReviewStatus.objects.get_or_create(
            category=record.category, value=record.ioc_detail,
            defaults={'checked': False, 'note': record.note},
        )
        if not created and not annotation.note:
            annotation.note = record.note
            annotation.save(update_fields=['note'])


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0071_analystiocimport_restored_count'),
    ]

    operations = [
        migrations.AddField(
            model_name='iocreviewstatus',
            name='note',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.RunPython(copy_notes_to_annotations, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='analystioc',
            name='note',
        ),
        migrations.RemoveField(
            model_name='analystioc',
            name='last_seen_import',
        ),
        migrations.RemoveField(
            model_name='analystioc',
            name='source_import',
        ),
        migrations.DeleteModel(
            name='AnalystIOCImport',
        ),
    ]
