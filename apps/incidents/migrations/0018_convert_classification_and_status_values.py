"""
Data migration for the workflow redesign — convert existing rows.

  classification (was disposition):
    TRUE_POSITIVE  → INCIDENT
    FALSE_POSITIVE → EVENT

  status (remap in-flight tickets onto the new state machine):
    UNDER_REVIEW → CONTAINMENT_REPORTED   (the single Tier 1 verification step)
    VERIFIED     → PENDING_MANAGER         (T1 verified, awaiting manager)
    CLOSED_FP    → CLOSED_EVENT            (benign close)

NEW / ESCALATED_T2 / AWAITING_CONTAINMENT / CONTAINMENT_REPORTED / APPROVED are
unchanged. Historical TicketLog.status_at_time codes are intentionally left
untouched — the audit trail records what actually happened at the time.
"""

from django.db import migrations


CLASSIFICATION_MAP = {
    'TRUE_POSITIVE':  'INCIDENT',
    'FALSE_POSITIVE': 'EVENT',
}

STATUS_MAP = {
    'UNDER_REVIEW': 'CONTAINMENT_REPORTED',
    'VERIFIED':     'PENDING_MANAGER',
    'CLOSED_FP':    'CLOSED_EVENT',
}


def forwards(apps, schema_editor):
    Ticket = apps.get_model('incidents', 'Ticket')
    for old, new in CLASSIFICATION_MAP.items():
        Ticket.objects.filter(classification=old).update(classification=new)
    for old, new in STATUS_MAP.items():
        Ticket.objects.filter(status=old).update(status=new)


def backwards(apps, schema_editor):
    Ticket = apps.get_model('incidents', 'Ticket')
    # Best-effort reverse. VERIFIED→PENDING_MANAGER is the only ambiguous one
    # (CONTAINMENT_REPORTED also maps back from UNDER_REVIEW); we restore the
    # value pairings that round-trip unambiguously.
    reverse_class = {v: k for k, v in CLASSIFICATION_MAP.items()}
    for old, new in reverse_class.items():
        Ticket.objects.filter(classification=old).update(classification=new)
    Ticket.objects.filter(status='PENDING_MANAGER').update(status='VERIFIED')
    Ticket.objects.filter(status='CLOSED_EVENT').update(status='CLOSED_FP')


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0017_ticket_escalated_to_t2_at_ticket_is_emergency_and_more'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
