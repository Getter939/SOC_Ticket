"""The IOC Database: two IOC sources unified, plus the analyst's manual entries.

Sources:
  • ticket IOCs  — entered by T1/T2 analysts on tickets (TicketIOC)
  • manual IOCs  — indicators the Forensic Analyst found externally and typed in
                   here (AnalystIOC); NOT the MISP/TI-platform set

The FA reviews each indicator against MISP and annotates it — a two-state
Checked/Not-Checked flag and a free-text note — stored per (category, value) in
IOCReviewStatus so ticket-sourced indicators can carry them too.
"""

from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Count, Max
from django.utils import timezone

from .ioc_values import TICKET_CATEGORY_CHOICES, normalize_for_category
from .models import AnalystIOC, IOCReviewStatus, TicketIOC

TICKET_CATEGORY_LABELS = dict(TICKET_CATEGORY_CHOICES)
SOURCE_LABELS = {'ticket': 'Ticket', 'analyst': 'Manual'}


def can_manage_inventory(user):
    profile = getattr(user, 'profile', None)
    return user.is_superuser or bool(profile and profile.is_forensic)


# ── The unified view ──────────────────────────────────────────────────────── #

def build_ioc_database(query='', status='all', source='all', category='all'):
    """Every distinct indicator (category, value) from BOTH sources, annotated with
    the FA's review status and note. Returns (rows, counts).

    ``counts`` are over the whole database (before filters), for the summary line.
    """
    observed = {}
    for row in (TicketIOC.objects.values('category', 'value')
                .annotate(ticket_count=Count('ticket', distinct=True),
                          last_seen=Max('ticket__created_at'))):
        observed[(row['category'], row['value'])] = row

    manual = {}
    for rec in AnalystIOC.objects.filter(is_active=True):
        manual[(rec.category, rec.ioc_detail)] = rec

    annotations = {
        (a['category'], a['value']): a
        for a in IOCReviewStatus.objects.values('category', 'value', 'checked', 'note')
    }

    rows = []
    for key in set(observed) | set(manual):
        category_code, value = key
        obs = observed.get(key)
        rec = manual.get(key)
        annotation = annotations.get(key)
        sources = [name for name, present in
                   (('ticket', obs is not None), ('analyst', rec is not None)) if present]
        if obs:
            last_seen = obs['last_seen']
        elif rec is not None:
            last_seen = rec.created_at
        else:
            last_seen = None
        rows.append({
            'category': category_code,
            'category_label': TICKET_CATEGORY_LABELS.get(category_code, category_code),
            'value': value,
            'note': (annotation or {}).get('note', ''),
            'sources': sources,
            'source_label': ' + '.join(SOURCE_LABELS[name] for name in sources),
            'status': 'checked' if (annotation or {}).get('checked') else 'not_checked',
            'ticket_count': obs['ticket_count'] if obs else 0,
            'last_seen': last_seen,
            'analyst_rec': rec,
        })

    counts = {
        'total': len(rows),
        'checked': sum(1 for row in rows if row['status'] == 'checked'),
        'not_checked': sum(1 for row in rows if row['status'] == 'not_checked'),
    }

    query = (query or '').strip().lower()
    if query:
        def matches(row):
            rec = row['analyst_rec']
            return (query in row['value'].lower()
                    or query in (row['note'] or '').lower()
                    or (rec is not None and query in (rec.ext_id or '').lower()))
        rows = [row for row in rows if matches(row)]
    if status in ('checked', 'not_checked'):
        rows = [row for row in rows if row['status'] == status]
    if source in ('ticket', 'analyst'):
        rows = [row for row in rows if source in row['sources']]
    if category in TICKET_CATEGORY_LABELS:
        rows = [row for row in rows if row['category'] == category]

    # Not-checked first (the worklist), then busiest, then value.
    rows.sort(key=lambda row: (row['status'] != 'not_checked', -row['ticket_count'], row['value']))
    return rows, counts


# ── Annotations (shared by both sources) ──────────────────────────────────── #

def _validate_key(category, value):
    value = (value or '').strip()[:500]
    if not value or category not in TICKET_CATEGORY_LABELS:
        raise ValidationError('Unknown IOC.')
    return value


def set_review_status(category, value, checked, user):
    """Set the FA's Checked / Not-Checked flag. Leaves any note untouched."""
    value = _validate_key(category, value)
    status, _ = IOCReviewStatus.objects.update_or_create(
        category=category, value=value,
        defaults={'checked': bool(checked), 'updated_by': user},
    )
    return status


def set_note(category, value, note, user):
    """Set the note for one indicator — works for ticket- and manual-sourced rows
    alike. Leaves the Checked flag untouched."""
    value = _validate_key(category, value)
    annotation, _ = IOCReviewStatus.objects.update_or_create(
        category=category, value=value,
        defaults={'note': (note or '').strip(), 'updated_by': user},
    )
    return annotation


def _move_annotation(old_key, new_key, user):
    """Carry a note/status across when a manual IOC's value is edited."""
    if TicketIOC.objects.filter(category=old_key[0], value=old_key[1]).exists():
        return          # the old indicator still exists via a ticket — leave it alone
    old = IOCReviewStatus.objects.filter(category=old_key[0], value=old_key[1]).first()
    if old is None:
        return
    if IOCReviewStatus.objects.filter(category=new_key[0], value=new_key[1]).exists():
        old.delete()    # the destination already has one; don't clobber it
        return
    old.category, old.value, old.updated_by = new_key[0], new_key[1], user
    old.save(update_fields=['category', 'value', 'updated_by'])


# ── Manual entries ────────────────────────────────────────────────────────── #

def _is_duplicate(category, value, exclude_pk=None):
    """True when the indicator already exists anywhere — on a ticket or as an
    active manual entry."""
    manual = AnalystIOC.objects.filter(category=category, ioc_detail=value, is_active=True)
    if exclude_pk is not None:
        manual = manual.exclude(pk=exclude_pk)
    return manual.exists() or TicketIOC.objects.filter(category=category, value=value).exists()


def create_manual_iocs(entries, user):
    """Add the analyst's typed IOCs.

    ``entries`` are cleaned dicts of category / value / file_name / note. Each is
    either **created**, **restored** (the same indicator was removed earlier — bring
    that record back with its original MAN- id) or reported a **duplicate** (the
    value already exists on a ticket or as an active manual entry).

    Returns a list of ``(entry, outcome)`` so the caller can report the results.
    """
    results = []
    with transaction.atomic():
        for entry in entries:
            category, value = entry['category'], entry['value']
            file_name = entry.get('file_name') or ''
            if _is_duplicate(category, value):
                results.append((entry, 'duplicate'))
                continue
            removed = AnalystIOC.objects.filter(
                category=category, ioc_detail=value, is_active=False).first()
            if removed is not None:
                AnalystIOC.objects.filter(pk=removed.pk).update(
                    is_active=True, removed_by=None, removed_at=None,
                    file_name=file_name, added_by=user)
                outcome = 'restored'
            else:
                # ext_id is unique and derived from the row's own pk, so it is
                # written in a second step behind a throwaway placeholder.
                record = AnalystIOC.objects.create(
                    ext_id=f'tmp-{uuid4().hex}', category=category, ioc_detail=value,
                    file_name=file_name, added_by=user)
                AnalystIOC.objects.filter(pk=record.pk).update(ext_id=f'MAN-{record.pk:04d}')
                outcome = 'created'
            if entry.get('note'):
                set_note(category, value, entry['note'], user)
            results.append((entry, outcome))
    return results


def update_manual_ioc(pk, category, value, file_name, user):
    """Edit a manual entry in place; carries its annotation across a value change."""
    with transaction.atomic():
        record = AnalystIOC.objects.select_for_update().filter(pk=pk, is_active=True).first()
        if record is None:
            raise ValidationError('That IOC is no longer in the database.')
        value = normalize_for_category(category, value)
        if not value:
            raise ValidationError('Enter an IOC value.')
        old_key = (record.category, record.ioc_detail)
        new_key = (category, value)
        if new_key != old_key and _is_duplicate(category, value, exclude_pk=pk):
            raise ValidationError('That IOC is already in the database.')
        record.category, record.ioc_detail = category, value
        record.file_name = file_name or ''
        record.save(update_fields=['category', 'ioc_detail', 'file_name'])
        if new_key != old_key:
            _move_annotation(old_key, new_key, user)
    return record


def remove_analyst_ioc(pk, user):
    """Soft-remove a mistaken manual entry (hidden from the database, kept for audit)."""
    return AnalystIOC.objects.filter(pk=pk, is_active=True).update(
        is_active=False, removed_by=user, removed_at=timezone.now())
