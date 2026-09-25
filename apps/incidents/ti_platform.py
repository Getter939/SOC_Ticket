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
from django.db.models import (
    BooleanField, Case, CharField, Count, Exists, F, IntegerField, Max, OuterRef, Q,
    Subquery, TextField, Value, When,
)
from django.db.models.functions import Coalesce, NullIf
from django.utils import timezone

from .ioc_values import TICKET_CATEGORY_CHOICES, normalize_for_category
from .models import AnalystIOC, IOCReviewStatus, TicketIOC

TICKET_CATEGORY_LABELS = dict(TICKET_CATEGORY_CHOICES)
SOURCE_LABELS = {'ticket': 'Ticket', 'analyst': 'Manual'}


def can_manage_inventory(user):
    profile = getattr(user, 'profile', None)
    return user.is_superuser or bool(profile and profile.is_forensic)


# ── The unified view ──────────────────────────────────────────────────────── #

#
# The page used to load every indicator from both sources into Python, merge and
# filter them there, and then show 30. That is now done by PostgreSQL, which
# returns only the page being viewed. The merge is split into two DISJOINT
# halves so a plain UNION ALL can combine them:
#
#   1. every (category, value) seen on a ticket — grouped over TicketIOC, with
#      the matching active manual entry (if any) looked up alongside it
#   2. every active manual entry whose (category, value) is on NO ticket
#
# An indicator in both sources therefore appears exactly once, in half 1, which
# is what the old in-memory merge produced. Both halves select the same columns
# in the same order (all aliased, see _KEY_COLUMNS) because a UNION matches
# columns by position, not by name.

_KEY_COLUMNS = (
    'k_category', 'k_value', 'k_ticket_count', 'k_last_seen',
    'k_manual_id', 'k_ext_id', 'k_checked', 'k_note',
    # Sort-only columns. A UNION can only be ordered by columns it selects, so
    # the table's header sorts need these materialised in both halves:
    # k_source = the SOURCE label the row shows; k_note_sort = the note with
    # blank as NULL, so unannotated rows sort last in either direction.
    'k_source', 'k_note_sort',
)
_SOURCE_BOTH = f"{SOURCE_LABELS['ticket']} + {SOURCE_LABELS['analyst']}"


def _review(value_ref, field, default, output_field):
    """The FA's annotation for the outer row's (category, value)."""
    return Coalesce(
        Subquery(
            IOCReviewStatus.objects
            .filter(category=OuterRef('category'), value=OuterRef(value_ref))
            .values(field)[:1]
        ),
        Value(default),
        output_field=output_field,
    )


def _ticket_half():
    """Half 1: one row per distinct indicator seen on a ticket."""
    manual = AnalystIOC.objects.filter(
        is_active=True, category=OuterRef('category'), ioc_detail=OuterRef('value'),
    )
    return (
        TicketIOC.objects.order_by()   # Meta.ordering would leak into the GROUP BY
        .values('category', 'value')
        .annotate(
            k_category=F('category'),
            k_value=F('value'),
            k_ticket_count=Count('ticket', distinct=True),
            k_last_seen=Max('ticket__created_at'),
            k_manual_id=Subquery(manual.values('pk')[:1]),
            k_ext_id=Coalesce(Subquery(manual.values('ext_id')[:1]), Value(''),
                              output_field=CharField()),
            k_checked=_review('value', 'checked', False, BooleanField()),
            k_note=_review('value', 'note', '', TextField()),
        )
        .annotate(
            k_source=Case(
                When(k_manual_id__isnull=False, then=Value(_SOURCE_BOTH)),
                default=Value(SOURCE_LABELS['ticket']), output_field=CharField(),
            ),
            k_note_sort=NullIf(F('k_note'), Value(''), output_field=TextField()),
        )
    )


def _manual_half():
    """Half 2: active manual entries that appear on no ticket."""
    on_a_ticket = TicketIOC.objects.filter(
        category=OuterRef('category'), value=OuterRef('ioc_detail'),
    )
    return (
        AnalystIOC.objects.order_by()
        .filter(is_active=True)
        .exclude(Exists(on_a_ticket))
        .annotate(
            k_category=F('category'),
            k_value=F('ioc_detail'),
            k_ticket_count=Value(0, output_field=IntegerField()),
            k_last_seen=F('created_at'),
            k_manual_id=F('pk'),
            k_ext_id=F('ext_id'),
            k_checked=_review('ioc_detail', 'checked', False, BooleanField()),
            k_note=_review('ioc_detail', 'note', '', TextField()),
        )
        .annotate(
            k_source=Value(SOURCE_LABELS['analyst'], output_field=CharField()),
            k_note_sort=NullIf(F('k_note'), Value(''), output_field=TextField()),
        )
    )


def _filtered(half, query, status, category):
    if category in TICKET_CATEGORY_LABELS:
        half = half.filter(k_category=category)
    if status in ('checked', 'not_checked'):
        half = half.filter(k_checked=(status == 'checked'))
    if query:
        half = half.filter(
            Q(k_value__icontains=query) | Q(k_note__icontains=query)
            | Q(k_ext_id__icontains=query)
        )
    return half.values(*_KEY_COLUMNS)


# Orderings for the IOC Database, by sort key. 'worklist' is the default (the
# FA's queue: not-checked first, then busiest). The rest back the table's
# sortable headers and the results-bar presets. Every one ends on value then
# category so ties stay stable across pages. Union orderings may only name
# selected columns — hence k_source / k_note_sort in _KEY_COLUMNS.
_TIE = ('k_value', 'k_category')
IOC_SORTS = {
    'worklist': ('k_checked', '-k_ticket_count', *_TIE),
    'category': ('k_category', *_TIE),
    '-category': ('-k_category', *_TIE),
    'value': ('k_value', 'k_category'),
    '-value': ('-k_value', 'k_category'),
    'note': (F('k_note_sort').asc(nulls_last=True), *_TIE),
    '-note': (F('k_note_sort').desc(nulls_last=True), *_TIE),
    'status': ('k_checked', *_TIE),
    '-status': ('-k_checked', *_TIE),
    'source': ('k_source', *_TIE),
    '-source': ('-k_source', *_TIE),
    'tickets': ('-k_ticket_count', *_TIE),
    'tickets_asc': ('k_ticket_count', *_TIE),
    'last': ('-k_last_seen', *_TIE),
    'last_oldest': ('k_last_seen', *_TIE),
}


def ioc_database_queryset(query='', status='all', source='all', category='all',
                          sort='worklist'):
    """The filtered, ordered IOC Database as one lazy queryset of raw key rows.

    Nothing is fetched until it is sliced (by the Paginator) or iterated; pass
    each row through decorate_ioc_rows() before rendering. The sort runs in
    SQL too, so it orders the whole database, not just the page on screen.
    """
    query = (query or '').strip()
    ticket_half = _filtered(_ticket_half(), query, status, category)
    manual_half = _filtered(_manual_half(), query, status, category)
    if source == 'ticket':
        combined = ticket_half
    elif source == 'analyst':
        # Half 1 rows that also carry a manual entry, plus all of half 2.
        combined = ticket_half.filter(k_manual_id__isnull=False).union(manual_half, all=True)
    else:
        combined = ticket_half.union(manual_half, all=True)
    return combined.order_by(*IOC_SORTS.get(sort, IOC_SORTS['worklist']))


def ioc_database_counts():
    """Summary-line totals over the whole database, before any filter."""
    ticket_half, manual_half = _ticket_half(), _manual_half()
    total = ticket_half.count() + manual_half.count()
    checked = (
        ticket_half.filter(k_checked=True).count()
        + manual_half.filter(k_checked=True).count()
    )
    return {'total': total, 'checked': checked, 'not_checked': total - checked}


def decorate_ioc_rows(key_rows):
    """Turn raw key rows into what ioc_database.html renders. One query loads
    the manual entries for exactly these rows (for their edit/remove buttons)."""
    key_rows = list(key_rows)
    manual_ids = [row['k_manual_id'] for row in key_rows if row['k_manual_id']]
    records = AnalystIOC.objects.in_bulk(manual_ids)
    rows = []
    for row in key_rows:
        rec = records.get(row['k_manual_id'])
        sources = [name for name, present in
                   (('ticket', row['k_ticket_count'] > 0), ('analyst', rec is not None))
                   if present]
        rows.append({
            'category': row['k_category'],
            'category_label': TICKET_CATEGORY_LABELS.get(row['k_category'], row['k_category']),
            'value': row['k_value'],
            'note': row['k_note'],
            'sources': sources,
            'source_label': ' + '.join(SOURCE_LABELS[name] for name in sources),
            'status': 'checked' if row['k_checked'] else 'not_checked',
            'ticket_count': row['k_ticket_count'],
            'last_seen': row['k_last_seen'],
            'analyst_rec': rec,
        })
    return rows


def build_ioc_database(query='', status='all', source='all', category='all'):
    """Every matching indicator, decorated, plus the summary counts.

    Evaluates the WHOLE filtered list — for tests and one-off scripts. The page
    itself pages through ioc_database_queryset() so only 30 rows are fetched.
    """
    return (
        decorate_ioc_rows(ioc_database_queryset(query, status, source, category)),
        ioc_database_counts(),
    )


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


def create_manual_iocs(entries, user, source_subtask=None):
    """Add the analyst's typed IOCs.

    ``entries`` are cleaned dicts of category / value / file_name / note. Each is
    either **created**, **restored** (the same indicator was removed earlier — bring
    that record back with its original MAN- id) or reported a **duplicate** (the
    value already exists on a ticket or as an active manual entry).

    ``source_subtask`` is the Forensics / RCA request the entries were pushed from
    (apps.incidents.rca.push_iocs); hand-typed entries leave it empty.

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
                restored = dict(
                    is_active=True, removed_by=None, removed_at=None,
                    file_name=file_name, added_by=user)
                if source_subtask is not None:
                    restored['source_subtask'] = source_subtask
                AnalystIOC.objects.filter(pk=removed.pk).update(**restored)
                outcome = 'restored'
            else:
                # ext_id is unique and derived from the row's own pk, so it is
                # written in a second step behind a throwaway placeholder.
                record = AnalystIOC.objects.create(
                    ext_id=f'tmp-{uuid4().hex}', category=category, ioc_detail=value,
                    file_name=file_name, added_by=user, source_subtask=source_subtask)
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
