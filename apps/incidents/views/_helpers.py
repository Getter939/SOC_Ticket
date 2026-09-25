import calendar
import logging
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import (
    Case, CharField, Exists, F, IntegerField, OuterRef, Q, Value, When,
)
from django.db.models.functions import Coalesce, Concat, Lower, NullIf, Trim
from django.shortcuts import render
from django.utils import timezone
from django.utils.dateparse import parse_date

from apps.incidents import ola as ola_buckets
from ..models import (
    MAX_ATTACHMENT_BATCH_SIZE, MAX_ATTACHMENT_SIZE, ThreatGuidance, Ticket,
    TicketLog, allowed_attachment_extensions,
)
from ..staging import (
    MAX_ATTACHMENT_COUNT,
)
from ..notifications import (
    notify_containment_alert,
)
from ..policies import (
    can_bulk_export_ticket_reports as _can_bulk_export_ticket_reports,
    user_can_drive as _user_can_drive,
)
from ..models import TicketCancellationRequest

logger = logging.getLogger('apps.incidents.views')


# ── Private helpers ──────────────────────────────────────────────────── #

def _active_threat_guidance():
    """Return the client-side containment guidance keyed by threat category."""
    return {
        guidance.detailed_issue: {
            'action_required': guidance.action_required,
            'action_precautions': guidance.action_precautions,
        }
        for guidance in ThreatGuidance.objects.filter(is_active=True)
    }


def _valid_soc_status_choices(ticket, user):
    """Status options to offer this user in the detail-page dropdown, honoring
    the state machine, the Event/Incident + manager-routing gates, and the
    per-user transition permission.
    """
    profile = getattr(user, 'profile', None)
    if not user.is_superuser and (profile is None or not profile.is_soc):
        return []

    status_map = dict(Ticket.STATUS_CHOICES)
    result = []
    if (
        not user.is_superuser
        and ticket.status in Ticket.CREATOR_REVIEW_STATUSES
        and user.pk != ticket.created_by_id
    ):
        pass  # not this ticket's creator — can't even add a note in this stage
    else:
        result.append((ticket.status, status_map.get(ticket.status, ticket.status)))

    for next_status in Ticket.ALLOWED_TRANSITIONS.get(ticket.status, []):
        edge = (ticket.status, next_status)
        if (edge in Ticket.STEP_BACK_EDGES or edge in Ticket.MONITORING_EDGES
                or edge in Ticket.MANAGER_RETURN_EDGES):
            continue  # step-back / monitoring / manager return have their own controls
        if not ticket.can_transition_to(next_status):
            continue  # blocked by classification or manager-routing gate
        perm = Ticket.TRANSITION_PERMISSIONS.get((ticket.status, next_status))
        if perm == 'ASSIGNED_ADMIN':
            continue  # admin uses the containment form, not this dropdown
        if _user_can_drive(ticket, user, perm):
            result.append((next_status, status_map.get(next_status, next_status)))

    return result


def _case_switch_qs(triage_id=None, alert_id=None, evidence_token=None):
    """Query string carrying the case's origin across the single ↔ multi switch.

    The two creation forms are one menu entry with a mode toggle, so switching
    must not lose the manual-triage record or Wazuh alert the analyst started
    from — otherwise the new case would come back unlinked. The evidence token
    rides along for the same reason: the toggle is a full page load, so without
    it any staged evidence would be stranded.
    """
    params = {k: v for k, v in (
        ('triage_id', triage_id), ('wazuh_alert', alert_id),
        ('evidence_token', evidence_token),
    ) if v}
    return urlencode(params)


def _attachment_limits():
    """Upload rules handed to the evidence picker's client-side pre-check.

    Derived from the model constants rather than restated in the template, so
    the `accept` list and the in-browser checks cannot drift from what
    validate_attachment actually enforces. The template hands this dict to the
    picker with the |json_script filter (an inert application/json data block).
    """
    extensions = allowed_attachment_extensions()
    return {
        'allowed_extensions': extensions,
        'accept': ','.join('.' + ext for ext in extensions),
        'max_file_size': MAX_ATTACHMENT_SIZE,
        'max_batch_size': MAX_ATTACHMENT_BATCH_SIZE,
        'max_count': MAX_ATTACHMENT_COUNT,
    }


def _transition_actions(ticket, user):
    """Return only legal, permitted forward actions for the current user."""
    if (
        ticket.project_incident_id
        and ticket.status == Ticket.STATUS_PENDING_MGR_TRIAGE
        and ticket.project_incident.emergency_decided_at is None
    ):
        return []
    labels = {
        Ticket.STATUS_CLOSED_EVENT: (
            'Confirm Event -> Close'
            if ticket.status == Ticket.STATUS_PENDING_MGR_EVENT_REVIEW
            else 'Mark as Event -> Close'
        ),
        Ticket.STATUS_PENDING_MGR_EVENT_REVIEW: 'Mark as Event -> SOC Manager verification',
        Ticket.STATUS_PENDING_MGR_TRIAGE: (
            'Mark as Incident -> SOC Manager review'
            if ticket.status == Ticket.STATUS_ESCALATED_T2
            else 'Route to SOC Manager review'
        ),
        # Records what the owner reported; it does not assert the fix is good.
        # "Confirm" was what invited Tier 1 to adjudicate a call that belongs
        # to Tier 2.
        Ticket.STATUS_OWNER_REMEDIATED: 'บันทึกผลจากเจ้าของระบบ (Record owner report)',
        Ticket.STATUS_PENDING_T2_REVIEW: 'Send to Tier 2 review',
        Ticket.STATUS_PENDING_MANAGER: 'Send to SOC Manager',
        Ticket.STATUS_APPROVED: (
            'Verify -> Close'
            if ticket.status in (
                Ticket.STATUS_PENDING_MANAGER, Ticket.STATUS_PENDING_T2_REVIEW,
                Ticket.STATUS_CONTAINMENT_REPORTED,
            ) else 'Close case'
        ),
    }
    actions = []
    for next_status in Ticket.ALLOWED_TRANSITIONS.get(ticket.status, []):
        edge = (ticket.status, next_status)
        if (edge in Ticket.STEP_BACK_EDGES or edge in Ticket.MONITORING_EDGES
                or edge in Ticket.MANAGER_RETURN_EDGES):
            continue  # step-back / monitoring / manager return have their own controls
        can_transition = ticket.can_transition_to(next_status)
        # Tier 2's decision buttons also set the classification (and, for the
        # Incident decision, the lane — chosen on the same form, so assume one).
        # Ask the model whether each edge is valid with that proposal.
        if ticket.status == Ticket.STATUS_ESCALATED_T2:
            proposed = {
                Ticket.STATUS_CLOSED_EVENT: Ticket.CLASSIFICATION_EVENT,
                # Same Event decision, but for a ticket Tier 2 is downgrading
                # from Incident the model routes it via the manager instead.
                Ticket.STATUS_PENDING_MGR_EVENT_REVIEW: Ticket.CLASSIFICATION_EVENT,
                Ticket.STATUS_PENDING_MGR_TRIAGE: Ticket.CLASSIFICATION_INCIDENT,
            }.get(next_status)
            if proposed:
                original = ticket.classification, ticket.t1_route
                ticket.classification = proposed
                if next_status == Ticket.STATUS_PENDING_MGR_TRIAGE:
                    ticket.t1_route = Ticket.T1_ROUTE_OWNER  # lane comes from the form
                can_transition = ticket.can_transition_to(next_status)
                ticket.classification, ticket.t1_route = original
        if not can_transition:
            continue
        permission = Ticket.TRANSITION_PERMISSIONS.get((ticket.status, next_status))
        if permission == 'ASSIGNED_ADMIN' or not _user_can_drive(ticket, user, permission):
            continue
        label = labels.get(next_status, dict(Ticket.STATUS_CHOICES).get(next_status, next_status))
        if next_status == Ticket.STATUS_AWAITING_CONTAINMENT:
            label = (
                'Return to System Admin (not contained)'
                if ticket.status == Ticket.STATUS_CONTAINMENT_REPORTED
                else 'Send to System Admin'
            )
        # From AWAITING_OWNER this single action IS the relay, so name what
        # Tier 1 is asserting. The legacy OWNER_REMEDIATED hop keeps the plain
        # wording — by then the report was already recorded.
        if (next_status == Ticket.STATUS_PENDING_T2_REVIEW
                and ticket.status == Ticket.STATUS_AWAITING_OWNER):
            label = 'เจ้าของแจ้งแก้ไขแล้ว → ส่ง Tier 2 ตรวจสอบ'
        if next_status == Ticket.STATUS_AWAITING_OWNER:
            # No OWNER_REMEDIATED branch: that edge is gone. Sending a case
            # back to the owner is Tier 2's call, made at PENDING_T2_REVIEW.
            if ticket.status == Ticket.STATUS_PENDING_T2_REVIEW:
                label = 'ตีกลับ → ส่งคืนเจ้าของระบบ'
            else:
                label = 'ส่งให้เจ้าของระบบ (โดยตรง)'
        actions.append({'status': next_status, 'label': label})
    return actions


def _notify_containment(ticket, reason, request):
    if not ticket.assigned_admin_id:
        messages.warning(request, 'Ticket routed — ไม่สามารถส่งอีเมลแจ้งเตือนได้: ยังไม่ได้กำหนดผู้ดูแลระบบ')
        return
    admin = ticket.assigned_admin
    if not admin.email:
        messages.warning(request, f'Ticket routed — {admin.get_full_name() or admin.username} ไม่มีอีเมล')
        return
    if not notify_containment_alert(ticket, reason=reason):
        messages.warning(request, 'Ticket routed แต่ส่งอีเมลแจ้งเตือนไม่สำเร็จ — โปรดแจ้งผู้ดูแลระบบด้วยตนเอง')


# ── Ticket views ─────────────────────────────────────────────────────── #

def _int_param(value):
    """A positive integer id from a query/form value, or None.

    Filtering pk= on a non-numeric string raises ValueError inside the ORM,
    which surfaced as a 500 for a hand-edited URL or a stale form. Callers treat
    None exactly like "no such row".
    """
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _alert_bundle_ids(request):
    """Return distinct selected Wazuh alert ids, preserving form order."""
    values = request.POST.getlist('alert_bundle') or request.GET.getlist('alert_bundle')
    ids = []
    for value in values:
        try:
            alert_id = int(value)
        except (TypeError, ValueError):
            continue
        if alert_id > 0 and alert_id not in ids:
            ids.append(alert_id)
    return ids


def _parse_date_param(value):
    """A YYYY-MM-DD query value as a date, or None when blank or malformed."""
    try:
        return parse_date(value) if value else None
    except ValueError:  # well-formed but impossible, e.g. 2026-02-31
        return None


def _date_range_params(params):
    """The start_date/end_date query pair as (start_str, end_str, start, end).

    `params` is the query (request.GET, or the page's querystring re-posted by
    the bulk report export). A hand-edited or truncated date must not 500 the
    page: an unparseable value is treated as absent, and its string is blanked
    so the form doesn't echo it.
    """
    start_str = params.get('start_date', '').strip()
    end_str = params.get('end_date', '').strip()
    start = _parse_date_param(start_str)
    end = _parse_date_param(end_str)
    return (start_str if start else '', end_str if end else '', start, end)


def _apply_date_range(qs, field, start, end):
    """Bound a queryset by a local-date range on `field`; either side optional."""
    if start:
        qs = qs.filter(**{f'{field}__date__gte': start})
    if end:
        qs = qs.filter(**{f'{field}__date__lte': end})
    return qs


def _date_presets(start_str, end_str):
    """One-click local-date ranges for the list toolbars.

    'เดือนนี้' runs to the last day of the month, not today, so it matches the
    Ticket History default and shows as active there.
    """
    today = timezone.localdate()
    month_end = today.replace(day=calendar.monthrange(today.year, today.month)[1])
    ranges = (
        ('วันนี้', today, today),
        ('7 วัน', today - timedelta(days=6), today),
        ('30 วัน', today - timedelta(days=29), today),
        ('เดือนนี้', today.replace(day=1), month_end),
    )
    presets = []
    for label, start, end in ranges:
        start_iso, end_iso = start.isoformat(), end.isoformat()
        presets.append({
            'label': label, 'start': start_iso, 'end': end_iso,
            'active': start_str == start_iso and end_str == end_iso,
        })
    return presets


def _date_range_label(start_str, end_str, presets):
    """What the date-range button says: the preset's name, else the dates."""
    for preset in presets:
        if preset['active']:
            return preset['label']
    start = _parse_date_param(start_str)
    end = _parse_date_param(end_str)
    if start and end:
        return f'{start:%d/%m/%Y} – {end:%d/%m/%Y}'
    if start:
        return f'ตั้งแต่ {start:%d/%m/%Y}'
    if end:
        return f'ถึง {end:%d/%m/%Y}'
    return ''


def _filter_chip(request, label, keys, *, set_params=None, is_default=False):
    """One removable "active filter" chip for the list toolbars.

    remove_url is the current query minus `keys` (and the page number), plus
    `set_params` — History removes its date range by switching to all_time.
    A default chip (History's current month) is shown muted and doesn't count
    towards "clear all".
    """
    params = request.GET.copy()
    for key in (*keys, 'page'):
        params.pop(key, None)
    for key, value in (set_params or {}).items():
        params[key] = value
    query = params.urlencode()
    return {
        'label': label,
        'remove_url': f'{request.path}?{query}' if query else request.path,
        'is_default': is_default,
    }


# ── Column sorting (Active Tickets / Manager Queue / Ticket History) ── #
# Server-side because the lists are paginated: a browser-side sort would only
# reorder the 25 rows on screen. Mirrors the Wazuh triage queue's headers
# (apps.wazuh_ingest.views._sort_headers). The expressions below sort by what
# the cell SHOWS, not the raw column: Thai choice labels, the display-name
# fallback, a person's full name, the workflow order of statuses.

def _choice_label_expr(field_name, model=Ticket):
    """A field's choice LABEL (what the cell shows) as an orderable expression."""
    field = model._meta.get_field(field_name)
    return Case(
        *[When(**{field_name: code}, then=Value(str(label))) for code, label in field.flatchoices],
        default=F(field_name), output_field=CharField(),
    )


def _ticket_name_expr():
    """Ticket.display_name in SQL: incident_name, else the sub-category label."""
    return Lower(Coalesce(
        NullIf(Trim('incident_name'), Value('')),
        _choice_label_expr('detailed_issue2'),
        output_field=CharField(),
    ))


def _choice_order_expr(field_name, model=Ticket):
    """A choice field in its DECLARED order (e.g. workflow order), not by code."""
    choices = model._meta.get_field(field_name).flatchoices
    return Case(
        *[When(**{field_name: code}, then=Value(index))
          for index, (code, _) in enumerate(choices)],
        default=Value(len(choices)), output_field=IntegerField(),
    )


def _status_order_expr():
    """Ticket statuses in workflow order (STATUS_CHOICES), not alphabetical codes."""
    return _choice_order_expr('status')


def _person_name_expr(prefix=''):
    """get_full_name|default:username in SQL; NULL when there is no user."""
    full_name = Trim(Concat(
        F(f'{prefix}first_name'), Value(' '), F(f'{prefix}last_name'),
        output_field=CharField(),
    ))
    return Lower(Coalesce(
        NullIf(full_name, Value('')), F(f'{prefix}username'), output_field=CharField(),
    ))


def _by(expression, descending=False):
    """Order by an expression with blanks last in BOTH directions, so rows
    missing the value never push real rows off the first page."""
    if descending:
        return expression.desc(nulls_last=True)
    return expression.asc(nulls_last=True)


def _column_sort_headers(columns, current_sort, *, request=None, param='sort',
                         page_param='page', extra_params=None):
    """Header cells for a list table, each carrying the sort it links to.

    columns: (label, first_key, second_key, first_is_ascending, th_class);
    first_key None = not sortable. Clicking a header applies its first sort —
    the most useful direction for that column — and clicking the active one
    flips it. `direction` is the VISUAL direction for aria-sort and the caret
    (e.g. '-id', newest first, is descending). Built here rather than in the
    template so the arrow shown and the link followed cannot disagree.

    A page with ONE sortable table leaves `request` out: the header partial
    builds `?sort=…` with {% querystring %}. A page with several tables (IOC
    search, My Queue's tabs) passes `request` plus its own `param` /
    `page_param`, and `extra_params` (e.g. {'tab': 'manual'}), and each header
    gets a ready `href` — {% querystring %} can't take a variable key.
    """
    def _href(next_sort):
        if request is None:
            return ''
        query = request.GET.copy()
        query[param] = next_sort
        query.pop(page_param, None)
        for key, value in (extra_params or {}).items():
            query[key] = value
        return '?' + query.urlencode()

    headers = []
    for label, first_key, second_key, first_is_ascending, th_class in columns:
        if first_key is None:
            headers.append({'label': label, 'sortable': False, 'th_class': th_class})
            continue
        first_direction = 'asc' if first_is_ascending else 'desc'
        second_direction = 'desc' if first_is_ascending else 'asc'
        if current_sort == first_key:
            next_sort, direction = second_key, first_direction
        elif current_sort == second_key:
            next_sort, direction = first_key, second_direction
        else:
            next_sort, direction = first_key, None
        headers.append({
            'label': label, 'sortable': True, 'th_class': th_class,
            'next_sort': next_sort, 'direction': direction,
            'href': _href(next_sort),
        })
    return headers


# Active Tickets / Manager Queue table columns, in cell order.
ACTIVE_LIST_COLUMNS = (
    ('เลขที่เคส', '-id', 'id', False, 'ps-4'),
    ('ชื่อเรื่อง', 'name', '-name', True, ''),
    ('ความรุนแรง', 'severity', 'severity_asc', False, ''),
    ('ประเภท', 'classification', '-classification', True, ''),
    ('OLA', 'ola', '-ola', True, ''),
    ('แหล่งที่มา', 'source', '-source', True, ''),
    ('ผู้ดูแลระบบ', 'admin', '-admin', True, ''),
    ('Tier 1 ผู้รับเรื่อง', 'creator', '-creator', True, ''),
    ('วันที่แจ้ง', 'newest', 'oldest', False, ''),
    ('สถานะ', 'status', '-status', True, ''),
    ('', None, None, True, ''),
)
# What the results-bar dropdown offers. Any other key came from a header, and
# the dropdown says so ("ตามคอลัมน์ในตาราง") instead of showing a wrong option.
ACTIVE_LIST_SORT_OPTIONS = (
    ('ola', 'OLA ใกล้ครบกำหนด'),
    ('emergency', 'Emergency ก่อน'),
    ('severity', 'ความรุนแรง'),
    ('newest', 'ใหม่สุดก่อน'),
    ('oldest', 'เก่าสุดก่อน'),
)


def _ticket_search_q(term):
    """Free-text ticket search shared by Active Tickets and Ticket History."""
    return (
        Q(ticket_id__icontains=term)
        # The lists lead with the case NAME, so it has to be searchable by it —
        # otherwise the one string on screen is the one you cannot type.
        | Q(incident_name__icontains=term)
        | Q(device_name__icontains=term)
        | Q(ip_address__icontains=term)
        | Q(issue_description__icontains=term)
        | Q(destination_ip__icontains=term)
    )


# Bulk PDF export (Active Tickets + History). Each report renders synchronously
# (a few seconds with evidence images) and the export streams, so this caps how
# long one request can hold a worker thread.
BULK_REPORT_LIMIT = 100


def _bulk_export_context(request, export_url):
    """Context for the results bar's bulk-export control; export_url '' = none.

    Only for the SOC Manager and Tier 2 (policies.can_bulk_export_ticket_reports
    — narrower than the single export, which all SOC staff have). The page's
    querystring, minus the page number, is posted back so the export rebuilds
    exactly the filtered, sorted list on screen.
    """
    if not export_url or not _can_bulk_export_ticket_reports(request.user):
        return {'export_url': ''}
    query = request.GET.copy()
    query.pop('page', None)
    return {
        'export_url': export_url,
        'export_query': query.urlencode(),
        'bulk_report_limit': BULK_REPORT_LIMIT,
    }


def _filter_open_tickets(request, params, visible, *, is_manager_queue=False,
                         date_filter=False):
    """The non-terminal ticket list, filtered and sorted from `params`.

    Shared by the page (params = request.GET) and the bulk report export
    (params = the page's querystring, re-posted), so the ZIP holds exactly the
    tickets the page shows. Returns a namespace: `qs` plus the validated filter
    state the page renders. date_filter adds the วันที่แจ้ง (created_at) range;
    the Manager Queue doesn't get it.
    """
    tickets_qs = visible.exclude(
        status__in=list(Ticket.TERMINAL_STATUSES)
    ).select_related('assigned_admin', 'created_by', 'project_incident')

    # A return from Tier 2 lands back in the same AWAITING_CONTAINMENT state as
    # a first assignment. Preserve that intentionally simple workflow state,
    # but annotate the System Admin's queue from its audit trail so rework is
    # impossible to mistake for brand-new work. The annotation avoids one log
    # query per queue row and also works for tickets returned before this UI
    # signal existed.
    profile = getattr(request.user, 'profile', None)
    is_system_admin_viewer = (
        not request.user.is_superuser
        and profile is not None
        and profile.is_system_admin
    )
    if is_system_admin_viewer:
        tickets_qs = tickets_qs.annotate(
            is_returned_to_admin=Exists(
                TicketLog.objects.filter(
                    ticket_id=OuterRef('pk'),
                    status_at_time=Ticket.STATUS_CONTAINMENT_REPORTED,
                )
            )
        )

    search = params.get('q', '').strip()
    status_filter = params.get('status', '').strip()
    severity_filter = params.get('severity', '').strip()
    classification_filter = params.get('classification', '').strip()
    emergency_filter = params.get('emergency', '').strip()
    sort = params.get('sort', 'ola').strip()

    if search:
        tickets_qs = tickets_qs.filter(_ticket_search_q(search))

    # No range by default: an open case must never drop out of the work queue
    # just because it is old. The range only narrows when the user sets one.
    start_date = end_date = ''
    if date_filter:
        start_date, end_date, start_obj, end_obj = _date_range_params(params)
        tickets_qs = _apply_date_range(tickets_qs, 'created_at', start_obj, end_obj)

    active_status_choices = [
        (code, label) for code, label in Ticket.STATUS_CHOICES
        if code not in Ticket.TERMINAL_STATUSES
    ]
    if is_manager_queue:
        active_status_choices = [
            (code, label) for code, label in active_status_choices
            if code in Ticket.MANAGER_QUEUE_STATUSES
        ]
    if status_filter in dict(active_status_choices):
        tickets_qs = tickets_qs.filter(status=status_filter)
    else:
        status_filter = ''

    if severity_filter in dict(Ticket.SEVERITY_CHOICES):
        tickets_qs = tickets_qs.filter(severity=severity_filter)
    else:
        severity_filter = ''

    if classification_filter in dict(Ticket.CLASSIFICATION_CHOICES):
        tickets_qs = tickets_qs.filter(classification=classification_filter)
    else:
        classification_filter = ''

    if emergency_filter in ('1', '0'):
        tickets_qs = tickets_qs.filter(is_emergency=emergency_filter == '1')
    else:
        emergency_filter = ''

    # OLA-pressure bucket filter — shares thresholds with the dashboard chart
    # (apps.incidents.ola) so the dashboard's "Overdue/Due ≤1h/…" bars can
    # deep-link straight to the matching slice of this list.
    ola_filter = params.get('ola', '').strip()
    if ola_filter in ola_buckets.BUCKET_KEYS:
        tickets_qs = tickets_qs.filter(
            ola_buckets.bucket_filter(ola_filter, timezone.now()))
    else:
        ola_filter = ''

    # Every ordering ends on the OLA deadline then -pk, so ties stay in a
    # stable, work-ordered sequence across pages.
    ola_first = _by(F('ola_contain_deadline'))
    tie = (ola_first, '-pk')
    sort_map = {
        # Dropdown presets (their keys predate the headers; links rely on them).
        'ola':       (ola_first, '-pk'),
        'emergency': ('-is_emergency', *tie),
        'newest':    ('-created_at', '-pk'),
        'oldest':    ('created_at', 'pk'),
        # -sev_rank, NOT 'severity': the raw CharField sorts alphabetically,
        # which ranks Low above Medium. See TicketQuerySet.with_severity_rank,
        # which the Tier 2 queue already uses for the same reason.
        'severity':  ('-sev_rank', *tie),
        # Column headers (ACTIVE_LIST_COLUMNS).
        '-id': ('-ticket_id', '-pk'),
        'id': ('ticket_id', 'pk'),
        'name': (_by(_ticket_name_expr()), *tie),
        '-name': (_by(_ticket_name_expr(), descending=True), *tie),
        'severity_asc': ('sev_rank', *tie),
        'classification': (_by(_choice_label_expr('classification')), *tie),
        '-classification': (_by(_choice_label_expr('classification'), descending=True), *tie),
        '-ola': (_by(F('ola_contain_deadline'), descending=True), '-pk'),
        'source': (_by(F('issue_type')), *tie),
        '-source': (_by(F('issue_type'), descending=True), *tie),
        'admin': (_by(_person_name_expr('assigned_admin__')), *tie),
        '-admin': (_by(_person_name_expr('assigned_admin__'), descending=True), *tie),
        'creator': (_by(_person_name_expr('created_by__')), *tie),
        '-creator': (_by(_person_name_expr('created_by__'), descending=True), *tie),
        'status': (_status_order_expr(), *tie),
        '-status': (_status_order_expr().desc(), *tie),
    }
    if is_system_admin_viewer:
        # The OLA deadline remains the primary work-ordering rule. Within the
        # same urgency band, returned work comes first because it already had a
        # failed verification pass and needs a concrete correction.
        sort_map['ola'] = (
            'ola_contain_deadline', '-is_returned_to_admin', '-status_changed_at',
        )
    if sort not in sort_map:
        sort = 'ola'
    if sort in ('severity', 'severity_asc'):
        tickets_qs = tickets_qs.with_severity_rank()
    tickets_qs = tickets_qs.order_by(*sort_map[sort])

    return SimpleNamespace(
        qs=tickets_qs, search=search, status_filter=status_filter,
        severity_filter=severity_filter, classification_filter=classification_filter,
        emergency_filter=emergency_filter, ola_filter=ola_filter, sort=sort,
        start_date=start_date, end_date=end_date,
        active_status_choices=active_status_choices,
        is_system_admin_viewer=is_system_admin_viewer,
    )


def _render_ticket_list(request, visible, *, page_title, heading, description,
                        is_manager_queue=False, date_filter=False, export_url=''):
    """Render a filtered, non-terminal ticket list with shared list controls.

    date_filter adds the วันที่แจ้ง (created_at) range + quick presets. Off by
    default: the Manager Queue shares this renderer and doesn't get it. Nor does
    it get export_url — the bulk PDF export is Active Tickets + History only.
    """
    f = _filter_open_tickets(request, request.GET, visible,
                             is_manager_queue=is_manager_queue, date_filter=date_filter)
    tickets_qs = f.qs
    search, status_filter, severity_filter = f.search, f.status_filter, f.severity_filter
    classification_filter, emergency_filter = f.classification_filter, f.emergency_filter
    ola_filter, sort = f.ola_filter, f.sort
    start_date, end_date = f.start_date, f.end_date
    active_status_choices = f.active_status_choices
    is_system_admin_viewer = f.is_system_admin_viewer

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    open_tickets = visible.exclude(status__in=list(Ticket.TERMINAL_STATUSES))
    # Live OLA breach: active ticket already past its contain/resolve deadline
    # (vs now()). Medium/Low have no contain deadline, so they never count here.
    ola_breach_count = open_tickets.filter(
        ola_contain_deadline__lt=timezone.now()
    ).count()

    date_presets = _date_presets(start_date, end_date) if date_filter else []
    date_label = _date_range_label(start_date, end_date, date_presets)
    ola_labels = {code: label for code, label, _ in ola_buckets.OLA_BUCKETS}
    # One chip per active filter, so a narrowed queue never passes for the whole
    # queue. Order follows the toolbar.
    filter_chips = []
    if search:
        filter_chips.append(_filter_chip(request, f'ค้นหา: “{search}”', ('q',)))
    if status_filter:
        filter_chips.append(_filter_chip(
            request, f'สถานะ: {dict(active_status_choices)[status_filter]}', ('status',)))
    if severity_filter:
        filter_chips.append(_filter_chip(
            request, f'ความรุนแรง: {dict(Ticket.SEVERITY_CHOICES)[severity_filter]}', ('severity',)))
    if date_label:
        filter_chips.append(_filter_chip(
            request, f'วันที่แจ้ง: {date_label}', ('start_date', 'end_date')))
    if classification_filter:
        filter_chips.append(_filter_chip(
            request, f'ประเภท: {dict(Ticket.CLASSIFICATION_CHOICES)[classification_filter]}',
            ('classification',)))
    if emergency_filter:
        filter_chips.append(_filter_chip(
            request, 'เฉพาะเคสฉุกเฉิน' if emergency_filter == '1' else 'เฉพาะเคสปกติ',
            ('emergency',)))
    if ola_filter:
        filter_chips.append(_filter_chip(request, f'OLA: {ola_labels[ola_filter]}', ('ola',)))

    return render(request, 'incidents/ticket_list.html', {
        'page_title': page_title,
        'heading': heading,
        'description': description,
        'is_manager_queue': is_manager_queue,
        'pending_cancellations': (
            TicketCancellationRequest.objects.filter(status='PENDING', ticket__in=Ticket.objects.visible_to(request.user))
            .select_related('ticket', 'requested_by').order_by('requested_at')
            if is_manager_queue else []
        ),
        'show_returned_to_admin_indicator': is_system_admin_viewer,
        'tickets': page_obj,
        'page_obj': page_obj,
        'result_count': paginator.count,
        'result_total': open_tickets.count(),
        'ola_breach_count': ola_breach_count,
        **_bulk_export_context(request, export_url),
        'filter_chips': filter_chips,
        'has_clearable_filters': bool(filter_chips),
        'more_filter_count': sum(bool(value) for value in (
            classification_filter, emergency_filter, ola_filter)),
        'sort_options': ACTIVE_LIST_SORT_OPTIONS,
        'sort_headers': _column_sort_headers(ACTIVE_LIST_COLUMNS, sort),
        'sort_is_from_column': sort not in dict(ACTIVE_LIST_SORT_OPTIONS),
        'search': search,
        'status_filter': status_filter,
        'severity_filter': severity_filter,
        'classification_filter': classification_filter,
        'emergency_filter': emergency_filter,
        'ola_filter': ola_filter,
        'date_filter_enabled': date_filter,
        'start_date': start_date,
        'end_date': end_date,
        'date_presets': date_presets,
        'date_label': date_label,
        'date_is_empty': not start_date and not end_date,
        'date_is_set': bool(date_label),
        'sort': sort,
        'active_status_choices': active_status_choices,
        'severity_choices': Ticket.SEVERITY_CHOICES,
        'classification_choices': Ticket.CLASSIFICATION_CHOICES,
        'ola_bucket_choices': ola_buckets.OLA_BUCKETS,
    })
