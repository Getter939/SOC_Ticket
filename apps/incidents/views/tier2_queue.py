"""The Tier 2 work queue ("คิวงาน Tier 2").

Lived in ``apps/wazuh_ingest/views.py`` until 2026-09-23. It was written there
in June 2026 as a sibling of the Wazuh alert triage queue, back when escalation
was an alert-level concept; the alert-level design was dropped and these views
became pure ticket code (see docs/handover/engineering-handover.md §3.7). The
URL *names* are unchanged — ``escalation_queue`` / ``claim_escalation`` /
``release_escalation`` — so every ``reverse()`` and ``{% url %}`` still resolves.
"""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, F
from django.shortcuts import redirect, render
from django.utils import timezone

from apps.incidents import ola as ola_buckets
from ..models import Ticket, TicketLog
from ..ticket_workflow import claim_tier2_ticket
from ._helpers import (
    _by,
    _choice_label_expr,
    _column_sort_headers,
    _filter_chip,
    _int_param,
    _person_name_expr,
    _status_order_expr,
    _ticket_name_expr,
    _ticket_search_q,
)


# Table columns in cell order: (label, first-click sort, second-click sort,
# first click ascending?, th class) — see _helpers._column_sort_headers.
# รอมานาน's first click is the LONGEST wait (oldest status_changed_at), shown as
# descending because the cell displays the age.
TIER2_COLUMNS = (
    ('เคส', '-id', 'id', False, ''),
    ('ขั้นตอน', 'stage', '-stage', True, ''),
    ('ความรุนแรง', 'severity', 'severity_asc', False, ''),
    ('ประเภท', 'classification', '-classification', True, ''),
    ('ชื่อเรื่อง', 'name', '-name', True, ''),
    ('OLA', 'ola', '-ola', True, ''),
    ('รอมานาน', 'waiting', 'newest', False, ''),
    ('ผู้รับเรื่อง', 'claimer', '-claimer', True, ''),
    ('ตรวจสอบ', None, None, True, 'text-end'),
)
TIER2_SORT_OPTIONS = (
    ('emergency', 'Emergency ก่อน'),
    ('ola', 'OLA ใกล้ครบกำหนด'),
    ('newest', 'เข้าคิวล่าสุด'),
    ('severity', 'ความรุนแรง'),
)


def _has_tier2_access(user):
    profile = getattr(user, 'profile', None)
    return user.is_superuser or (profile is not None and profile.is_tier2)


@login_required
def claim_escalation(request):
    """Take a ticket out of the shared Tier 2 queue.

    One conditional UPDATE (claim_tier2_ticket), so two analysts pressing the
    button at the same moment can't both win — the loser is told it is already
    claimed instead of silently sharing the case. Same service the Claim button
    on ticket detail uses.
    """
    if request.method != 'POST':
        return redirect('escalation_queue')

    if not _has_tier2_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 2 เท่านั้นที่สามารถรับ Ticket ได้')
        return redirect('escalation_queue')

    ticket = Ticket.objects.filter(pk=_int_param(request.POST.get('ticket_id'))).first()
    claimed = ticket is not None and claim_tier2_ticket(
        ticket=ticket, actor=request.user,
    ).claimed

    if not claimed:
        messages.error(request, 'Ticket นี้ถูกเจ้าหน้าที่คนอื่นรับไปแล้ว หรือไม่ได้อยู่ในคิว Tier 2')
    else:
        messages.success(request, 'คุณรับ Ticket นี้มาดำเนินการแล้ว')
    return redirect('escalation_queue')


@login_required
def release_escalation(request):
    """Hand a claimed ticket back to the Tier 2 queue.

    A reason is required, same as release_alert, and it is written to the
    ticket log at the current status — releasing is not a state transition, so
    it must not go through transition_to.
    """
    if request.method != 'POST':
        return redirect('escalation_queue')

    if not _has_tier2_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 2 เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('escalation_queue')

    reason = request.POST.get('release_reason', '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการคืน Ticket กลับเข้าคิว')
        return redirect('escalation_queue')

    ticket_pk = _int_param(request.POST.get('ticket_id'))
    with transaction.atomic():
        ticket = (
            Ticket.objects.select_for_update()
            .filter(pk=ticket_pk, t2_claimed_by=request.user)
            .first()
        )
        if ticket is None:
            messages.error(request, 'Ticket นี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
            return redirect('escalation_queue')
        ticket.t2_claimed_by = None
        ticket.t2_claimed_at = None
        ticket.save(update_fields=['t2_claimed_by', 't2_claimed_at'])
        TicketLog.objects.create(
            ticket=ticket,
            note=f'คืน Ticket กลับเข้าคิว Tier 2 — เหตุผล: {reason}',
            status_at_time=ticket.status,
            author=request.user,
        )

    messages.success(request, 'คืน Ticket กลับเข้าคิวพร้อมเหตุผลแล้ว')
    return redirect('escalation_queue')


@login_required
def escalation_queue(request):
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_tier2):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 2 เท่านั้นที่สามารถเข้าถึง Escalation Queue ได้')
        return redirect('ticket_list')

    claim_filter = request.GET.get('claim', '').strip()
    stage_filter = request.GET.get('stage', '').strip()
    sort = request.GET.get('sort', 'emergency').strip()
    search = request.GET.get('q', '').strip()
    severity_filter = request.GET.get('severity', '').strip()
    classification_filter = request.GET.get('classification', '').strip()
    ola_filter = request.GET.get('ola', '').strip()

    # The Tier 2 queue covers all three T2 stages: escalation triage plus the
    # two verification stages (admin containment / owner remediation).
    stage_map = {
        'escalated': Ticket.STATUS_ESCALATED_T2,
        'containment': Ticket.STATUS_CONTAINMENT_REPORTED,
        'owner': Ticket.STATUS_PENDING_T2_REVIEW,
    }
    if stage_filter not in stage_map:
        stage_filter = ''
    # Claim state — the discipline this whole page is built around. "Unclaimed"
    # is what an analyst can pick up; "mine" is what they are already holding.
    # Both claim fields reset on every transition (Ticket.transition_to), so this
    # tracks the current stage only. request.user is safe here: @login_required
    # and the Tier 2 gate above have both already run.
    #
    # Deliberately no "claimed by others" value — it is derivable, and the
    # ผู้รับเรื่อง column already names the holder.
    if claim_filter not in ('unclaimed', 'mine'):
        claim_filter = ''

    # visible_to, like every other ticket list: the Tier 2 gate above already
    # limits this page to is_tier2/superuser and visible_to returns everything
    # for is_soc, so this changes nothing today — it just stops the queue being
    # the one list that reads the table directly instead of the single
    # authoritative visibility rule.
    queue_qs = Ticket.objects.visible_to(request.user).filter(
        status__in=Ticket.TIER2_QUEUE_STATUSES)

    # Toolbar filters (same bar as Active Tickets / History). They narrow the
    # pills' counts too, so each pill still counts what clicking it would show.
    # Deliberately no emergency filter — see the template's note.
    base_qs = queue_qs
    if search:
        base_qs = base_qs.filter(_ticket_search_q(search))
    if severity_filter in dict(Ticket.SEVERITY_CHOICES):
        base_qs = base_qs.filter(severity=severity_filter)
    else:
        severity_filter = ''
    if classification_filter in dict(Ticket.CLASSIFICATION_CHOICES):
        base_qs = base_qs.filter(classification=classification_filter)
    else:
        classification_filter = ''
    if ola_filter in ola_buckets.BUCKET_KEYS:
        base_qs = base_qs.filter(ola_buckets.bucket_filter(ola_filter, timezone.now()))
    else:
        ola_filter = ''

    def _apply_stage(qs):
        return qs.filter(status=stage_map[stage_filter]) if stage_filter else qs

    def _apply_claim(qs):
        if claim_filter == 'unclaimed':
            return qs.filter(t2_claimed_by__isnull=True)
        if claim_filter == 'mine':
            return qs.filter(t2_claimed_by=request.user)
        return qs

    # Facet counts for the pill rows. Each pill counts what you would get by
    # clicking it — so a row is counted with the OTHER dimension's filter still
    # applied. This is the point of the pills: the stage split (how much is
    # escalation triage vs verification) was previously unknowable without
    # filtering three times and reading the header badge each time.
    stage_tally = dict(
        _apply_claim(base_qs).values_list('status')
        .annotate(n=Count('id')).values_list('status', 'n')
    )
    stage_facets = [
        {'key': None, 'label': 'ทั้งหมด',
         'count': sum(stage_tally.values()), 'active': not stage_filter},
    ] + [
        {'key': key, 'label': label,
         'count': stage_tally.get(stage_map[key], 0),
         'active': stage_filter == key}
        for key, label in (
            ('escalated', 'รอตรวจสอบ'),
            ('containment', 'ยืนยันการควบคุม (Admin)'),
            ('owner', 'ยืนยันการแก้ไข (Owner)'),
        )
    ]

    claim_scoped = _apply_stage(base_qs)
    claim_facets = [
        {'key': None, 'label': 'ทั้งหมด',
         'count': claim_scoped.count(), 'active': not claim_filter},
        {'key': 'unclaimed', 'label': 'ยังไม่มีผู้รับ',
         'count': claim_scoped.filter(t2_claimed_by__isnull=True).count(),
         'active': claim_filter == 'unclaimed'},
        {'key': 'mine', 'label': 'ที่ฉันรับไว้',
         'count': claim_scoped.filter(t2_claimed_by=request.user).count(),
         'active': claim_filter == 'mine'},
    ]

    tickets_qs = _apply_claim(_apply_stage(base_qs)).select_related(
        'created_by', 'assigned_admin', 't2_claimed_by',
        # bundle_ref dereferences project_incident — without this the bundle
        # indicator costs a query per row.
        'project_incident',
    ).with_severity_rank()
    # status_changed_at = when the ticket entered its current (queue) status —
    # meaningful for all three stages, unlike escalated_to_t2_at.
    #
    # Only the default sort floats emergencies. The other three are deliberately
    # left alone: `ola` answers "what breaches next", and an emergency with 4h of
    # slack outranking an already-overdue ticket would defeat that. The red row
    # tint and EMERGENCY badge carry the signal under every sort.
    tie = ('-status_changed_at', '-pk')
    sort_map = {
        # Dropdown presets.
        'emergency': ('-is_emergency', *tie),
        # Nulls last: Medium/Low have no contain deadline, so they belong below
        # everything that is actually on a clock.
        'ola': (F('ola_contain_deadline').asc(nulls_last=True), *tie),
        'newest': tie,
        # -sev_rank, NOT 'severity': the raw CharField sorts alphabetically,
        # which ranks Low above Medium. See TicketQuerySet.with_severity_rank.
        'severity': ('-sev_rank', *tie),
        # Column headers (TIER2_COLUMNS), sorting by what each cell shows.
        '-id': ('-ticket_id', '-pk'),
        'id': ('ticket_id', 'pk'),
        'stage': (_status_order_expr(), *tie),
        '-stage': (_status_order_expr().desc(), *tie),
        'severity_asc': ('sev_rank', *tie),
        'classification': (_by(_choice_label_expr('classification')), *tie),
        '-classification': (_by(_choice_label_expr('classification'), descending=True), *tie),
        'name': (_by(_ticket_name_expr()), *tie),
        '-name': (_by(_ticket_name_expr(), descending=True), *tie),
        '-ola': (F('ola_contain_deadline').desc(nulls_last=True), *tie),
        'waiting': ('status_changed_at', 'pk'),
        'claimer': (_by(_person_name_expr('t2_claimed_by__')), *tie),
        '-claimer': (_by(_person_name_expr('t2_claimed_by__'), descending=True), *tie),
    }
    if sort not in sort_map:
        sort = 'emergency'
    tickets_qs = tickets_qs.order_by(*sort_map[sort])

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    # Chips for the toolbar filters. Stage and claim are pills, which already
    # show what is selected, so they get none.
    ola_labels = {code: label for code, label, _ in ola_buckets.OLA_BUCKETS}
    filter_chips = []
    if search:
        filter_chips.append(_filter_chip(request, f'ค้นหา: “{search}”', ('q',)))
    if severity_filter:
        filter_chips.append(_filter_chip(
            request, f'ความรุนแรง: {dict(Ticket.SEVERITY_CHOICES)[severity_filter]}', ('severity',)))
    if classification_filter:
        filter_chips.append(_filter_chip(
            request, f'ประเภท: {dict(Ticket.CLASSIFICATION_CHOICES)[classification_filter]}',
            ('classification',)))
    if ola_filter:
        filter_chips.append(_filter_chip(request, f'OLA: {ola_labels[ola_filter]}', ('ola',)))

    return render(request, 'incidents/tier2_queue.html', {
        'page_obj': page_obj,
        'tickets': page_obj,
        # paginator.count is the same post-filter total the second count() query
        # produced, minus the query. Note this is the FILTERED count, unlike the
        # sidebar badge (wazuh_ingest/context_processors.py, which still owns
        # every nav count), which is unfiltered.
        'escalated_count': paginator.count,
        'claim_filter': claim_filter,
        'stage_filter': stage_filter,
        'stage_facets': stage_facets,
        'claim_facets': claim_facets,
        'sort': sort,
        'sort_options': TIER2_SORT_OPTIONS,
        'sort_headers': _column_sort_headers(TIER2_COLUMNS, sort),
        'sort_is_from_column': sort not in dict(TIER2_SORT_OPTIONS),
        # Results bar: "N เคส จาก M ในคิว" (M = the whole queue, unfiltered).
        'result_count': paginator.count,
        'result_total': queue_qs.count(),
        'search': search,
        'severity_filter': severity_filter,
        'classification_filter': classification_filter,
        'ola_filter': ola_filter,
        'severity_choices': Ticket.SEVERITY_CHOICES,
        'classification_choices': Ticket.CLASSIFICATION_CHOICES,
        'ola_bucket_choices': ola_buckets.OLA_BUCKETS,
        'filter_chips': filter_chips,
        'has_clearable_filters': bool(filter_chips or stage_filter or claim_filter),
    })
