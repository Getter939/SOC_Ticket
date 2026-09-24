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

from ..models import Ticket, TicketLog
from ..ticket_workflow import claim_tier2_ticket
from ._helpers import _int_param


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
    base_qs = Ticket.objects.visible_to(request.user).filter(
        status__in=Ticket.TIER2_QUEUE_STATUSES)

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
    sort_map = {
        'emergency': ('-is_emergency', '-status_changed_at'),
        # Nulls last: Medium/Low have no contain deadline, so they belong below
        # everything that is actually on a clock.
        'ola': (F('ola_contain_deadline').asc(nulls_last=True), '-status_changed_at'),
        'newest': ('-status_changed_at',),
        # -sev_rank, NOT 'severity': the raw CharField sorts alphabetically,
        # which ranks Low above Medium. See TicketQuerySet.with_severity_rank.
        'severity': ('-sev_rank', '-status_changed_at'),
    }
    if sort not in sort_map:
        sort = 'emergency'
    tickets_qs = tickets_qs.order_by(*sort_map[sort])

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

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
    })
