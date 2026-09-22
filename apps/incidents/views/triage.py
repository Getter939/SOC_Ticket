import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import F, Q
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone

from ..forms import (
    TriageForm,
)
from ..models import (
    Ticket,
    TriageRecord,
)

logger = logging.getLogger('apps.incidents.views')



# ── Triage views ─────────────────────────────────────────────────────── #

@login_required
def triage_list(request):
    """Tier 1's single work queue ("My Queue" / คิวงานของฉัน).

    Sections on one page, in render order:
      1. The analyst's own-court tickets (TIER1_QUEUE_STATUSES, created by
         them) — including a preparation the SOC Manager returned (NEW with
         first_submitted_at set), where only the creator may act.
         Alongside it, a passive "changed by Tier 2" list: tickets the analyst
         opened whose content a Tier 2 analyst has edited since they last
         looked. Informational only — not part of the needs-action counts.
      2. Manual-intake reports awaiting triage (TriageRecord) — the former
         Manual Triage page, with the same claim / convert / release /
         dismiss actions.
      3. The analyst's own recent dispositions. This is the only trail a
         DISMISSED report leaves: dismiss_manual_triage stamps decision=FP
         with no ticket, so the record surfaces in no ticket list and no
         dashboard.

    Keeps the historical `triage_list` URL name: every redirect and deep link
    from the manual-triage flow lands here, where the manual queue still lives.
    """
    profile = getattr(request.user, 'profile', None)
    if not request.user.is_superuser and (profile is None or not profile.is_tier1):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่เข้าถึงหน้านี้ได้')
        return redirect('home')

    # Which tab opens. The manual-triage actions redirect back with
    # ?tab=manual so a claim/release/dismiss doesn't bounce the analyst out of
    # the queue they were working in.
    active_tab = request.GET.get('tab', 'tickets')
    if active_tab not in ('tickets', 'monitoring', 't2changes', 'manual', 'history'):
        active_tab = 'tickets'

    queue = TriageRecord.objects.filter(decision='', ticket__isnull=True).select_related(
        'analyst', 'claimed_by',
    ).order_by('-created_at')
    # Scoped to this analyst: on a page called "my queue" a global log of every
    # analyst's records is not actionable, and IOC Search already covers the
    # full history with real filtering. What this needs to show is a trail of
    # what YOU just did — above all a dismissal, which leaves no ticket behind.
    history = TriageRecord.objects.filter(
        resolved_by=request.user,
    ).select_related('ticket').order_by('-resolved_at')[:10]

    # Own-court tickets. Monitoring cases are split into their own tab — a case
    # on a 30-day watch is not "awaiting action" like the rest, so mixing it into
    # the action queue would just add noise — so the main tab excludes them and
    # the monitoring tab lists only them, soonest-to-expire (and overdue) first.
    own_court = (
        Ticket.objects.filter(
            created_by=request.user, status__in=Ticket.TIER1_QUEUE_STATUSES,
        )
        .select_related('assigned_admin')
    )
    my_tickets = own_court.exclude(status=Ticket.STATUS_MONITORING).order_by(
        F('ola_contain_deadline').asc(nulls_last=True),
        '-status_changed_at',
    )
    monitoring_tickets = own_court.filter(status=Ticket.STATUS_MONITORING).order_by(
        F('monitor_until').asc(nulls_last=True),
    )
    # Counted before paging — these drive the tab badges and the alerts, which
    # describe the whole queue, not the page being viewed.
    my_tickets_total = my_tickets.count()
    returned_count = my_tickets.filter(
        status=Ticket.STATUS_NEW, first_submitted_at__isnull=False,
    ).count()
    # Passive "changed by Tier 2" marker (Ticket.has_unseen_t2_changes), across
    # every ticket this analyst opened, whatever its current stage. Opening the
    # ticket clears it (ticket_detail stamps creator_seen_at).
    t2_changed_tickets = (
        Ticket.objects.filter(created_by=request.user, t2_changed_at__isnull=False)
        .filter(Q(creator_seen_at__isnull=True) | Q(t2_changed_at__gt=F('creator_seen_at')))
        .order_by('-t2_changed_at')
    )
    t2_changed_count = t2_changed_tickets.count()
    monitoring_count = monitoring_tickets.count()
    monitoring_overdue_count = monitoring_tickets.filter(
        monitor_until__lte=timezone.now(),
    ).count()
    # This page was the only queue in the app without a Paginator; an unbounded
    # ticket table is what pushed the manual-intake queue below the fold.
    page_obj = Paginator(my_tickets, 10).get_page(request.GET.get('page'))

    return render(request, 'incidents/my_queue.html', {
        'manual_queue': queue,
        'manual_history': history,
        'my_tickets': page_obj,
        'page_obj': page_obj,
        'my_tickets_total': my_tickets_total,
        'monitoring_tickets': monitoring_tickets,
        'monitoring_count': monitoring_count,
        'monitoring_overdue_count': monitoring_overdue_count,
        # Actionable count, matching the sidebar badge's rule exactly
        # (wazuh_ingest.context_processors.pending_triage_count): reports this
        # analyst can pick up or already holds. The table below still lists a
        # peer's claimed rows for shift awareness, but a badge is a call to
        # action — counting another analyst's work would make the nav badge
        # and this one disagree about the same queue.
        'manual_queue_count': queue.filter(
            Q(claimed_by__isnull=True) | Q(claimed_by=request.user)
        ).count(),
        'manual_history_count': len(history),
        'returned_count': returned_count,
        't2_changed_tickets': t2_changed_tickets[:50],
        't2_changed_count': t2_changed_count,
        'active_tab': active_tab,
    })


@login_required
def create_triage(request):
    profile = getattr(request.user, 'profile', None)
    # Route through is_tier1 (not raw role/tier) so it tracks a manager's
    # temporary acting-tier grant like every other Tier-1 gate.
    if not request.user.is_superuser and (profile is None or not profile.is_tier1):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถ Triage ได้')
        return redirect('home')

    if request.method == 'POST':
        form = TriageForm(request.POST)
        if form.is_valid():
            triage = form.save(commit=False)
            triage.analyst = request.user
            triage.save()

            messages.success(request, 'เพิ่มรายการ Manual Triage เข้าคิวแล้ว')
            return _manual_queue_redirect()
    else:
        form = TriageForm()

    return render(request, 'incidents/triage_form.html', {'form': form})


def _manual_queue_redirect():
    """Back to My Queue with the manual-intake tab open.

    Every action below belongs to that tab, so landing on the default
    (tickets) tab afterwards would lose the analyst's place mid-triage.
    """
    return redirect(f"{reverse('triage_list')}?tab=manual")


@login_required
def claim_manual_triage(request, triage_id):
    profile = getattr(request.user, 'profile', None)
    if request.method != 'POST' or (
        not request.user.is_superuser and (profile is None or not profile.is_tier1)
    ):
        return _manual_queue_redirect()
    updated = TriageRecord.objects.filter(
        pk=triage_id, decision='', ticket__isnull=True, claimed_by__isnull=True,
    ).update(claimed_by=request.user, claimed_at=timezone.now())
    if not updated:
        messages.error(request, 'รายการนี้ถูกผู้อื่นรับไปแล้วหรือดำเนินการเสร็จแล้ว')
    return _manual_queue_redirect()


@login_required
def release_manual_triage(request, triage_id):
    profile = getattr(request.user, 'profile', None)
    if request.method != 'POST' or (
        not request.user.is_superuser and (profile is None or not profile.is_tier1)
    ):
        return _manual_queue_redirect()
    reason = request.POST.get('release_reason', '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการคืนรายการกลับเข้าคิว')
        return _manual_queue_redirect()
    releasable = TriageRecord.objects.filter(
        pk=triage_id, decision='', ticket__isnull=True, claimed_by=request.user,
    )
    if request.user.is_superuser:
        releasable = TriageRecord.objects.filter(
            pk=triage_id, decision='', ticket__isnull=True,
        )
    updated = releasable.update(
        claimed_by=None, claimed_at=None, release_reason=reason,
    )
    if not updated:
        messages.error(request, 'รายการนี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
    return _manual_queue_redirect()


@login_required
def dismiss_manual_triage(request, triage_id):
    """Close a manual-intake report as junk — no ticket.

    The disposal path the queue lacked: previously the claimer's only options
    were convert-to-ticket or release-back, so a prank call either became a
    full Event ticket (with a Tier 2 confirm) or sat in the queue forever.

    Stamps the existing decision=FP with a required reason (appended to the
    record's notes for the audit trail). A dismissed record leaves the queue
    via the history filter, and _can_create_ticket_from_triage already rejects
    FP-without-ticket records, so it cannot be converted afterwards.
    """
    profile = getattr(request.user, 'profile', None)
    if request.method != 'POST' or (
        not request.user.is_superuser and (profile is None or not profile.is_tier1)
    ):
        return _manual_queue_redirect()

    reason = request.POST.get('dismiss_reason', '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการปิดรายการโดยไม่เปิดเคส')
        return _manual_queue_redirect()

    # Claimer-only, like release — dismissal is a triage decision, so it
    # belongs to whoever holds the item. Superuser may clear any pending row.
    dismissable = TriageRecord.objects.filter(
        pk=triage_id, decision='', ticket__isnull=True, claimed_by=request.user,
    )
    if request.user.is_superuser:
        dismissable = TriageRecord.objects.filter(
            pk=triage_id, decision='', ticket__isnull=True,
        )
    triage = dismissable.first()
    if triage is None:
        messages.error(request, 'รายการนี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
        return _manual_queue_redirect()

    triage.decision = TriageRecord.DECISION_FP
    note = f'ปิดโดยไม่เปิดเคส: {reason}'
    triage.notes = f'{triage.notes}\n{note}' if triage.notes else note
    triage.resolved_by = request.user
    triage.resolved_at = timezone.now()
    triage.claimed_by = None
    triage.claimed_at = None
    triage.save(update_fields=[
        'decision', 'notes', 'resolved_by', 'resolved_at',
        'claimed_by', 'claimed_at',
    ])

    messages.success(request, 'ปิดรายการโดยไม่เปิดเคสแล้ว')
    return _manual_queue_redirect()
