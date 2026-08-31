from datetime import timedelta
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import CharField, Count, F, Q, TextField
from django.db.models.functions import Cast
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import Ticket, TicketLog
from .models import WazuhAlert

ESCALATE_TIER_CHOICES = dict(WazuhAlert.TIER_CHOICES)

# Triage no longer collects an incident category — the ticket form owns the
# threat taxonomy (Ticket.DETAILED_ISSUE_HIERARCHY), so the coarse alert-side
# mapping that used to pre-fill detailed_issue2 from it is gone. The
# WazuhAlert.incident_category column stays for the alerts that already carry
# a value; nothing writes it now.


def _severity_for_rule_level(rule_level):
    """Map a Wazuh rule.level to a Ticket severity choice."""
    if rule_level >= 13:
        return 'Critical'
    if rule_level >= 10:
        return 'High'
    if rule_level >= 7:
        return 'Medium'
    return 'Low'


def _user_tier(profile):
    """Return the WazuhAlert tier code this user receives escalations for, or None."""
    if profile.is_soc_manager:
        return WazuhAlert.TIER_MANAGER
    if profile.tier in (WazuhAlert.TIER_T1, WazuhAlert.TIER_T2):
        return profile.tier
    return None


def _has_soc_access(user):
    profile = getattr(user, 'profile', None)
    return user.is_superuser or (profile is not None and profile.is_soc)


def _has_tier1_access(user):
    """Triage (claim / create-ticket / release) is a Tier 1 activity."""
    profile = getattr(user, 'profile', None)
    return user.is_superuser or (profile is not None and profile.is_tier1)


def _allowed_escalation_tiers(profile, user=None):
    """Return only tiers higher than the current analyst's tier."""
    if user is not None and user.is_superuser:
        return list(WazuhAlert.TIER_CHOICES)
    tier = _user_tier(profile)
    if tier == WazuhAlert.TIER_T1:
        allowed = (WazuhAlert.TIER_T2, WazuhAlert.TIER_MANAGER)
    elif tier == WazuhAlert.TIER_T2:
        allowed = (WazuhAlert.TIER_MANAGER,)
    else:
        allowed = ()
    return [choice for choice in WazuhAlert.TIER_CHOICES if choice[0] in allowed]


@login_required
def triage_queue(request):
    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถเข้าถึง Triage Queue ได้')
        return redirect('ticket_list')

    queue = WazuhAlert.objects.filter(
        triage_status__in=[WazuhAlert.TRIAGE_PENDING, WazuhAlert.TRIAGE_TRIAGING],
    )
    queue_total = queue.count()

    # The queue opens on work this analyst can act on: alerts nobody has claimed
    # plus alerts they already hold. Other analysts' claims remain one click away
    # for team awareness, without pushing actionable work onto later pages.
    claim_filter = request.GET.get('claim', 'actionable').strip()
    if claim_filter not in ('actionable', 'unclaimed', 'mine', 'others', 'all'):
        claim_filter = 'actionable'

    ola_filter = request.GET.get('ola', '').strip()
    if ola_filter not in ('breached', 'due', 'on_track'):
        ola_filter = ''

    # These are disjoint Wazuh rule-level bands, not Ticket severity. Severity
    # belongs to a judged case and is selected on the ticket form.
    rule_level_filter = request.GET.get('rule_level_filter', '').strip()
    if rule_level_filter not in ('under12', '12', '15'):
        rule_level_filter = ''

    search_query = request.GET.get('q', '').strip()[:200]
    now = timezone.now()
    breached_before = now - timedelta(hours=WazuhAlert.OLA_HOURS)
    due_within_hour_before = now - timedelta(hours=WazuhAlert.OLA_HOURS - 1)
    ready_q = Q(
        triage_status=WazuhAlert.TRIAGE_PENDING,
        claimed_by__isnull=True,
    )
    mine_q = Q(
        triage_status=WazuhAlert.TRIAGE_TRIAGING,
        claimed_by=request.user,
    )

    def _apply_claim(qs, value=claim_filter):
        if value == 'actionable':
            return qs.filter(ready_q | mine_q)
        if value == 'unclaimed':
            return qs.filter(ready_q)
        if value == 'mine':
            return qs.filter(mine_q)
        if value == 'others':
            return qs.filter(
                triage_status=WazuhAlert.TRIAGE_TRIAGING,
                claimed_by__isnull=False,
            ).exclude(claimed_by=request.user)
        return qs

    def _apply_ola(qs):
        if ola_filter == 'breached':
            return qs.filter(timestamp__lt=breached_before)
        if ola_filter == 'due':
            return qs.filter(
                timestamp__gte=breached_before,
                timestamp__lte=due_within_hour_before,
            )
        if ola_filter == 'on_track':
            return qs.filter(timestamp__gt=due_within_hour_before)
        return qs

    def _apply_level(qs):
        if rule_level_filter == '15':
            return qs.filter(rule_level__gte=15)
        if rule_level_filter == '12':
            return qs.filter(rule_level__gte=12, rule_level__lt=15)
        if rule_level_filter == 'under12':
            return qs.filter(rule_level__lt=12)
        return qs

    def _apply_search(qs):
        if not search_query:
            return qs
        return qs.annotate(
            search_agent_ip=Cast('agent_ip', output_field=CharField()),
            search_mitre_ids=Cast('mitre_ids', output_field=TextField()),
        ).filter(
            Q(agent_name__icontains=search_query)
            | Q(search_agent_ip__icontains=search_query)
            | Q(rule_id__icontains=search_query)
            | Q(rule_description__icontains=search_query)
            | Q(alert_id__icontains=search_query)
            | Q(search_mitre_ids__icontains=search_query)
        )

    alerts = _apply_claim(_apply_ola(_apply_level(_apply_search(queue))))

    # ola_deadline is timestamp + a flat OLA_HOURS, so ordering by timestamp
    # ascending is the OLA order — no annotation needed.
    sort = request.GET.get('sort', 'ola').strip()
    if sort not in ('ola', 'level', 'newest'):
        sort = 'ola'
    sort_map = {
        'ola': ('timestamp', '-rule_level'),
        'level': ('-rule_level', 'timestamp'),
        'newest': ('-timestamp', '-rule_level'),
    }
    order = sort_map[sort]
    alerts = alerts.select_related('claimed_by').order_by(*order)

    paginator = Paginator(alerts, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    # Facets are cross-filtered: each count says what clicking that pill would
    # produce while retaining the other active dimensions and search text.
    claim_scope = _apply_ola(_apply_level(_apply_search(queue)))
    claim_tally = claim_scope.aggregate(
        total=Count('id'),
        actionable=Count('id', filter=ready_q | mine_q),
        unclaimed=Count('id', filter=ready_q),
        mine=Count('id', filter=mine_q),
        others=Count(
            'id',
            filter=(
                Q(triage_status=WazuhAlert.TRIAGE_TRIAGING)
                & Q(claimed_by__isnull=False)
                & ~Q(claimed_by=request.user)
            ),
        ),
    )
    claim_facets = [
        {'key': None, 'label': 'พร้อมดำเนินการ', 'count': claim_tally['actionable'],
         'active': claim_filter == 'actionable'},
        {'key': 'unclaimed', 'label': 'พร้อมรับ', 'count': claim_tally['unclaimed'],
         'active': claim_filter == 'unclaimed'},
        {'key': 'mine', 'label': 'ที่ฉันรับไว้', 'count': claim_tally['mine'],
         'active': claim_filter == 'mine'},
        {'key': 'others', 'label': 'ผู้อื่นรับไว้', 'count': claim_tally['others'],
         'active': claim_filter == 'others'},
        {'key': 'all', 'label': 'ทั้งหมด', 'count': claim_tally['total'],
         'active': claim_filter == 'all'},
    ]

    ola_scope = _apply_claim(_apply_level(_apply_search(queue)))
    ola_tally = ola_scope.aggregate(
        total=Count('id'),
        breached=Count('id', filter=Q(timestamp__lt=breached_before)),
        due=Count(
            'id',
            filter=Q(
                timestamp__gte=breached_before,
                timestamp__lte=due_within_hour_before,
            ),
        ),
        on_track=Count('id', filter=Q(timestamp__gt=due_within_hour_before)),
    )
    ola_facets = [
        {'key': None, 'label': 'ทั้งหมด', 'count': ola_tally['total'],
         'active': not ola_filter},
        {'key': 'breached', 'label': 'เกิน OLA', 'count': ola_tally['breached'],
         'active': ola_filter == 'breached'},
        {'key': 'due', 'label': 'ครบใน 1 ชม.', 'count': ola_tally['due'],
         'active': ola_filter == 'due'},
        {'key': 'on_track', 'label': 'ยังไม่เร่งด่วน', 'count': ola_tally['on_track'],
         'active': ola_filter == 'on_track'},
    ]

    level_scope = _apply_claim(_apply_ola(_apply_search(queue)))
    level_tally = level_scope.aggregate(
        total=Count('id'),
        lvl15=Count('id', filter=Q(rule_level__gte=15)),
        lvl12=Count('id', filter=Q(rule_level__gte=12, rule_level__lt=15)),
        under12=Count('id', filter=Q(rule_level__lt=12)),
    )
    level_facets = [
        {'key': None, 'label': 'ทั้งหมด', 'count': level_tally['total'],
         'active': not rule_level_filter},
        {'key': '15', 'label': '15+', 'count': level_tally['lvl15'],
         'active': rule_level_filter == '15'},
        {'key': '12', 'label': '12–14', 'count': level_tally['lvl12'],
         'active': rule_level_filter == '12'},
    ]
    # Keep lower ingested alerts accounted for without making the secondary
    # bucket permanent when the ingestion policy only admits level 12+.
    if level_tally['under12'] or rule_level_filter == 'under12':
        level_facets.append({
            'key': 'under12', 'label': 'ต่ำกว่า 12', 'count': level_tally['under12'],
            'active': rule_level_filter == 'under12',
        })

    return render(request, 'wazuh_ingest/triage_queue.html', {
        'page_obj': page_obj,
        'alerts': page_obj,
        'queue_total': queue_total,
        'filtered_count': paginator.count,
        'ready_count': claim_tally['unclaimed'],
        'mine_count': claim_tally['mine'],
        'claim_facets': claim_facets,
        'claim_filter': claim_filter,
        'ola_facets': ola_facets,
        'ola_filter': ola_filter,
        'level_facets': level_facets,
        'rule_level_filter': rule_level_filter,
        'search_query': search_query,
        'sort': sort,
    })


@login_required
def claim_alert(request):
    if request.method != 'POST':
        return redirect('triage_queue')

    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถรับ Alert มา Triage ได้')
        return redirect('triage_queue')

    alert_id = request.POST.get('alert_id')
    updated = WazuhAlert.objects.filter(
        pk=alert_id,
        triage_status=WazuhAlert.TRIAGE_PENDING,
        claimed_by__isnull=True,
    ).update(
        triage_status=WazuhAlert.TRIAGE_TRIAGING,
        claimed_by=request.user,
        claimed_at=timezone.now(),
    )
    if not updated:
        messages.error(request, 'Alert นี้ถูกเจ้าหน้าที่คนอื่นรับไปแล้ว หรือไม่ได้อยู่ในสถานะ Pending')
        return redirect('triage_queue')

    messages.success(request, f'คุณรับ Alert #{alert_id} มา Triage แล้ว')
    return redirect('triage_queue')


@login_required
def release_alert(request):
    if request.method != 'POST':
        return redirect('triage_queue')

    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('triage_queue')

    # A reason is REQUIRED when releasing a claimed alert back to the queue.
    reason = request.POST.get('release_reason', '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการคืน Alert กลับเข้า Queue')
        return redirect('triage_queue')

    alert_id = request.POST.get('alert_id')
    with transaction.atomic():
        alert = (
            WazuhAlert.objects.select_for_update()
            .filter(
                pk=alert_id,
                triage_status=WazuhAlert.TRIAGE_TRIAGING,
                claimed_by=request.user,
            )
            .first()
        )
        if alert is None:
            messages.error(request, 'Alert นี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
            return redirect('triage_queue')
        alert.release_reason = reason
        alert.triage_note = reason
        alert.triage_status = WazuhAlert.TRIAGE_PENDING
        alert.claimed_by = None
        alert.claimed_at = None
        alert.save(update_fields=[
            'release_reason', 'triage_note', 'triage_status',
            'claimed_by', 'claimed_at',
        ])

    messages.success(request, f'คืน Alert #{alert_id} กลับเข้า Queue พร้อมเหตุผลแล้ว')
    return redirect('triage_queue')


def _has_tier2_access(user):
    profile = getattr(user, 'profile', None)
    return user.is_superuser or (profile is not None and profile.is_tier2)


@login_required
def claim_escalation(request):
    """Take a ticket out of the shared Tier 2 queue.

    Mirrors claim_alert: one conditional UPDATE, so two analysts pressing the
    button at the same moment can't both win — the loser is told it is already
    claimed instead of silently sharing the case.
    """
    if request.method != 'POST':
        return redirect('escalation_queue')

    if not _has_tier2_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 2 เท่านั้นที่สามารถรับ Ticket ได้')
        return redirect('escalation_queue')

    ticket_pk = request.POST.get('ticket_id')
    updated = Ticket.objects.filter(
        pk=ticket_pk,
        status__in=Ticket.TIER2_QUEUE_STATUSES,
        t2_claimed_by__isnull=True,
    ).update(t2_claimed_by=request.user, t2_claimed_at=timezone.now())

    if not updated:
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

    ticket_pk = request.POST.get('ticket_id')
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

    base_qs = Ticket.objects.filter(status__in=Ticket.TIER2_QUEUE_STATUSES)

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

    return render(request, 'wazuh_ingest/escalation_queue.html', {
        'page_obj': page_obj,
        'tickets': page_obj,
        # paginator.count is the same post-filter total the second count() query
        # produced, minus the query. Note this is the FILTERED count, unlike the
        # sidebar badge (wazuh_ingest/context_processors.py), which is unfiltered.
        'escalated_count': paginator.count,
        'claim_filter': claim_filter,
        'stage_filter': stage_filter,
        'stage_facets': stage_facets,
        'claim_facets': claim_facets,
        'sort': sort,
    })


@login_required
def triage_action(request):
    """Tier 1 triage has exactly two actions after claiming an alert:
    create a ticket (here) or release it back to the queue (release_alert).

    The old triage-level Close (FP) and Escalate actions are gone — the
    Event/Incident and escalation decisions now live on the ticket.

    Because creating a ticket is the only forward move, this step asks the
    analyst for nothing: there is no alternative to justify. It only records
    which destination they picked. The threat taxonomy is captured on the
    ticket form, which owns it properly (a validated detailed_issue →
    detailed_issue2 cascade), and the Critical triage OLA runs from incident
    time (Ticket.OLA_TARGETS), so anything asked for here is spent from that
    30-minute budget before the ticket even exists.
    """
    if request.method != 'POST':
        return redirect('triage_queue')

    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('triage_queue')

    action = request.POST.get('action', '')

    if action not in ('create_ticket', 'create_project_incident'):
        messages.error(
            request,
            'การดำเนินการไม่ถูกต้อง — Tier 1 สามารถสร้าง Ticket หรือคืน Alert เท่านั้น',
        )
        return redirect('triage_queue')

    # Read-only ownership gate: nothing is written here, so no row lock is
    # needed. The alert deliberately stays claimed and TRIAGING until the
    # Ticket is saved — a cancelled ticket form must not lose the claim.
    alert = get_object_or_404(WazuhAlert, pk=request.POST.get('alert_id'))
    owns_triage = (
        alert.triage_status == WazuhAlert.TRIAGE_TRIAGING
        and alert.claimed_by_id == request.user.id
    )
    if not (owns_triage or (
        request.user.is_superuser
        and alert.triage_status == WazuhAlert.TRIAGE_TRIAGING
    )):
        messages.error(request, f'Alert #{alert.pk} ไม่ได้อยู่ในความรับผิดชอบของคุณ หรือถูกดำเนินการไปแล้ว')
        return redirect('triage_queue')

    params = {
        'wazuh_alert': alert.pk,
        'issue_description': alert.rule_description,
        'severity': _severity_for_rule_level(alert.rule_level),
    }

    # Same claimed-alert intake, two destinations: a single ticket or a
    # multi-system Project Incident (case bundle). Both pre-fill from the alert;
    # the alert stays claimed until the target form is saved.
    target = (
        'create_project_incident'
        if action == 'create_project_incident'
        else 'create_ticket'
    )
    return redirect(f"{reverse(target)}?{urlencode(params)}")
