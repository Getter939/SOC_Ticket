from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import Ticket, TicketLog
from .models import WazuhAlert

ESCALATE_TIER_CHOICES = dict(WazuhAlert.TIER_CHOICES)
CATEGORY_CHOICES = dict(WazuhAlert.CATEGORY_CHOICES)

# Best-effort mapping from a WazuhAlert incident category to the closest
# Ticket.DETAILED_ISSUE_CHOICES2 value, used to pre-fill the ticket form.
# Maps a Wazuh alert category to a detailed_issue2 code within the clean threat
# hierarchy (Ticket.DETAILED_ISSUE_HIERARCHY). create_ticket derives the parent
# detailed_issue from this, so every code here must be a selectable child.
CATEGORY_TO_DETAILED_ISSUE2 = {
    WazuhAlert.CATEGORY_MALWARE: 'Malware EDR',
    WazuhAlert.CATEGORY_PHISHING: 'Malicious Other',
    WazuhAlert.CATEGORY_UNAUTHORIZED_ACCESS: 'Unauthorized Admin',
    WazuhAlert.CATEGORY_DATA_EXFILTRATION: 'Data Exfiltration',
    WazuhAlert.CATEGORY_DOS: 'DDoS',
    WazuhAlert.CATEGORY_RECONNAISSANCE: 'Recon Other',
    WazuhAlert.CATEGORY_POLICY_VIOLATION: 'Compliance Other',
    WazuhAlert.CATEGORY_OTHER: 'Investigating Other',
}


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
    profile = getattr(request.user, 'profile', None)
    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถเข้าถึง Triage Queue ได้')
        return redirect('ticket_list')

    queue = WazuhAlert.objects.filter(
        triage_status__in=[WazuhAlert.TRIAGE_PENDING, WazuhAlert.TRIAGE_TRIAGING],
    )
    pending = queue.filter(triage_status=WazuhAlert.TRIAGE_PENDING)

    rule_level_filter = request.GET.get('rule_level_filter', '').strip()
    alerts = queue
    if rule_level_filter:
        try:
            min_level = int(rule_level_filter)
            alerts = alerts.filter(rule_level__gte=min_level)
        except ValueError:
            rule_level_filter = ''

    alerts = alerts.select_related('claimed_by').order_by('-rule_level', 'timestamp')

    paginator = Paginator(alerts, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    level_summary = (
        pending.values('rule_level')
        .annotate(count=Count('id'))
        .order_by('-rule_level')
    )

    return render(request, 'wazuh_ingest/triage_queue.html', {
        'page_obj': page_obj,
        'alerts': page_obj,
        'pending_count': pending.count(),
        'triaging_count': queue.filter(triage_status=WazuhAlert.TRIAGE_TRIAGING).count(),
        'level_summary': level_summary,
        'rule_level_filter': rule_level_filter,
        'tier_choices': _allowed_escalation_tiers(profile, request.user),
        'category_choices': WazuhAlert.CATEGORY_CHOICES,
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

    emergency_filter = request.GET.get('emergency', '').strip()
    stage_filter = request.GET.get('stage', '').strip()
    sort = request.GET.get('sort', 'emergency').strip()

    # The Tier 2 queue covers all three T2 stages: escalation triage plus the
    # two verification stages (admin containment / owner remediation).
    stage_map = {
        'escalated': Ticket.STATUS_ESCALATED_T2,
        'containment': Ticket.STATUS_CONTAINMENT_REPORTED,
        'owner': Ticket.STATUS_PENDING_T2_REVIEW,
    }
    if stage_filter in stage_map:
        tickets_qs = Ticket.objects.filter(status=stage_map[stage_filter])
    else:
        stage_filter = ''
        tickets_qs = Ticket.objects.filter(status__in=Ticket.TIER2_QUEUE_STATUSES)
    tickets_qs = tickets_qs.select_related('created_by', 'assigned_admin', 't2_claimed_by')

    if emergency_filter in ('1', '0'):
        tickets_qs = tickets_qs.filter(is_emergency=emergency_filter == '1')
    else:
        emergency_filter = ''
    # status_changed_at = when the ticket entered its current (queue) status —
    # meaningful for all three stages, unlike escalated_to_t2_at.
    sort_map = {
        'emergency': ('-is_emergency', '-status_changed_at'),
        'newest': ('-status_changed_at',),
        'severity': ('severity', '-status_changed_at'),
    }
    if sort not in sort_map:
        sort = 'emergency'
    tickets_qs = tickets_qs.order_by(*sort_map[sort])

    paginator = Paginator(tickets_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'wazuh_ingest/escalation_queue.html', {
        'page_obj': page_obj,
        'tickets': page_obj,
        'escalated_count': tickets_qs.count(),
        'emergency_filter': emergency_filter,
        'stage_filter': stage_filter,
        'sort': sort,
    })


@login_required
def triage_action(request):
    """Tier 1 triage has exactly two actions after claiming an alert:
    create a ticket (here) or release it back to the queue (release_alert).

    The old triage-level Close (FP) and Escalate actions are gone — the
    Event/Incident and escalation decisions now live on the ticket.
    """
    if request.method != 'POST':
        return redirect('triage_queue')

    if not _has_tier1_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('triage_queue')

    action = request.POST.get('action', '')
    note = request.POST.get('note', '').strip()
    category = request.POST.get('category', '').strip()

    if action not in ('create_ticket', 'create_project_incident'):
        messages.error(
            request,
            'การดำเนินการไม่ถูกต้อง — Tier 1 สามารถสร้าง Ticket หรือคืน Alert เท่านั้น',
        )
        return redirect('triage_queue')

    if not note:
        messages.error(request, 'กรุณาระบุหมายเหตุประกอบการตัดสินใจ')
        return redirect('triage_queue')

    if category not in CATEGORY_CHOICES:
        messages.error(request, 'กรุณาเลือกประเภทของเหตุการณ์ (Incident Category)')
        return redirect('triage_queue')

    with transaction.atomic():
        alert = get_object_or_404(
            WazuhAlert.objects.select_for_update(),
            pk=request.POST.get('alert_id'),
        )
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

        # Keep the alert claimed and in TRIAGING until the Ticket is saved —
        # a cancelled ticket form must not lose the claim.
        alert.triage_note = note
        if category:
            alert.incident_category = category
        alert.save(update_fields=['triage_note', 'incident_category'])

    params = {
        'wazuh_alert': alert.pk,
        'issue_description': alert.rule_description,
        'severity': _severity_for_rule_level(alert.rule_level),
    }
    detailed_issue2 = CATEGORY_TO_DETAILED_ISSUE2.get(category)
    if detailed_issue2:
        params['detailed_issue2'] = detailed_issue2

    # Same claimed-alert intake, two destinations: a single ticket or a
    # multi-system Project Incident (case bundle). Both pre-fill from the alert;
    # the alert stays claimed until the target form is saved.
    target = (
        'create_project_incident'
        if action == 'create_project_incident'
        else 'create_ticket'
    )
    return redirect(f"{reverse(target)}?{urlencode(params)}")
