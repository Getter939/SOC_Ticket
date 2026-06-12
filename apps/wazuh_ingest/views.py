from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date

from .models import WazuhAlert

ESCALATE_TIER_CHOICES = dict(WazuhAlert.TIER_CHOICES)
CATEGORY_CHOICES = dict(WazuhAlert.CATEGORY_CHOICES)

# Best-effort mapping from a WazuhAlert incident category to the closest
# Ticket.DETAILED_ISSUE_CHOICES2 value, used to pre-fill the ticket form.
CATEGORY_TO_DETAILED_ISSUE2 = {
    WazuhAlert.CATEGORY_MALWARE: 'Malware EDR',
    WazuhAlert.CATEGORY_PHISHING: 'SIEM Other Detail',
    WazuhAlert.CATEGORY_UNAUTHORIZED_ACCESS: 'Unauthorized Admin',
    WazuhAlert.CATEGORY_DATA_EXFILTRATION: 'Data Exfiltration',
    WazuhAlert.CATEGORY_DOS: 'DDoS',
    WazuhAlert.CATEGORY_RECONNAISSANCE: 'Recon Other',
    WazuhAlert.CATEGORY_POLICY_VIOLATION: 'Compliance Other',
    WazuhAlert.CATEGORY_OTHER: 'SIEM Other Detail',
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
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเข้าถึง Triage Queue ได้')
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

    profile = getattr(request.user, 'profile', None)
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('ticket_list')

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

    profile = getattr(request.user, 'profile', None)
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('ticket_list')

    alert_id = request.POST.get('alert_id')
    updated = WazuhAlert.objects.filter(
        pk=alert_id,
        triage_status=WazuhAlert.TRIAGE_TRIAGING,
        claimed_by=request.user,
    ).update(
        triage_status=WazuhAlert.TRIAGE_PENDING,
        claimed_by=None,
        claimed_at=None,
    )
    if not updated:
        messages.error(request, 'Alert นี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
        return redirect('triage_queue')

    messages.success(request, f'คืน Alert #{alert_id} กลับเข้า Queue แล้ว')
    return redirect('triage_queue')


@login_required
def claim_escalation(request):
    if request.method != 'POST':
        return redirect('escalation_queue')

    profile = getattr(request.user, 'profile', None)
    tier = _user_tier(profile) if profile and profile.is_soc else None
    if not request.user.is_superuser and tier is None:
        messages.error(request, 'บัญชีของคุณไม่มีสิทธิ์รับงานจาก Escalation Queue')
        return redirect('ticket_list')

    alert_id = request.POST.get('alert_id')
    claimable = WazuhAlert.objects.filter(
        pk=alert_id,
        triage_status=WazuhAlert.TRIAGE_ESCALATED,
        claimed_by__isnull=True,
    )
    if not request.user.is_superuser:
        claimable = claimable.filter(escalated_to_tier=tier)
    updated = claimable.update(claimed_by=request.user, claimed_at=timezone.now())
    if not updated:
        messages.error(request, 'Alert นี้ถูกเจ้าหน้าที่คนอื่นรับไปแล้ว หรือไม่อยู่ใน Queue ของ Tier คุณ')
        return redirect('escalation_queue')

    messages.success(request, f'คุณรับ Escalated Alert #{alert_id} แล้ว')
    return redirect('escalation_queue')


@login_required
def release_escalation(request):
    if request.method != 'POST':
        return redirect('escalation_queue')

    profile = getattr(request.user, 'profile', None)
    tier = _user_tier(profile) if profile and profile.is_soc else None
    if not request.user.is_superuser and tier is None:
        messages.error(request, 'บัญชีของคุณไม่มีสิทธิ์ดำเนินการนี้')
        return redirect('ticket_list')

    alert_id = request.POST.get('alert_id')
    releasable = WazuhAlert.objects.filter(
        pk=alert_id,
        triage_status=WazuhAlert.TRIAGE_ESCALATED,
        claimed_by=request.user,
    )
    if not request.user.is_superuser:
        releasable = releasable.filter(escalated_to_tier=tier)
    updated = releasable.update(claimed_by=None, claimed_at=None)
    if not updated:
        messages.error(request, 'Alert นี้ไม่ได้อยู่ในความรับผิดชอบของคุณ')
        return redirect('escalation_queue')

    messages.success(request, f'คืน Escalated Alert #{alert_id} กลับเข้า Queue แล้ว')
    return redirect('escalation_queue')


@login_required
def escalation_queue(request):
    profile = getattr(request.user, 'profile', None)
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเข้าถึง Escalation Queue ได้')
        return redirect('ticket_list')

    tier = _user_tier(profile) if profile else None
    if request.user.is_superuser:
        alerts_qs = WazuhAlert.objects.filter(
            triage_status=WazuhAlert.TRIAGE_ESCALATED,
        )
        tier_label = 'All tiers'
    elif tier is None:
        alerts_qs = WazuhAlert.objects.none()
        tier_label = None
    else:
        alerts_qs = WazuhAlert.objects.filter(
            triage_status=WazuhAlert.TRIAGE_ESCALATED, escalated_to_tier=tier,
        )
        tier_label = tier

    alerts_qs = alerts_qs.select_related('triaged_by', 'claimed_by').order_by('-rule_level', 'timestamp')

    paginator = Paginator(alerts_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'wazuh_ingest/escalation_queue.html', {
        'page_obj': page_obj,
        'alerts': page_obj,
        'escalated_count': alerts_qs.count(),
        'tier': tier_label,
        'tier_choices': _allowed_escalation_tiers(profile, request.user),
        'category_choices': WazuhAlert.CATEGORY_CHOICES,
    })


@login_required
def triage_history(request):
    profile = getattr(request.user, 'profile', None)
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเข้าถึงประวัติ Triage ได้')
        return redirect('ticket_list')

    status_filter = request.GET.get('status', '').strip()
    rule_level_filter = request.GET.get('rule_level_filter', '').strip()
    triaged_by_filter = request.GET.get('triaged_by', '').strip()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()

    alerts_qs = WazuhAlert.objects.filter(
        triage_status__in=[WazuhAlert.TRIAGE_TRUE_POSITIVE, WazuhAlert.TRIAGE_FALSE_POSITIVE],
        triaged_by__isnull=False,
    )
    if status_filter in (WazuhAlert.TRIAGE_TRUE_POSITIVE, WazuhAlert.TRIAGE_FALSE_POSITIVE):
        alerts_qs = alerts_qs.filter(triage_status=status_filter)

    if rule_level_filter:
        try:
            alerts_qs = alerts_qs.filter(rule_level__gte=int(rule_level_filter))
        except ValueError:
            rule_level_filter = ''

    if triaged_by_filter:
        try:
            alerts_qs = alerts_qs.filter(triaged_by_id=int(triaged_by_filter))
        except ValueError:
            triaged_by_filter = ''

    parsed_date_from = parse_date(date_from)
    if parsed_date_from:
        alerts_qs = alerts_qs.filter(triaged_at__date__gte=parsed_date_from)
    else:
        date_from = ''

    parsed_date_to = parse_date(date_to)
    if parsed_date_to:
        alerts_qs = alerts_qs.filter(triaged_at__date__lte=parsed_date_to)
    else:
        date_to = ''

    alerts_qs = alerts_qs.select_related('triaged_by').order_by('-triaged_at', '-timestamp')

    paginator = Paginator(alerts_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    triager_choices = (
        User.objects.filter(triaged_alerts__isnull=False)
        .distinct()
        .order_by('first_name', 'username')
    )

    # For closed False Positives, flag whether a new alert with the same
    # agent/rule has since come in — a hint that it may be worth reopening.
    for alert in page_obj:
        alert.related_pending_count = 0
        if alert.triage_status == WazuhAlert.TRIAGE_FALSE_POSITIVE and alert.agent_ip and alert.rule_id:
            alert.related_pending_count = WazuhAlert.objects.filter(
                triage_status__in=[WazuhAlert.TRIAGE_PENDING, WazuhAlert.TRIAGE_TRIAGING],
                agent_ip=alert.agent_ip,
                rule_id=alert.rule_id,
            ).exclude(pk=alert.pk).count()

    return render(request, 'wazuh_ingest/triage_history.html', {
        'page_obj': page_obj,
        'alerts': page_obj,
        'status_filter': status_filter,
        'rule_level_filter': rule_level_filter,
        'triaged_by_filter': triaged_by_filter,
        'date_from': date_from,
        'date_to': date_to,
        'triager_choices': triager_choices,
        'fp_count': WazuhAlert.objects.filter(triage_status=WazuhAlert.TRIAGE_FALSE_POSITIVE).count(),
        'tp_count': WazuhAlert.objects.filter(triage_status=WazuhAlert.TRIAGE_TRUE_POSITIVE).count(),
    })


@login_required
def reopen_alert(request):
    if request.method != 'POST':
        return redirect('triage_history')

    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('ticket_list')

    alert_id = request.POST.get('alert_id')
    updated = WazuhAlert.objects.filter(
        pk=alert_id,
        triage_status=WazuhAlert.TRIAGE_FALSE_POSITIVE,
    ).update(
        triage_status=WazuhAlert.TRIAGE_PENDING,
        triaged_by=None,
        triaged_at=None,
        triage_note='',
        escalated_to_tier=None,
        claimed_by=None,
        claimed_at=None,
    )
    if not updated:
        messages.error(request, f'Alert #{alert_id} ไม่สามารถเปิดกลับได้ (ต้องเป็นสถานะ False Positive)')
        return redirect('triage_history')

    messages.success(request, f'เปิด Alert #{alert_id} กลับเข้า Triage Queue แล้ว')
    return redirect('triage_history')


@login_required
def triage_action(request):
    if request.method != 'POST':
        return redirect('triage_queue')

    profile = getattr(request.user, 'profile', None)
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('ticket_list')

    action = request.POST.get('action', '')
    note = request.POST.get('note', '').strip()
    category = request.POST.get('category', '').strip()
    escalate_to = request.POST.get('escalate_to', '').strip()
    source = request.POST.get('source', 'triage_queue')
    redirect_to = 'escalation_queue' if source == 'escalation_queue' else 'triage_queue'

    if action not in ('close_fp', 'create_ticket', 'escalate'):
        messages.error(request, 'การดำเนินการไม่ถูกต้อง')
        return redirect(redirect_to)

    if not note:
        messages.error(request, 'กรุณาระบุหมายเหตุประกอบการตัดสินใจ')
        return redirect(redirect_to)

    if action in ('create_ticket', 'escalate') and category not in CATEGORY_CHOICES:
        messages.error(request, 'กรุณาเลือกประเภทของเหตุการณ์ (Incident Category)')
        return redirect(redirect_to)

    allowed_escalation_tiers = dict(
        _allowed_escalation_tiers(profile, request.user)
    )
    if action == 'escalate' and escalate_to not in allowed_escalation_tiers:
        messages.error(request, 'สามารถ Escalate ได้เฉพาะ Tier ที่สูงกว่าปัจจุบันเท่านั้น')
        return redirect(redirect_to)

    with transaction.atomic():
        alert = get_object_or_404(
            WazuhAlert.objects.select_for_update(),
            pk=request.POST.get('alert_id'),
        )
        owns_triage = (
            alert.triage_status == WazuhAlert.TRIAGE_TRIAGING
            and alert.claimed_by_id == request.user.id
        )
        owns_escalation = (
            alert.triage_status == WazuhAlert.TRIAGE_ESCALATED
            and (
                request.user.is_superuser
                or alert.escalated_to_tier == _user_tier(profile)
            )
            and alert.claimed_by_id == request.user.id
        )
        if not (owns_triage or owns_escalation):
            messages.error(request, f'Alert #{alert.pk} ไม่ได้อยู่ในความรับผิดชอบของคุณ หรือถูกดำเนินการไปแล้ว')
            return redirect(redirect_to)

        alert.triage_note = note
        if category:
            alert.incident_category = category

        if action == 'close_fp':
            alert.triage_status = WazuhAlert.TRIAGE_FALSE_POSITIVE
            alert.triaged_by = request.user
            alert.triaged_at = timezone.now()
            alert.escalated_to_tier = None
            alert.claimed_by = None
            alert.claimed_at = None
            alert.save(update_fields=[
                'triage_status', 'triaged_by', 'triaged_at', 'triage_note',
                'incident_category', 'escalated_to_tier', 'claimed_by', 'claimed_at',
            ])
            messages.success(request, f'Alert #{alert.pk} ถูกปิดเป็น False Positive แล้ว')
            return redirect(redirect_to)

        if action == 'escalate':
            alert.triage_status = WazuhAlert.TRIAGE_ESCALATED
            alert.triaged_by = request.user
            alert.triaged_at = timezone.now()
            alert.escalated_to_tier = escalate_to
            alert.claimed_by = None
            alert.claimed_at = None
            alert.save(update_fields=[
                'triage_status', 'triaged_by', 'triaged_at', 'triage_note',
                'incident_category', 'escalated_to_tier', 'claimed_by', 'claimed_at',
            ])
            messages.success(
                request,
                f'Alert #{alert.pk} ถูก Escalate ไปยัง {alert.get_escalated_to_tier_display()} แล้ว',
            )
            return redirect(redirect_to)

        # Keep the alert assigned and in its current queue until the Ticket
        # is successfully saved. This prevents a cancelled form from losing it.
        alert.save(update_fields=['triage_note', 'incident_category'])

    params = {
        'wazuh_alert': alert.pk,
        'issue_description': alert.rule_description,
        'severity': _severity_for_rule_level(alert.rule_level),
    }
    detailed_issue2 = CATEGORY_TO_DETAILED_ISSUE2.get(category)
    if detailed_issue2:
        params['detailed_issue2'] = detailed_issue2

    return redirect(f"{reverse('create_ticket')}?{urlencode(params)}")
