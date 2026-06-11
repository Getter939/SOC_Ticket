from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from .models import WazuhAlert

ESCALATE_TIER_CHOICES = dict(WazuhAlert.TIER_CHOICES)
CATEGORY_CHOICES = dict(WazuhAlert.CATEGORY_CHOICES)

# Best-effort mapping from a WazuhAlert incident category to the closest
# Ticket.DETAILED_ISSUE_CHOICES2 value, used to pre-fill the ticket form.
CATEGORY_TO_DETAILED_ISSUE2 = {
    WazuhAlert.CATEGORY_MALWARE: 'Malware EDR',
    WazuhAlert.CATEGORY_PHISHING: 'Simulated Phishing',
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


@login_required
def triage_queue(request):
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
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
        'tier_choices': WazuhAlert.TIER_CHOICES,
        'category_choices': WazuhAlert.CATEGORY_CHOICES,
    })


@login_required
def claim_alert(request):
    if request.method != 'POST':
        return redirect('triage_queue')

    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('ticket_list')

    alert = get_object_or_404(WazuhAlert, pk=request.POST.get('alert_id'))

    if alert.triage_status != WazuhAlert.TRIAGE_PENDING:
        messages.error(request, f'Alert #{alert.pk} ไม่ได้อยู่ในสถานะ Pending แล้ว')
        return redirect('triage_queue')

    alert.triage_status = WazuhAlert.TRIAGE_TRIAGING
    alert.claimed_by = request.user
    alert.claimed_at = timezone.now()
    alert.save(update_fields=['triage_status', 'claimed_by', 'claimed_at'])

    messages.success(request, f'คุณรับ Alert #{alert.pk} มา Triage แล้ว')
    return redirect('triage_queue')


@login_required
def release_alert(request):
    if request.method != 'POST':
        return redirect('triage_queue')

    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('ticket_list')

    alert = get_object_or_404(WazuhAlert, pk=request.POST.get('alert_id'))

    if alert.triage_status != WazuhAlert.TRIAGE_TRIAGING or alert.claimed_by_id != request.user.id:
        messages.error(request, f'Alert #{alert.pk} ไม่ได้อยู่ในความรับผิดชอบของคุณ')
        return redirect('triage_queue')

    alert.triage_status = WazuhAlert.TRIAGE_PENDING
    alert.claimed_by = None
    alert.claimed_at = None
    alert.save(update_fields=['triage_status', 'claimed_by', 'claimed_at'])

    messages.success(request, f'คืน Alert #{alert.pk} กลับเข้า Queue แล้ว')
    return redirect('triage_queue')


@login_required
def escalation_queue(request):
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเข้าถึง Escalation Queue ได้')
        return redirect('ticket_list')

    tier = _user_tier(profile)
    if tier is None:
        alerts_qs = WazuhAlert.objects.none()
    else:
        alerts_qs = WazuhAlert.objects.filter(
            triage_status=WazuhAlert.TRIAGE_ESCALATED, escalated_to_tier=tier,
        )

    alerts_qs = alerts_qs.select_related('triaged_by').order_by('-rule_level', 'timestamp')

    paginator = Paginator(alerts_qs, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'wazuh_ingest/escalation_queue.html', {
        'page_obj': page_obj,
        'alerts': page_obj,
        'escalated_count': alerts_qs.count(),
        'tier': tier,
        'tier_choices': WazuhAlert.TIER_CHOICES,
        'category_choices': WazuhAlert.CATEGORY_CHOICES,
    })


@login_required
def triage_action(request):
    if request.method != 'POST':
        return redirect('triage_queue')

    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถดำเนินการนี้ได้')
        return redirect('ticket_list')

    alert = get_object_or_404(WazuhAlert, pk=request.POST.get('alert_id'))
    action = request.POST.get('action', '')
    note = request.POST.get('note', '').strip()
    category = request.POST.get('category', '').strip()
    escalate_to = request.POST.get('escalate_to', '').strip()
    source = request.POST.get('source', 'triage_queue')
    redirect_to = 'escalation_queue' if source == 'escalation_queue' else 'triage_queue'

    # An alert can only be acted on by the analyst who claimed it (Triage Queue),
    # or by a member of the tier it was escalated to (Escalation Queue).
    if alert.triage_status == WazuhAlert.TRIAGE_TRIAGING and alert.claimed_by_id == request.user.id:
        pass
    elif alert.triage_status == WazuhAlert.TRIAGE_ESCALATED and alert.escalated_to_tier == _user_tier(profile):
        pass
    else:
        messages.error(request, f'Alert #{alert.pk} ไม่ได้อยู่ในความรับผิดชอบของคุณ หรือถูกดำเนินการไปแล้ว')
        return redirect(redirect_to)

    if action not in ('close_fp', 'create_ticket', 'escalate'):
        messages.error(request, 'การดำเนินการไม่ถูกต้อง')
        return redirect(redirect_to)

    if not note:
        messages.error(request, 'กรุณาระบุหมายเหตุประกอบการตัดสินใจ')
        return redirect(redirect_to)

    if action in ('create_ticket', 'escalate') and category not in CATEGORY_CHOICES:
        messages.error(request, 'กรุณาเลือกประเภทของเหตุการณ์ (Incident Category)')
        return redirect(redirect_to)

    if action == 'escalate' and escalate_to not in ESCALATE_TIER_CHOICES:
        messages.error(request, 'กรุณาเลือกระดับ (Tier) ที่ต้องการ Escalate')
        return redirect(redirect_to)

    alert.triaged_by = request.user
    alert.triaged_at = timezone.now()
    alert.triage_note = note
    if category:
        alert.incident_category = category

    if action == 'close_fp':
        alert.triage_status = WazuhAlert.TRIAGE_FALSE_POSITIVE
        alert.save(update_fields=[
            'triage_status', 'triaged_by', 'triaged_at', 'triage_note', 'incident_category',
        ])
        messages.success(request, f'Alert #{alert.pk} ถูกปิดเป็น False Positive แล้ว')
        return redirect(redirect_to)

    if action == 'escalate':
        alert.triage_status = WazuhAlert.TRIAGE_ESCALATED
        alert.escalated_to_tier = escalate_to
        alert.save(update_fields=[
            'triage_status', 'triaged_by', 'triaged_at', 'triage_note', 'incident_category',
            'escalated_to_tier',
        ])
        messages.success(
            request,
            f'Alert #{alert.pk} ถูก Escalate ไปยัง {alert.get_escalated_to_tier_display()} แล้ว',
        )
        return redirect(redirect_to)

    # action == 'create_ticket'
    alert.triage_status = WazuhAlert.TRIAGE_TRUE_POSITIVE
    alert.save(update_fields=[
        'triage_status', 'triaged_by', 'triaged_at', 'triage_note', 'incident_category',
    ])

    params = {
        'wazuh_alert': alert.pk,
        'issue_description': alert.rule_description,
        'severity': _severity_for_rule_level(alert.rule_level),
    }
    detailed_issue2 = CATEGORY_TO_DETAILED_ISSUE2.get(category)
    if detailed_issue2:
        params['detailed_issue2'] = detailed_issue2

    return redirect(f"{reverse('create_ticket')}?{urlencode(params)}")
