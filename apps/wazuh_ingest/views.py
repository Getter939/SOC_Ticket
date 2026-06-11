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


def _severity_for_rule_level(rule_level):
    """Map a Wazuh rule.level to a Ticket severity choice."""
    if rule_level >= 13:
        return 'Critical'
    if rule_level >= 10:
        return 'High'
    if rule_level >= 7:
        return 'Medium'
    return 'Low'


@login_required
def triage_queue(request):
    profile = getattr(request.user, 'profile', None)
    if profile is None or not profile.is_soc:
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเข้าถึง Triage Queue ได้')
        return redirect('ticket_list')

    pending = WazuhAlert.objects.filter(triage_status=WazuhAlert.TRIAGE_PENDING)

    rule_level_filter = request.GET.get('rule_level_filter', '').strip()
    alerts = pending
    if rule_level_filter:
        try:
            min_level = int(rule_level_filter)
            alerts = alerts.filter(rule_level__gte=min_level)
        except ValueError:
            rule_level_filter = ''

    alerts = alerts.order_by('-rule_level', 'timestamp')

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
        'level_summary': level_summary,
        'rule_level_filter': rule_level_filter,
        'tier_choices': WazuhAlert.TIER_CHOICES,
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
    escalate_to = request.POST.get('escalate_to', '').strip()

    if alert.triage_status != WazuhAlert.TRIAGE_PENDING:
        messages.error(request, f'Alert #{alert.pk} ถูกดำเนินการ Triage ไปแล้วโดยผู้อื่น')
        return redirect('triage_queue')

    if action not in ('close_fp', 'create_ticket', 'escalate'):
        messages.error(request, 'การดำเนินการไม่ถูกต้อง')
        return redirect('triage_queue')

    if not note:
        messages.error(request, 'กรุณาระบุหมายเหตุประกอบการตัดสินใจ')
        return redirect('triage_queue')

    if action == 'escalate' and escalate_to not in ESCALATE_TIER_CHOICES:
        messages.error(request, 'กรุณาเลือกระดับ (Tier) ที่ต้องการ Escalate')
        return redirect('triage_queue')

    alert.triaged_by = request.user
    alert.triaged_at = timezone.now()
    alert.triage_note = note

    if action == 'close_fp':
        alert.triage_status = WazuhAlert.TRIAGE_FALSE_POSITIVE
        alert.save(update_fields=['triage_status', 'triaged_by', 'triaged_at', 'triage_note'])
        messages.success(request, f'Alert #{alert.pk} ถูกปิดเป็น False Positive แล้ว')
        return redirect('triage_queue')

    if action == 'escalate':
        alert.triage_status = WazuhAlert.TRIAGE_ESCALATED
        alert.escalated_to_tier = escalate_to
        alert.save(update_fields=[
            'triage_status', 'triaged_by', 'triaged_at', 'triage_note', 'escalated_to_tier',
        ])
        messages.success(
            request,
            f'Alert #{alert.pk} ถูก Escalate ไปยัง {alert.get_escalated_to_tier_display()} แล้ว',
        )
        return redirect('triage_queue')

    # action == 'create_ticket'
    alert.triage_status = WazuhAlert.TRIAGE_TRUE_POSITIVE
    alert.save(update_fields=['triage_status', 'triaged_by', 'triaged_at', 'triage_note'])

    params = urlencode({
        'wazuh_alert': alert.pk,
        'issue_description': alert.rule_description,
        'severity': _severity_for_rule_level(alert.rule_level),
    })
    return redirect(f"{reverse('create_ticket')}?{params}")
