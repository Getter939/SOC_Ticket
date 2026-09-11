"""Thai cancellation forms and POST endpoint."""

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from .cancellation import can_cancel_directly, can_request_cancellation
from .models import Ticket, TicketCancellationRequest, TicketSubtask
from .policies import is_soc_manager
from .ticket_workflow import cancellation_action


class CancellationForm(forms.Form):
    reason = forms.ChoiceField(
        label='ประเภทเหตุผล',
        choices=[('', 'เลือกประเภทเหตุผล')] + list(TicketCancellationRequest.REASON_CHOICES),
    )
    explanation = forms.CharField(label='รายละเอียดเหตุผล', max_length=4000, widget=forms.Textarea(attrs={'rows': 3}))
    duplicate_reference = forms.CharField(label='เลขรายการต้นฉบับ (กรณีรายการซ้ำ)', required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-select' if isinstance(field, forms.ChoiceField) else 'form-control'
            field.error_messages['required'] = 'กรุณากรอกข้อมูลนี้'
        self.fields['reason'].error_messages['invalid_choice'] = 'กรุณาเลือกประเภทเหตุผลที่ถูกต้อง'


def cancellation_context(ticket, user):
    records = list(ticket.cancellation_requests.select_related('requested_by', 'decided_by', 'duplicate_of'))
    visible_duplicates = set(Ticket.objects.visible_to(user).filter(
        pk__in=[record.duplicate_of_id for record in records if record.duplicate_of_id],
    ).values_list('pk', flat=True))
    for record in records:
        record.duplicate_visible = record.duplicate_of_id in visible_duplicates
    pending = next((r for r in records if r.status == 'PENDING'), None)
    active = ticket.status not in Ticket.TERMINAL_STATUSES
    return {
        'cancellation_form': CancellationForm(),
        'cancellation_records': records,
        'pending_cancellation': pending,
        'can_request_cancellation': not pending and can_request_cancellation(ticket, user),
        'can_cancel_directly': not pending and can_cancel_directly(ticket, user),
        'can_decide_cancellation': active and pending and is_soc_manager(user),
        'can_withdraw_cancellation': active and pending and pending.requested_by_id == user.pk,
        'cancellation_outstanding_tasks': ticket.subtasks.exclude(status__in=TicketSubtask.TERMINAL_STATUSES),
        'cancellation_manager': is_soc_manager(user),
    }


@login_required
@require_POST
def ticket_cancellation(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    action = request.POST.get('action', '')
    kwargs = {
        'request_id': request.POST.get('request_id'),
        'decision_note': request.POST.get('decision_note', ''),
        'cancel_subtask_ids': request.POST.getlist('cancel_subtask_ids'),
    }
    try:
        if action in ('request', 'direct'):
            form = CancellationForm(request.POST)
            if not form.is_valid():
                raise ValidationError('กรุณาเลือกประเภทเหตุผลและกรอกรายละเอียดไม่เกิน 4,000 ตัวอักษร')
            kwargs.update({key: form.cleaned_data[key] for key in ('reason', 'explanation')})
            if form.cleaned_data['reason'] == 'DUPLICATE':
                kwargs['duplicate_of'] = Ticket.objects.visible_to(request.user).filter(
                    ticket_id=form.cleaned_data['duplicate_reference'],
                ).first()
        cancellation_action(ticket=ticket, actor=request.user, action=action, **kwargs)
        messages.success(request, {
            'request': 'ส่งคำขอยกเลิกให้ผู้จัดการ SOC แล้ว ระหว่างรออนุมัติให้ดำเนินงานต่อ',
            'direct': 'ยกเลิกรายการเรียบร้อยแล้ว', 'approve': 'อนุมัติยกเลิกรายการเรียบร้อยแล้ว',
            'reject': 'บันทึกการไม่อนุมัติแล้ว รายการยังดำเนินงานต่อ',
            'withdraw': 'ถอนคำขอยกเลิกเรียบร้อยแล้ว',
        }[action])
    except ValidationError as exc:
        messages.error(request, ' '.join(exc.messages))
    return redirect('ticket_detail', pk=pk)
