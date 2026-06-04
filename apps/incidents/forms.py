from django import forms
from django.contrib.auth.models import User

from apps.accounts.models import UserProfile
from .models import Ticket, TriageRecord


class TicketForm(forms.ModelForm):
    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('first_name', 'username'),
        required=False,
        label='ผู้รับผิดชอบ (SOC)',
        empty_label='-- ยังไม่ระบุ --',
        widget=forms.Select(attrs={'class': 'form-control'}),
    )
    assigned_admin = forms.ModelChoiceField(
        queryset=User.objects.filter(
            profile__role=UserProfile.ROLE_SYSTEM_ADMIN,
            is_active=True,
        ).order_by('first_name', 'username'),
        required=False,
        label='ผู้ดูแลระบบที่รับผิดชอบ',
        empty_label='-- ยังไม่ระบุ --',
        widget=forms.Select(attrs={'class': 'form-control'}),
    )

    class Meta:
        model = Ticket
        fields = [
            'device_name',
            'ip_address',
            'category',
            'issue_type',
            'detailed_issue',
            'detailed_issue2',
            'issue_description',
            'assigned_to',
            'assigned_admin',
            'system_owner_name',
            'system_owner_email',
        ]
        widgets = {
            'device_name':        forms.TextInput(attrs={'class': 'form-control'}),
            'ip_address':         forms.TextInput(attrs={'class': 'form-control'}),
            'category':           forms.Select(attrs={'class': 'form-control'}),
            'issue_type':         forms.Select(attrs={'class': 'form-control'}),
            'detailed_issue':     forms.Select(attrs={'class': 'form-control'}),
            'detailed_issue2':    forms.Select(attrs={'class': 'form-control'}),
            'issue_description':  forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'system_owner_name':  forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'ชื่อหน่วยงาน / เจ้าของระบบ'}),
            'system_owner_email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'email@example.com'}),
        }


class TriageForm(forms.ModelForm):
    escalated_to = forms.ModelChoiceField(
        queryset=User.objects.filter(
            profile__role__in=[UserProfile.ROLE_SOC_STAFF, UserProfile.ROLE_SOC_MANAGER],
            is_active=True,
        ).order_by('first_name', 'username'),
        required=False,
        label='Escalate ไปยัง T2',
        empty_label='-- เลือก T2 (เฉพาะกรณี Escalate) --',
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    class Meta:
        model = TriageRecord
        fields = ['alert_description', 'source_ip', 'decision', 'notes', 'escalated_to']
        widgets = {
            'alert_description': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 4,
                'placeholder': 'อธิบายรายละเอียด Alert จาก Wazuh — rule, severity, affected asset...',
            }),
            'source_ip': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '0.0.0.0'}),
            'decision':  forms.Select(attrs={'class': 'form-select'}),
            'notes':     forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'บันทึกเหตุผลประกอบการตัดสินใจ...',
            }),
        }

    def clean(self):
        cleaned = super().clean()
        decision = cleaned.get('decision')
        escalated_to = cleaned.get('escalated_to')
        if decision == TriageRecord.DECISION_ESCALATED and not escalated_to:
            self.add_error('escalated_to', 'กรุณาเลือก T2 ที่จะรับช่วงต่อ')
        return cleaned
