from django import forms
from django.contrib.auth.models import User

from apps.accounts.models import UserProfile
from .models import Ticket, TicketAttachment, TriageRecord


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

    system_owner = forms.ModelChoiceField(
        queryset=User.objects.filter(
            profile__role=UserProfile.ROLE_SYSTEM_OWNER,
            is_active=True,
        ).order_by('profile__department', 'first_name', 'username'),
        required=False,
        label='เจ้าของระบบ / หน่วยงาน',
        empty_label='-- ยังไม่ระบุ --',
        widget=forms.Select(attrs={'class': 'form-control'}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Show "Department — Full Name" in the system_owner dropdown
        self.fields['system_owner'].label_from_instance = lambda u: (
            f"{u.profile.department} — {u.get_full_name() or u.username}"
            if hasattr(u, 'profile') else u.username
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
            'system_owner',
        ]
        widgets = {
            'device_name':        forms.TextInput(attrs={'class': 'form-control'}),
            'ip_address':         forms.TextInput(attrs={'class': 'form-control'}),
            'category':           forms.Select(attrs={'class': 'form-control'}),
            'issue_type':         forms.Select(attrs={'class': 'form-control'}),
            'detailed_issue':     forms.Select(attrs={'class': 'form-control'}),
            'detailed_issue2':    forms.Select(attrs={'class': 'form-control'}),
            'issue_description':  forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
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


class AttachmentForm(forms.ModelForm):
    class Meta:
        model = TicketAttachment
        fields = ['file', 'description']
        widgets = {
            'file':        forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'description': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'คำอธิบายไฟล์ (ไม่บังคับ)',
            }),
        }
