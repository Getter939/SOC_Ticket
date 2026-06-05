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

    class Meta:
        model = Ticket
        fields = [
            # Section 1
            'severity',
            'incident_datetime',
            'reference_id',
            # Section 2
            'category',
            'issue_type',
            'detailed_issue',
            'detailed_issue2',
            # Section 3
            'device_name',
            'issue_description',
            # Section 4
            'ip_address',
            'mac_address',
            'asset_type',
            'spread_to_others',
            # Section 5
            'destination_ip',
            'ioc_details',
            # Section 6
            'mitre_phase',
            # Assignment
            'assigned_to',
            'assigned_admin',
            'system_owner',
        ]
        widgets = {
            'severity':           forms.RadioSelect(attrs={'class': 'severity-radio'}),
            'incident_datetime':  forms.DateTimeInput(
                attrs={'class': 'form-control', 'type': 'datetime-local'},
                format='%Y-%m-%dT%H:%M',
            ),
            'reference_id':       forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น INC-2026-0001'}),
            'category':           forms.Select(attrs={'class': 'form-select'}),
            'issue_type':         forms.Select(attrs={'class': 'form-select'}),
            'detailed_issue':     forms.Select(attrs={'class': 'form-select'}),
            'detailed_issue2':    forms.Select(attrs={'class': 'form-select'}),
            'device_name':        forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น NTHQ-WS-047 / ระบบ HR Portal'}),
            'issue_description':  forms.Textarea(attrs={
                'class': 'form-control', 'rows': 5,
                'placeholder': 'สรุปรายละเอียดเหตุการณ์ที่ตรวจพบ เช่น ลักษณะเหตุการณ์ ช่องโหว่/เทคนิคที่เกี่ยวข้อง วันที่และเวลาที่เริ่มพบเหตุการณ์ แหล่งที่มาของการแจ้งเตือน และผลกระทบเบื้องต้น',
            }),
            'ip_address':         forms.TextInput(attrs={'class': 'form-control', 'placeholder': '0.0.0.0'}),
            'mac_address':        forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'AA:BB:CC:DD:EE:FF'}),
            'asset_type':         forms.RadioSelect(attrs={'class': 'asset-type-radio'}),
            'spread_to_others':   forms.NullBooleanSelect(attrs={'class': 'form-select'}),
            'destination_ip':     forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น 79[.]124[.]59[.]146'}),
            'ioc_details':        forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'IP, Domain, Hash, หรือ IoC อื่น ๆ ที่พบ',
            }),
            'mitre_phase':        forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น T1059.001 — Command and Scripting Interpreter: PowerShell'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk and self.instance.incident_datetime:
            self.initial['incident_datetime'] = self.instance.incident_datetime.strftime('%Y-%m-%dT%H:%M')
        self.fields['system_owner'].label_from_instance = lambda u: (
            f"{u.profile.department} — {u.get_full_name() or u.username}"
            if hasattr(u, 'profile') else u.username
        )


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
