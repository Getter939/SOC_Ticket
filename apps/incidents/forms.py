from django import forms
from django.contrib.auth.models import User

from apps.accounts.models import UserProfile
from .models import Ticket


class TicketForm(forms.ModelForm):
    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('first_name', 'username'),
        required=False,
        label='ผู้รับผิดชอบ (SOC)',
        empty_label='-- ยังไม่ระบุ --',
        widget=forms.Select(attrs={'class': 'form-control'}),
    )
    assigned_admin = forms.ModelChoiceField(
        # Only show users whose profile role is SYSTEM_ADMIN
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
        ]
        widgets = {
            'device_name':       forms.TextInput(attrs={'class': 'form-control'}),
            'ip_address':        forms.TextInput(attrs={'class': 'form-control'}),
            'category':          forms.Select(attrs={'class': 'form-control'}),
            'issue_type':        forms.Select(attrs={'class': 'form-control'}),
            'detailed_issue':    forms.Select(attrs={'class': 'form-control'}),
            'detailed_issue2':   forms.Select(attrs={'class': 'form-control'}),
            'issue_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }
