from django import forms
from django.contrib.auth.models import User
from .models import Ticket


class TicketForm(forms.ModelForm):
    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('first_name', 'username'),
        required=False,
        label='ผู้รับผิดชอบ',
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
        ]
        widgets = {
            'device_name': forms.TextInput(attrs={'class': 'form-control'}),
            'ip_address': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-control'}),
            'issue_type': forms.Select(attrs={'class': 'form-control'}),
            'detailed_issue': forms.Select(attrs={'class': 'form-control'}),
            'detailed_issue2': forms.Select(attrs={'class': 'form-control'}),
            'issue_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }
