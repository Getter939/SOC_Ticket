from django import forms
from django.forms import inlineformset_factory
from .models import Customer, CustomerEmail, CustomerPhone


class CustomerForm(forms.ModelForm):
    class Meta:
        model = Customer
        fields = ['name', 'note']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'note': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


EmailFormSet = inlineformset_factory(
    Customer, CustomerEmail, fields=['email'], extra=1, can_delete=True,
    widgets={'email': forms.EmailInput(attrs={'class': 'form-control'})}
)

PhoneFormSet = inlineformset_factory(
    Customer, CustomerPhone, fields=['phone_number'], extra=1, can_delete=True,
    widgets={'phone_number': forms.TextInput(attrs={'class': 'form-control'})}
)
