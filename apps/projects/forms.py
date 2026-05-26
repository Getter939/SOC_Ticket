from django import forms
from .models import Project, Task


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['name', 'customer', 'status', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'customer': forms.Select(attrs={'class': 'form-select'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


class TaskForm(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['title', 'description', 'assignee', 'ticket', 'due_date', 'priority', 'status']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'assignee': forms.Select(attrs={'class': 'form-select'}),
            'ticket': forms.Select(attrs={'class': 'form-select'}),
            'due_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'priority': forms.Select(attrs={'class': 'form-select'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
        }
