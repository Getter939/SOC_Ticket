from django.urls import path

from . import views

urlpatterns = [
    path('triage_queue/', views.triage_queue, name='triage_queue'),
    path('triage_action/', views.triage_action, name='triage_action'),
    path('claim_alert/', views.claim_alert, name='claim_alert'),
    path('release_alert/', views.release_alert, name='release_alert'),
    path('escalation_queue/', views.escalation_queue, name='escalation_queue'),
    path('claim_escalation/', views.claim_escalation, name='claim_escalation'),
    path('release_escalation/', views.release_escalation, name='release_escalation'),
    path('triage_history/', views.triage_history, name='triage_history'),
    path('reopen_alert/', views.reopen_alert, name='reopen_alert'),
]
