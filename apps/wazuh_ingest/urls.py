from django.urls import path

from . import views

urlpatterns = [
    path('triage_queue/', views.triage_queue, name='triage_queue'),
    path('triage_action/', views.triage_action, name='triage_action'),
]
