from django.urls import path
from . import views

urlpatterns = [
    # Tickets
    path('', views.ticket_list, name='ticket_list'),
    path('new/', views.create_ticket, name='create_ticket'),
    path('lookup/ip/', views.ip_lookup, name='ip_lookup'),
    path('search/', views.global_search, name='global_search'),
    path('ticket/<int:pk>/', views.ticket_detail, name='ticket_detail'),
    path('ticket/<int:pk>/upload/', views.upload_attachment, name='upload_attachment'),
    path('attachment/<int:attachment_id>/delete/', views.delete_attachment, name='delete_attachment'),
    path('attachment/<int:attachment_id>/download/', views.download_attachment, name='download_attachment'),
    path('log/edit/<int:log_id>/', views.edit_log, name='edit_log'),
    path('ticket/<int:pk>/subtask/new/', views.create_subtask, name='create_subtask'),
    path('subtask/<int:subtask_id>/update/', views.update_subtask, name='update_subtask'),
    path('history/', views.ticket_history, name='ticket_history'),
    # Triage
    path('triage/', views.triage_list, name='triage_list'),
    path('triage/new/', views.create_triage, name='create_triage'),
    path('triage/<int:triage_id>/respond/', views.respond_escalation, name='respond_escalation'),
    # System Owner
    path('my-tickets/', views.system_owner_dashboard, name='system_owner_dashboard'),
]
