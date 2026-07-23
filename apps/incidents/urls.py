from django.urls import path
from . import views

urlpatterns = [
    # Tickets
    path('', views.ticket_list, name='ticket_list'),
    path('manager-queue/', views.manager_queue, name='manager_queue'),
    path('new/', views.create_ticket, name='create_ticket'),
    # Project Incident (Case Bundling) — one incident → many linked tickets
    path('project-incident/new/', views.create_project_incident, name='create_project_incident'),
    path('project-incident/<int:pk>/', views.project_incident_detail, name='project_incident_detail'),
    path('lookup/ip/', views.ip_lookup, name='ip_lookup'),
    path('search/', views.global_search, name='global_search'),
    path('ticket/<int:pk>/', views.ticket_detail, name='ticket_detail'),
    path('ticket/<int:pk>/report/docx/', views.ticket_report_docx, name='ticket_report_docx'),
    path('ticket/<int:pk>/report/pdf/', views.ticket_report_pdf, name='ticket_report_pdf'),
    path('ticket/<int:pk>/report/preview/', views.ticket_report_preview, name='ticket_report_preview'),
    path('ticket/<int:pk>/upload/', views.upload_attachment, name='upload_attachment'),
    path('attachment/<int:attachment_id>/delete/', views.delete_attachment, name='delete_attachment'),
    path('attachment/<int:attachment_id>/download/', views.download_attachment, name='download_attachment'),
    path('log/edit/<int:log_id>/', views.edit_log, name='edit_log'),
    path('ticket/<int:pk>/subtask/new/', views.create_subtask, name='create_subtask'),
    path('ticket/<int:pk>/response-request/new/', views.create_response_request, name='create_response_request'),
    path('subtask/<int:subtask_id>/update/', views.update_subtask, name='update_subtask'),
    # Response team (Forensic / Red Team) — "My Requests" work queue
    path('response-requests/', views.response_request_queue, name='response_request_queue'),
    path('history/', views.ticket_history, name='ticket_history'),
    # Triage
    # My Queue — Tier 1's single work queue. The historical 'triage_list' name
    # stays on the same view so every manual-triage redirect and deep link
    # keeps working; 'my_queue' is the canonical name the sidebar uses.
    path('my-queue/', views.triage_list, name='my_queue'),
    path('triage/', views.triage_list, name='triage_list'),
    path('triage/new/', views.create_triage, name='create_triage'),
    path('triage/<int:triage_id>/claim/', views.claim_manual_triage, name='claim_manual_triage'),
    path('triage/<int:triage_id>/release/', views.release_manual_triage, name='release_manual_triage'),
    path('triage/<int:triage_id>/dismiss/', views.dismiss_manual_triage, name='dismiss_manual_triage'),
    # System Owner
    path('my-tickets/', views.system_owner_dashboard, name='system_owner_dashboard'),
]
