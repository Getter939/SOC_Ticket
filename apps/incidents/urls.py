from django.urls import path
from . import views
from .cancellation_views import ticket_cancellation
from . import ti_platform_views as ti_views

urlpatterns = [
    path('ticket/<int:pk>/cancellation/', ticket_cancellation, name='ticket_cancellation'),
    path('ioc-database/', ti_views.ioc_database, name='ioc_database'),
    path('ioc-database/add/', ti_views.ioc_manual_add, name='ioc_manual_add'),
    path('ioc-database/edit/', ti_views.ioc_manual_edit, name='ioc_manual_edit'),
    path('ioc-database/status/', ti_views.ioc_status_toggle, name='ioc_status_toggle'),
    path('ioc-database/note/', ti_views.ioc_note_save, name='ioc_note_save'),
    path('ioc-database/remove/', ti_views.analyst_ioc_remove, name='analyst_ioc_remove'),
    # Tickets
    path('', views.ticket_list, name='ticket_list'),
    path('manager-queue/', views.manager_queue, name='manager_queue'),
    path('new/', views.create_ticket, name='create_ticket'),
    # Project Incident (Case Bundling) — one incident → many linked tickets
    path('project-incident/new/', views.create_project_incident, name='create_project_incident'),
    path('project-incident/<int:pk>/', views.project_incident_detail, name='project_incident_detail'),
    path('project-attachment/<int:attachment_id>/download/', views.download_project_attachment, name='download_project_attachment'),
    path('project-attachment/<int:attachment_id>/preview/', views.preview_project_attachment, name='preview_project_attachment'),
    # Shared bundle evidence — same lifecycle as ticket attachments.
    path('project-incident/<int:pk>/attachment/', views.upload_project_attachment, name='upload_project_attachment'),
    path('project-attachment/<int:attachment_id>/delete/', views.delete_project_attachment, name='delete_project_attachment'),
    path('project-attachment/<int:attachment_id>/restore/', views.restore_project_attachment, name='restore_project_attachment'),
    path('lookup/ip/', views.ip_lookup, name='ip_lookup'),
    path('search/', views.global_search, name='global_search'),
    path('ticket/<int:pk>/', views.ticket_detail, name='ticket_detail'),
    path('ticket/<int:pk>/report/docx/', views.ticket_report_docx, name='ticket_report_docx'),
    path('ticket/<int:pk>/report/pdf/', views.ticket_report_pdf, name='ticket_report_pdf'),
    path('ticket/<int:pk>/report/preview/', views.ticket_report_preview, name='ticket_report_preview'),
    path('ticket/<int:pk>/upload/', views.upload_attachment, name='upload_attachment'),
    path('attachment/<int:attachment_id>/delete/', views.delete_attachment, name='delete_attachment'),
    path('ticket/<int:pk>/edit/', views.edit_ticket, name='edit_ticket'),
    path('attachment/<int:attachment_id>/restore/', views.restore_attachment, name='restore_attachment'),
    path('evidence/staged/<int:pk>/discard/', views.discard_staged_attachment, name='discard_staged_attachment'),
    path('evidence/staged/<int:pk>/restore/', views.restore_staged_attachment, name='restore_staged_attachment'),
    path('attachment/<int:attachment_id>/download/', views.download_attachment, name='download_attachment'),
    path('attachment/<int:attachment_id>/preview/', views.preview_attachment, name='preview_attachment'),
    path('log/edit/<int:log_id>/', views.edit_log, name='edit_log'),
    path('ticket/<int:pk>/response-request/new/', views.create_response_request, name='create_response_request'),
    path('subtask/<int:subtask_id>/update/', views.update_subtask, name='update_subtask'),
    path('subtask/<int:subtask_id>/accept/', views.accept_subtask, name='accept_subtask'),
    # The retired RCA workspace — links in already-sent emails land on the ticket.
    path('rca/<int:subtask_id>/', views.legacy_rca_workspace, name='legacy_rca_workspace'),
    # Response team (Forensic / Red Team) — "My Requests" work queue
    path('response-requests/', views.response_request_queue, name='response_request_queue'),
    path('history/', views.ticket_history, name='ticket_history'),
    # Bulk PDF export of the filtered list (POST, SOC only) — a ZIP, streamed.
    path('reports/active.zip', views.ticket_list_reports_pdf, name='ticket_list_reports_pdf'),
    path('history/reports.zip', views.ticket_history_reports_pdf, name='ticket_history_reports_pdf'),
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
    # Tier 2 queue — moved here from apps/wazuh_ingest on 2026-09-23 (it had
    # nothing to do with Wazuh; see views/tier2_queue.py). The URL names are
    # the historical ones, so every reverse() and {% url %} is unchanged.
    path('tier2-queue/', views.escalation_queue, name='escalation_queue'),
    path('tier2-queue/claim/', views.claim_escalation, name='claim_escalation'),
    path('tier2-queue/release/', views.release_escalation, name='release_escalation'),
    # System Owner
    path('my-tickets/', views.system_owner_dashboard, name='system_owner_dashboard'),
]
