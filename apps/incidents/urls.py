from django.urls import path
from . import views

urlpatterns = [
    path('', views.ticket_list, name='ticket_list'),
    path('new/', views.create_ticket, name='create_ticket'),
    path('ticket/<int:pk>/', views.ticket_detail, name='ticket_detail'),
    path('log/edit/<int:log_id>/', views.edit_log, name='edit_log'),
    path('history/', views.ticket_history, name='ticket_history'),
    path('export/excel/', views.export_tickets_excel, name='export_tickets_excel'),
]
