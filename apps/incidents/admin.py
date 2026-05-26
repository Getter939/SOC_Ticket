from django.contrib import admin
from .models import Ticket, TicketLog


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('ticket_id', 'device_name', 'status', 'category', 'issue_type', 'assigned_to', 'created_by', 'created_at')
    list_filter = ('status', 'category', 'issue_type', 'created_at')
    search_fields = ('ticket_id', 'device_name', 'ip_address',
                     'assigned_to__username', 'assigned_to__first_name')
    readonly_fields = ('ticket_id', 'created_at', 'updated_at')
    raw_id_fields = ('assigned_to', 'created_by')


@admin.register(TicketLog)
class TicketLogAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'author', 'status_at_time', 'created_at')
    list_filter = ('status_at_time',)
    search_fields = ('ticket__ticket_id', 'author__username', 'author__first_name', 'note')
    raw_id_fields = ('author',)
