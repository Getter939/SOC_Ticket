from django.contrib import admin
from .models import Project, Task


class TaskInline(admin.TabularInline):
    model = Task
    extra = 1
    fields = ('title', 'assignee', 'priority', 'status', 'due_date')


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'customer', 'status', 'created_by', 'created_at')
    list_filter = ('status',)
    search_fields = ('name',)
    inlines = [TaskInline]


@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'project', 'assignee', 'priority', 'status', 'due_date')
    list_filter = ('status', 'priority')
    search_fields = ('title', 'project__name')
