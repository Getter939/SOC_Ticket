from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.db.models import Count, Q

from .forms import ProjectForm, TaskForm
from .models import Project, Task


def _has_soc_access(user):
    profile = getattr(user, 'profile', None)
    return user.is_superuser or (profile is not None and profile.is_soc)


@login_required
def project_list(request):
    projects = Project.objects.select_related('customer').annotate(
        total_tasks=Count('tasks'),
        done_tasks=Count('tasks', filter=Q(tasks__status='Done')),
    )
    stats = {
        'total': projects.count(),
        'active': projects.filter(status='Active').count(),
        'planning': projects.filter(status='Planning').count(),
        'completed': projects.filter(status='Completed').count(),
    }
    return render(request, 'projects/project_list.html', {'projects': projects, 'stats': stats})


@login_required
def project_detail(request, pk):
    project = get_object_or_404(Project, pk=pk)
    tasks = project.tasks.select_related('assignee', 'ticket')
    task_stats = {
        'todo': tasks.filter(status='Todo').count(),
        'doing': tasks.filter(status='Doing').count(),
        'done': tasks.filter(status='Done').count(),
    }

    if request.method == 'POST':
        if not _has_soc_access(request.user):
            messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถสร้างงานในโปรเจกต์ได้')
            return redirect('project_detail', pk=pk)
        form = TaskForm(request.POST)
        if form.is_valid():
            task = form.save(commit=False)
            task.project = project
            task.save()
            return redirect('project_detail', pk=pk)
    else:
        form = TaskForm()

    return render(request, 'projects/project_detail.html', {
        'project': project,
        'tasks': tasks,
        'task_stats': task_stats,
        'form': form,
    })


@login_required
def create_project(request):
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถสร้างโปรเจกต์ได้')
        return redirect('project_list')

    if request.method == 'POST':
        form = ProjectForm(request.POST)
        if form.is_valid():
            project = form.save(commit=False)
            project.created_by = request.user
            project.save()
            return redirect('project_detail', pk=project.pk)
    else:
        form = ProjectForm()
    return render(request, 'projects/project_form.html', {'form': form, 'title': 'สร้างโปรเจกต์ใหม่'})


@login_required
def edit_project(request, pk):
    if not _has_soc_access(request.user):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถแก้ไขโปรเจกต์ได้')
        return redirect('project_list')

    project = get_object_or_404(Project, pk=pk)
    if request.method == 'POST':
        form = ProjectForm(request.POST, instance=project)
        if form.is_valid():
            form.save()
            return redirect('project_detail', pk=pk)
    else:
        form = ProjectForm(instance=project)
    return render(request, 'projects/project_form.html', {'form': form, 'title': 'แก้ไขโปรเจกต์', 'project': project})


@login_required
def update_task_status(request, task_id):
    """HTMX-friendly: update task status via POST."""
    task = get_object_or_404(Task, id=task_id)
    if request.method == 'POST':
        if not _has_soc_access(request.user):
            messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถอัปเดตสถานะงานได้')
            return redirect('project_detail', pk=task.project.pk)
        new_status = request.POST.get('status')
        if new_status in dict(Task.STATUS_CHOICES):
            task.status = new_status
            task.save()
    return redirect('project_detail', pk=task.project.pk)


@login_required
def delete_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    project_pk = task.project.pk
    if request.method == 'POST':
        if not _has_soc_access(request.user):
            messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถลบงานได้')
            return redirect('project_detail', pk=project_pk)
        task.delete()
    return redirect('project_detail', pk=project_pk)
