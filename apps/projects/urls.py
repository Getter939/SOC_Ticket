from django.urls import path
from . import views

urlpatterns = [
    path('', views.project_list, name='project_list'),
    path('new/', views.create_project, name='create_project'),
    path('<int:pk>/', views.project_detail, name='project_detail'),
    path('<int:pk>/edit/', views.edit_project, name='edit_project'),
    path('task/<int:task_id>/status/', views.update_task_status, name='update_task_status'),
    path('task/<int:task_id>/delete/', views.delete_task, name='delete_task'),
]
