from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='home'),
    path('executive/', views.executive_dashboard, name='executive_dashboard'),
]
