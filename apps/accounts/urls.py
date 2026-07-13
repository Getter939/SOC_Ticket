from django.urls import path
from . import views

urlpatterns = [
    path('password/change/', views.AccountPasswordChangeView.as_view(), name='password_change'),
    path('password/change/done/', views.PasswordChangeDoneView.as_view(), name='password_change_done'),
]
