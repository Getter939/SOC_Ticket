from django.urls import path
from . import views
from . import mfa_views

urlpatterns = [
    path('2fa/setup/', mfa_views.SetupView.as_view(), name='mfa_setup'),
    path('2fa/verify/', mfa_views.VerifyView.as_view(), name='mfa_verify'),
    path('2fa/recovery-codes/', mfa_views.RecoveryCodesView.as_view(), name='mfa_recovery_codes'),
    path('password/change/', views.AccountPasswordChangeView.as_view(), name='password_change'),
    path('password/change/done/', views.PasswordChangeDoneView.as_view(), name='password_change_done'),
]
