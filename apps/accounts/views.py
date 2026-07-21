import logging

from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import PasswordResetForm
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy

from .models import PasswordChangeAudit
from .password_audit import password_audit_context
from .passwords import (
    password_reset_request_allowed,
    send_password_changed_notification,
    send_password_reset_email,
)


logger = logging.getLogger(__name__)


class AccountPasswordResetForm(PasswordResetForm):
    """Django's reset form with project-owned delivery for consistent emails."""

    def save(self, *, request, **kwargs):
        for user in self.get_users(self.cleaned_data['email']):
            send_password_reset_email(user=user, request=request)


class ThrottledPasswordResetView(auth_views.PasswordResetView):
    form_class = AccountPasswordResetForm
    template_name = 'registration/password_reset_form.html'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        # Keep the public response identical whether the address is valid,
        # unknown, inactive, or rate-limited to avoid account enumeration.
        if password_reset_request_allowed(self.request, form.cleaned_data['email']):
            try:
                form.save(request=self.request)
            except Exception:
                # SMTP failures must not identify an account or expose server
                # details to the requester. Do not log SMTP exception details:
                # they may contain the recipient address.
                logger.error('Unable to send password reset email')
        else:
            logger.warning('Password reset request rate limit reached')
        return HttpResponseRedirect(self.get_success_url())


class AccountPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = 'registration/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

    def form_valid(self, form):
        with password_audit_context(
            source=PasswordChangeAudit.SOURCE_SELF_SERVICE_RESET,
        ):
            response = super().form_valid(form)
        send_password_changed_notification(user=form.user)
        return response


class AccountPasswordChangeView(auth_views.PasswordChangeView):
    template_name = 'registration/password_change_form.html'
    success_url = reverse_lazy('password_change_done')

    def form_valid(self, form):
        with password_audit_context(
            source=PasswordChangeAudit.SOURCE_SELF_SERVICE_CHANGE,
            actor=self.request.user,
        ):
            response = super().form_valid(form)
        send_password_changed_notification(user=self.request.user)
        messages.success(self.request, 'Your password has been changed.')
        return response


class PasswordChangeDoneView(auth_views.PasswordChangeDoneView):
    template_name = 'registration/password_change_done.html'
