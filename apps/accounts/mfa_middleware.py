"""Fail closed for every resolved application view, regardless of role."""

from django.contrib.auth import logout
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import redirect
from django.utils.cache import add_never_cache_headers
from django.utils.deprecation import MiddlewareMixin

from . import mfa
from .models import AuthenticatorDevice


class RequireMFAMiddleware(MiddlewareMixin):
    PUBLIC_VIEWS = frozenset(
        {
            'login',
            'logout',
            'healthz',
            'password_reset',
            'password_reset_done',
            'password_reset_confirm',
            'password_reset_complete',
        }
    )
    FLOW_VIEWS = frozenset({'mfa_setup', 'mfa_verify', 'mfa_recovery_codes'})

    def process_view(self, request, view_func, view_args, view_kwargs):
        name = request.resolver_match.view_name
        # Rendering any pre-MFA screen must not expose navigation or queue data.
        request.mfa_complete = (
            mfa.is_verified(request) and request.user.otp_device.recovery_codes_confirmed
        )
        if name == 'admin:login':
            if request.mfa_complete:
                # A fully authenticated user without staff permission must not
                # bounce forever between the two login pages.
                if not request.user.is_staff:
                    from django.http import HttpResponseForbidden

                    return HttpResponseForbidden('Django admin access is not permitted.')
                return redirect('admin:index')
            return redirect_to_login('/admin/', 'login')
        if name in self.PUBLIC_VIEWS:
            return None
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path(), 'login')
        if request.mfa_complete:
            # Retain no recoverable code bundle after the user acknowledges it.
            request.session.pop(mfa.CODE_BUNDLE, None)
            return None
        if mfa.is_verified(request):
            if name != 'mfa_recovery_codes':
                return redirect('mfa_recovery_codes')
            return None
        if not mfa.password_is_fresh(request):
            destination = mfa.safe_destination(request, request.get_full_path())
            logout(request)
            return redirect_to_login(destination, 'login')
        if name not in self.FLOW_VIEWS:
            request.session[mfa.NEXT_URL] = mfa.safe_destination(request, request.get_full_path())
            return redirect(
                'mfa_verify'
                if AuthenticatorDevice.objects.filter(user=request.user, confirmed=True).exists()
                else 'mfa_setup'
            )
        return None

    def process_response(self, request, response):
        # Prevent browser/proxy caches retaining evidence pages after logout,
        # or retaining a QR code / recovery-code response after enrollment.
        if getattr(getattr(request, 'user', None), 'is_authenticated', False):
            add_never_cache_headers(response)
        if (
            getattr(request, 'resolver_match', None)
            and request.resolver_match.view_name in self.FLOW_VIEWS
        ):
            # Chromium sends Origin: null on form POSTs from a no-referrer
            # document, breaking Django's CSRF check. Preserve same-origin
            # form submissions while withholding referrers from other sites.
            response['Referrer-Policy'] = 'same-origin'
        return response
