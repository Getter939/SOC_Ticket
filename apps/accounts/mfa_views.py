import base64
from io import BytesIO
import time

import qrcode
from django import forms
from django.contrib.auth import authenticate, views as auth_views
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django_otp import DEVICE_ID_SESSION_KEY

from . import mfa
from .models import AuthenticatorDevice


class CodeForm(forms.Form):
    code = forms.CharField(
        label='Authenticator or recovery code',
        max_length=64,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control form-control-lg',
                'autocomplete': 'one-time-code',
                'autofocus': True,
                'spellcheck': 'false',
                'autocapitalize': 'off',
            }
        ),
    )


class EnrollmentForm(CodeForm):
    code = forms.RegexField(
        regex=r'^[0-9]{6}$',
        label='6-digit authenticator code',
        widget=forms.TextInput(
            attrs={
                'class': 'form-control form-control-lg',
                'autocomplete': 'one-time-code',
                'inputmode': 'numeric',
                'maxlength': '6',
                'pattern': '[0-9]{6}',
                'autofocus': True,
            }
        ),
        error_messages={'invalid': 'Enter the six digits shown in your authenticator app.'},
    )


class ReauthenticateForm(CodeForm):
    password = forms.CharField(
        label='Current password',
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'autocomplete': 'current-password',
            }
        ),
    )


@method_decorator(never_cache, name='dispatch')
class MFALoginView(auth_views.LoginView):
    def get_success_url(self):
        if not mfa.enforcement_enabled():
            # 2FA off: land on the normal post-login destination, no enrolment.
            return super().get_success_url()
        if mfa.is_verified(self.request):
            return mfa.safe_destination(self.request, self.get_redirect_url())
        from django.urls import reverse

        enrolled = AuthenticatorDevice.objects.filter(
            user=self.request.user, confirmed=True
        ).exists()
        return reverse('mfa_verify' if enrolled else 'mfa_setup')

    def form_valid(self, form):
        self.request.session.pop(DEVICE_ID_SESSION_KEY, None)
        self.request.session.pop(mfa.CODE_BUNDLE, None)
        self.request.session.pop(mfa.SETUP_ID, None)
        self.request.session[mfa.NEXT_URL] = mfa.safe_destination(
            self.request, self.get_redirect_url()
        )
        response = super().form_valid(form)
        self.request.session[mfa.PASSWORD_AT] = time.time()
        return response


@method_decorator(never_cache, name='dispatch')
@method_decorator(sensitive_post_parameters(), name='dispatch')
class SetupView(View):
    def get(self, request):
        device = AuthenticatorDevice.objects.filter(user=request.user).first()
        if device and device.confirmed:
            return redirect('home' if request.mfa_complete else 'mfa_verify')
        if not device or str(device.setup_id) != request.session.get(mfa.SETUP_ID):
            return render(request, 'accounts/mfa_setup.html', {'form': None})
        return self.show(request, device, EnrollmentForm())

    def post(self, request):
        if request.POST.get('action') == 'start':
            device = mfa.begin_setup(request)
            return redirect('mfa_verify' if device.confirmed else 'mfa_setup')
        form = EnrollmentForm(request.POST)
        if form.is_valid():
            if mfa.verify(request, form.cleaned_data['code'], enrollment=True):
                return redirect('mfa_recovery_codes')
            form.add_error(
                'code',
                'Code could not be verified. Wait for a new code, check your phone’s automatic time setting, and try again. Repeated attempts are temporarily limited.',
            )
        device = AuthenticatorDevice.objects.filter(user=request.user, confirmed=False).first()
        if not device or str(device.setup_id) != request.session.get(mfa.SETUP_ID):
            return redirect('mfa_setup')
        return self.show(request, device, form)

    @sensitive_variables()
    def show(self, request, device, form):
        output = BytesIO()
        qrcode.make(device.config_url).save(output, format='PNG')
        return render(
            request,
            'accounts/mfa_setup.html',
            {
                'form': form,
                'secret': device.secret,
                'qr_code': base64.b64encode(output.getvalue()).decode('ascii'),
            },
        )


@method_decorator(never_cache, name='dispatch')
@method_decorator(sensitive_post_parameters(), name='dispatch')
class VerifyView(View):
    def get(self, request):
        if request.mfa_complete:
            return redirect('home')
        if not AuthenticatorDevice.objects.filter(user=request.user, confirmed=True).exists():
            return redirect('mfa_setup')
        return render(request, 'accounts/mfa_verify.html', {'form': CodeForm()})

    def post(self, request):
        form = CodeForm(request.POST)
        if form.is_valid():
            device = mfa.verify(request, form.cleaned_data['code'])
            if device:
                if not device.recovery_codes_confirmed:
                    return redirect('mfa_recovery_codes')
                return redirect(
                    mfa.safe_destination(request, request.session.pop(mfa.NEXT_URL, ''))
                )
            form.add_error(
                'code',
                'Code could not be verified. Wait for a new code and try again, or use an unused recovery code. Repeated attempts are temporarily limited.',
            )
        return render(request, 'accounts/mfa_verify.html', {'form': form})


@method_decorator(never_cache, name='dispatch')
@method_decorator(sensitive_post_parameters(), name='dispatch')
class RecoveryCodesView(View):
    def get(self, request):
        if not mfa.is_verified(request):
            return redirect('mfa_verify')
        device = request.user.otp_device
        codes = mfa.recovery_bundle(request, device)
        return render(
            request,
            'accounts/mfa_recovery_codes.html',
            {
                'codes': codes,
                'form': None if codes else ReauthenticateForm(),
                'remaining': device.recovery_codes.count(),
            },
        )

    def post(self, request):
        if not mfa.is_verified(request):
            return redirect('mfa_verify')
        device = request.user.otp_device
        if request.POST.get('action') == 'acknowledge':
            with transaction.atomic():
                device = (
                    AuthenticatorDevice.objects.select_for_update().filter(pk=device.pk).first()
                )
                if device is None:
                    return redirect('login')
                if mfa.recovery_bundle(request, device) and request.POST.get('saved') == 'yes':
                    device.recovery_codes_confirmed = True
                    device.save(update_fields=['recovery_codes_confirmed'])
                    request.session.pop(mfa.CODE_BUNDLE, None)
                    return redirect(
                        mfa.safe_destination(request, request.session.pop(mfa.NEXT_URL, ''))
                    )
            return self.get(request)
        form = ReauthenticateForm(request.POST)
        if form.is_valid():
            # authenticate() keeps Axes' password lockout protections in this
            # sensitive account-management flow as well as the main login.
            user = authenticate(
                request,
                username=request.user.get_username(),
                password=form.cleaned_data['password'],
            )
            if user and mfa.replace_recovery_codes(request, form.cleaned_data['code']):
                return redirect('mfa_recovery_codes')
            form.add_error(
                None, 'Password or code could not be verified. Please wait before trying again.'
            )
        return render(
            request,
            'accounts/mfa_recovery_codes.html',
            {
                'form': form,
                'remaining': device.recovery_codes.count(),
            },
        )
