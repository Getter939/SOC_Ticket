"""
Security-hardening tests for HTTP response headers, HTTPS enforcement, and
cookie attributes.

These cover the scanner findings remediated centrally in config/settings.py and
config/middleware.py:

  - CWE-1021  Clickjacking      → CSP frame-ancestors + X-Frame-Options
  - CWE-319   Cleartext transit → HTTP → HTTPS redirect on login/sensitive routes
  - CWE-311   Login encryption  → login form/POST cannot stay on plain HTTP
  - CWE-539   Persistent cookie → session/auth cookie is Secure/HttpOnly/SameSite
                                   and session-only (no Expires/Max-Age)

The HTTPS-dependent settings (SECURE_SSL_REDIRECT, *_COOKIE_SECURE) default OFF
so internal-HTTP deployments keep working; the tests that exercise them turn
them on with override_settings to prove the production configuration behaves.
"""
import re
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.test import Client, RequestFactory, TestCase, override_settings
from django.contrib.messages.storage.fallback import FallbackStorage
from django.urls import reverse

from axes.models import AccessAttempt

from .admin import AccessAttemptAdmin
from .models import AccountLockoutAudit, PasswordChangeAudit


class AntiFramingHeaderTest(TestCase):
    """CWE-1021: every page must carry anti-framing headers centrally."""

    def test_csp_frame_ancestors_present_on_login_page(self):
        resp = self.client.get(reverse('login'))
        self.assertEqual(resp.status_code, 200)
        csp = resp.headers.get('Content-Security-Policy', '')
        self.assertIn("frame-ancestors", csp)
        # This app should never be framed.
        self.assertIn("frame-ancestors 'none'", csp)

    def test_x_frame_options_present_on_login_page(self):
        resp = self.client.get(reverse('login'))
        self.assertEqual(resp.headers.get('X-Frame-Options'), 'DENY')

    def test_headers_present_on_sensitive_route(self):
        """Anti-framing applies to sensitive routes too — the middleware runs on
        every response, including the login redirect a gated route emits."""
        resp = self.client.get(reverse('home'))  # 302 → login when unauthenticated
        self.assertIn("frame-ancestors 'none'",
                      resp.headers.get('Content-Security-Policy', ''))
        self.assertEqual(resp.headers.get('X-Frame-Options'), 'DENY')


class HttpsEnforcementTest(TestCase):
    """CWE-319 / CWE-311: login and sensitive routes must not stay on HTTP."""

    @override_settings(SECURE_SSL_REDIRECT=True)
    def test_http_login_get_redirects_to_https(self):
        resp = self.client.get(reverse('login'))
        self.assertIn(resp.status_code, (301, 302))
        self.assertTrue(resp['Location'].startswith('https://'),
                        msg=f"expected https redirect, got {resp['Location']}")

    @override_settings(SECURE_SSL_REDIRECT=True)
    def test_http_login_post_redirects_to_https_before_processing(self):
        """An insecure credential POST is redirected to HTTPS, not processed in clear text."""
        resp = self.client.post(
            reverse('login'),
            {'username': 'someone', 'password': 'secret-not-logged'},
        )
        self.assertIn(resp.status_code, (301, 302))
        self.assertTrue(resp['Location'].startswith('https://'))

    @override_settings(SECURE_SSL_REDIRECT=True)
    def test_http_sensitive_route_redirects_to_https(self):
        resp = self.client.get(reverse('home'))
        self.assertIn(resp.status_code, (301, 302))
        self.assertTrue(resp['Location'].startswith('https://'))


class LoginFormActionTest(TestCase):
    """CWE-311: the rendered login form must not hardcode an http:// action."""

    def test_login_form_action_is_not_plain_http(self):
        html = self.client.get(reverse('login')).content.decode()
        # The form uses a relative/empty action (posts back to the HTTPS page),
        # so there must be no absolute http:// form action.
        self.assertNotIn('action="http://', html)
        self.assertIn('<form method="post"', html)


class SessionCookieSecurityTest(TestCase):
    """CWE-539: the session/auth cookie must be hardened and session-only."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='cookie_user', password='pw-correct-horse')

    def _login_and_get_session_cookie(self):
        self.client.post(
            reverse('login'),
            {'username': 'cookie_user', 'password': 'pw-correct-horse'},
        )
        self.assertIn('sessionid', self.client.cookies)
        return self.client.cookies['sessionid']

    def test_session_cookie_is_httponly(self):
        self.assertTrue(self._login_and_get_session_cookie()['httponly'])

    def test_session_cookie_samesite(self):
        self.assertEqual(
            self._login_and_get_session_cookie()['samesite'].lower(), 'lax')

    def test_session_cookie_is_session_only_not_persistent(self):
        """No Expires and no Max-Age → discarded when the browser closes."""
        cookie = self._login_and_get_session_cookie()
        self.assertEqual(cookie['expires'], '')
        self.assertEqual(str(cookie['max-age']), '')

    @override_settings(SESSION_COOKIE_SECURE=True)
    def test_session_cookie_secure_when_enabled(self):
        self.assertTrue(self._login_and_get_session_cookie()['secure'])


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    PASSWORD_RESET_RATE_LIMIT_PER_EMAIL=3,
    PASSWORD_RESET_RATE_LIMIT_PER_IP=100,
)
class PasswordManagementSecurityTest(TestCase):
    """Regression tests for self-service password management controls."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='password_user',
            email='password.user@example.test',
            password='OldPassword!123',
        )

    def _request_reset(self, email=None, client=None):
        return (client or self.client).post(
            reverse('password_reset'),
            {'email': email or self.user.email},
        )

    def _complete_reset(self, password='NewPassword!456'):
        self._request_reset()
        match = re.search(r'https?://[^\s]+', mail.outbox[-1].body)
        self.assertIsNotNone(match)
        reset_path = urlsplit(match.group()).path

        start_response = self.client.get(reset_path)
        self.assertEqual(start_response.status_code, 302)
        finish_response = self.client.post(
            start_response['Location'],
            {'new_password1': password, 'new_password2': password},
        )
        self.assertRedirects(finish_response, reverse('password_reset_complete'))
        return reset_path

    def test_password_change_requires_current_password_and_updates_session(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse('password_change'),
            {
                'old_password': 'OldPassword!123',
                'new_password1': 'NewPassword!456',
                'new_password2': 'NewPassword!456',
            },
        )

        self.assertRedirects(response, reverse('password_change_done'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewPassword!456'))
        # PasswordChangeView updates this session's auth hash so the user does
        # not get unexpectedly logged out of the password-change screen.
        self.assertEqual(
            self.client.session['_auth_user_hash'], self.user.get_session_auth_hash()
        )
        audit = PasswordChangeAudit.objects.get(
            user=self.user,
            source=PasswordChangeAudit.SOURCE_SELF_SERVICE_CHANGE,
        )
        self.assertEqual(audit.actor, self.user)

    def test_password_change_enforces_minimum_length(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse('password_change'),
            {
                'old_password': 'OldPassword!123',
                'new_password1': 'too-short',
                'new_password2': 'too-short',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This password is too short')
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('OldPassword!123'))

    def test_reset_response_does_not_reveal_account_existence(self):
        known = self._request_reset()
        unknown = self._request_reset('unknown@example.test')

        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known['Location'], unknown['Location'])
        self.assertEqual(len(mail.outbox), 1)

    def test_reset_link_is_single_use_and_invalidates_other_sessions(self):
        other_session = Client()
        self.assertTrue(other_session.login(
            username='password_user', password='OldPassword!123'
        ))

        reset_path = self._complete_reset()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewPassword!456'))
        audit = PasswordChangeAudit.objects.get(
            user=self.user,
            source=PasswordChangeAudit.SOURCE_SELF_SERVICE_RESET,
        )
        self.assertIsNone(audit.actor)

        # Auth-hash rotation forces every pre-existing session to reauthenticate.
        response = other_session.get(reverse('home'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response['Location'])

        used_link = Client().get(reset_path)
        self.assertEqual(used_link.status_code, 200)
        self.assertContains(used_link, 'invalid or expired')

    def test_reset_link_expires_after_the_configured_timeout(self):
        self._request_reset()
        match = re.search(r'https?://[^\s]+', mail.outbox[-1].body)
        reset_path = urlsplit(match.group()).path

        future = default_token_generator._now() + timedelta(hours=2)
        with patch.object(default_token_generator, '_now', return_value=future):
            response = Client().get(reset_path)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'invalid or expired')

    def test_reset_requests_are_limited_per_email(self):
        for _ in range(4):
            response = self._request_reset()
            self.assertRedirects(response, reverse('password_reset_done'))

        self.assertEqual(len(mail.outbox), 3)


class PasswordChangeAuditTest(TestCase):
    """Every supported password-update route records non-sensitive attribution."""

    def test_direct_password_save_is_recorded_as_system_change(self):
        user = User.objects.create_user('audit_system_user', password='OldPassword!123')
        PasswordChangeAudit.objects.filter(user=user).delete()

        user.set_password('NewPassword!456')
        user.save(update_fields=['password'])

        audit = PasswordChangeAudit.objects.get(user=user)
        self.assertEqual(audit.source, PasswordChangeAudit.SOURCE_SYSTEM)
        self.assertIsNone(audit.actor)

    def test_admin_password_change_records_the_admin_actor(self):
        admin_user = User.objects.create_superuser(
            'audit_admin', 'audit-admin@example.test', 'AdminPassword!123',
        )
        target = User.objects.create_user(
            'audit_target', 'audit-target@example.test', 'OldPassword!123',
        )
        PasswordChangeAudit.objects.filter(user=target).delete()
        self.client.force_login(admin_user)

        response = self.client.post(
            reverse('admin:auth_user_password_change', args=(target.pk,)),
            {
                'password1': 'NewPassword!456',
                'password2': 'NewPassword!456',
            },
        )

        self.assertEqual(response.status_code, 302)
        audit = PasswordChangeAudit.objects.get(user=target)
        self.assertEqual(audit.source, PasswordChangeAudit.SOURCE_ADMIN)
        self.assertEqual(audit.actor, admin_user)


class AccountLockoutAdminTest(TestCase):
    """Manual Axes resets must be precise, privileged, and auditable."""

    def setUp(self):
        self.factory = RequestFactory()
        self.admin_user = User.objects.create_superuser(
            'unlock_admin', 'unlock-admin@example.test', 'AdminPassword!123',
        )
        self.target = User.objects.create_user(
            'locked_user', 'locked-user@example.test', 'UserPassword!123',
        )
        self.model_admin = AccessAttemptAdmin(AccessAttempt, admin.site)

    def _request(self, user, **data):
        request = self.factory.post('/admin/axes/accessattempt/', data)
        request.user = user
        request.session = self.client.session
        request._messages = FallbackStorage(request)
        return request

    def test_unlock_clears_only_selected_username_ip_pair_and_records_reason(self):
        request = self._request(
            self.admin_user,
            confirm_unlock='yes',
            reason='Identity verified by the service desk.',
        )
        attempt = SimpleNamespace(
            username=self.target.username,
            ip_address='203.0.113.45',
        )

        with patch('apps.accounts.admin.reset_axes_attempts', return_value=2) as reset:
            response = self.model_admin.unlock_selected_lockouts(request, [attempt])

        self.assertIsNone(response)
        reset.assert_called_once_with(username=self.target.username, ip='203.0.113.45')
        audit = AccountLockoutAudit.objects.get()
        self.assertEqual(audit.user, self.target)
        self.assertEqual(audit.username, self.target.username)
        self.assertEqual(audit.ip_address, '203.0.113.45')
        self.assertEqual(audit.actor, self.admin_user)
        self.assertEqual(audit.reason, 'Identity verified by the service desk.')
        self.assertEqual(audit.attempts_cleared, 2)

    def test_unlock_requires_a_reason(self):
        request = self._request(self.admin_user, confirm_unlock='yes', reason='')
        attempt = SimpleNamespace(
            pk=1,
            username=self.target.username,
            ip_address='203.0.113.45',
            failures_since_start=5,
            attempt_time='2026-08-04 10:00:00',
        )

        with patch('apps.accounts.admin.reset_axes_attempts') as reset:
            response = self.model_admin.unlock_selected_lockouts(request, [attempt])

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'A reason is required')
        reset.assert_not_called()
        self.assertFalse(AccountLockoutAudit.objects.exists())

    def test_non_superuser_cannot_unlock_an_account(self):
        staff_user = User.objects.create_user(
            'staff_only', 'staff@example.test', 'StaffPassword!123', is_staff=True,
        )
        request = self._request(
            staff_user,
            confirm_unlock='yes',
            reason='This must not be accepted.',
        )
        attempt = SimpleNamespace(
            username=self.target.username,
            ip_address='203.0.113.45',
        )

        with patch('apps.accounts.admin.reset_axes_attempts') as reset:
            response = self.model_admin.unlock_selected_lockouts(request, [attempt])

        self.assertIsNone(response)
        reset.assert_not_called()
        self.assertFalse(AccountLockoutAudit.objects.exists())


class DjangoAdminAccessByRoleTest(TestCase):
    """K13: /admin/ is for SOC Managers and superusers only.

    Nothing in this codebase ever assigns ``is_staff`` — every flag in a live
    database was set by hand. These tests pin the RULE; ``manage.py
    audit_staff_flags`` is what checks the live roster against it.
    """

    @classmethod
    def setUpTestData(cls):
        from apps.accounts.models import UserProfile

        def _make(username, role, **flags):
            user = User.objects.create_user(
                username, f'{username}@example.test', 'AdminAccess!123', **flags,
            )
            UserProfile.objects.create(
                user=user, department='Test', phone='000', role=role,
            )
            return user

        cls.system_admin = _make('k13_sysadmin', UserProfile.ROLE_SYSTEM_ADMIN)
        cls.tier2 = _make('k13_t2', UserProfile.ROLE_SOC_STAFF, )
        cls.tier2.profile.tier = UserProfile.TIER_T2
        cls.tier2.profile.save(update_fields=['tier'])
        cls.soc_manager = _make(
            'k13_manager', UserProfile.ROLE_SOC_MANAGER, is_staff=True,
        )

    def _get_admin_index(self, user):
        self.client.force_login(user)
        return self.client.get('/admin/', follow=False)

    def test_system_admin_is_bounced_to_the_admin_login(self):
        response = self._get_admin_index(self.system_admin)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response['Location'])

    def test_tier2_analyst_is_bounced_to_the_admin_login(self):
        response = self._get_admin_index(self.tier2)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response['Location'])

    def test_soc_manager_with_is_staff_reaches_the_admin(self):
        self.assertEqual(self._get_admin_index(self.soc_manager).status_code, 200)

    def test_a_soc_role_alone_does_not_grant_admin_access(self):
        # The role is not what opens /admin/ — is_staff is. Strip the flag from
        # the manager and the door closes, confirming no role->is_staff mapping
        # has crept in.
        self.soc_manager.is_staff = False
        self.soc_manager.save(update_fields=['is_staff'])
        response = self._get_admin_index(self.soc_manager)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response['Location'])


class AuditStaffFlagsCommandTest(TestCase):
    """The live-data half of K13."""

    @staticmethod
    def _run(**kwargs):
        from io import StringIO
        from django.core.management import call_command

        out, err = StringIO(), StringIO()
        try:
            call_command('audit_staff_flags', stdout=out, stderr=err, **kwargs)
            code = 0
        except SystemExit as exc:
            code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_passes_when_only_superusers_and_soc_managers_hold_is_staff(self):
        from apps.accounts.models import UserProfile

        User.objects.create_superuser('af_root', 'r@example.test', 'Pw!123456789')
        mgr = User.objects.create_user(
            'af_mgr', 'm@example.test', 'Pw!123456789', is_staff=True,
        )
        UserProfile.objects.create(
            user=mgr, department='T', phone='0', role=UserProfile.ROLE_SOC_MANAGER,
        )

        code, out, _ = self._run()
        self.assertEqual(code, 0)
        self.assertIn('af_root', out)
        self.assertIn('af_mgr', out)

    def test_fails_on_an_unexpected_staff_account(self):
        from apps.accounts.models import UserProfile

        stray = User.objects.create_user(
            'af_stray', 's@example.test', 'Pw!123456789', is_staff=True,
        )
        UserProfile.objects.create(
            user=stray, department='T', phone='0',
            role=UserProfile.ROLE_SYSTEM_ADMIN,
        )

        code, _, err = self._run()
        self.assertEqual(code, 1)
        self.assertIn('af_stray', err)

    def test_profileless_staff_account_is_reported(self):
        User.objects.create_user(
            'af_noprofile', 'n@example.test', 'Pw!123456789', is_staff=True,
        )
        code, _, err = self._run()
        self.assertEqual(code, 1)
        self.assertIn('af_noprofile', err)

    def test_command_never_mutates_flags(self):
        stray = User.objects.create_user(
            'af_readonly', 'ro@example.test', 'Pw!123456789', is_staff=True,
        )
        self._run()
        stray.refresh_from_db()
        self.assertTrue(stray.is_staff)
