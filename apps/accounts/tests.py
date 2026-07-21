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
from urllib.parse import urlsplit
from unittest.mock import patch

from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .models import PasswordChangeAudit


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
