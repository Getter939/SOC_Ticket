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
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse


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
