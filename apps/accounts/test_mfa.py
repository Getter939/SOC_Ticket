"""Real HTTP MFA flows: no simulated verified-session client in this module."""

import base64
import hashlib
from io import StringIO
import json
import time
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.management import call_command, CommandError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.oath import TOTP

from . import mfa
from .checks import mfa_configuration
from .mfa_crypto import encrypt, decrypt
from .models import AuthenticatorDevice, MFAAudit, MFARecoveryCode, UserProfile
from .testing import TEST_MFA_KEY


@override_settings(
    MFA_ENABLED=True,
    MFA_ENCRYPTION_KEYS=[TEST_MFA_KEY],
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
)
class MFAFlowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('mfa-user', 'mfa@example.test', 'StrongPassword!123')

    def password_login(self, client=None, next_url=''):
        return (client or self.client).post(
            reverse('login'),
            {
                'username': self.user.username,
                'password': 'StrongPassword!123',
                'next': next_url,
            },
        )

    def token(self, device=None, offset=0):
        device = device or AuthenticatorDevice.objects.get(user=self.user)
        totp = TOTP(base64.b32decode(device.secret))
        totp.time = time.time() + offset * 30
        return f'{totp.token():06d}'

    def enroll(self, acknowledge=True, client=None):
        client = client or self.client
        self.password_login(client)
        client.post(reverse('mfa_setup'), {'action': 'start'})
        response = client.post(reverse('mfa_setup'), {'code': self.token()})
        self.assertEqual(response.status_code, 302)
        page = client.get(reverse('mfa_recovery_codes'))
        codes = page.context['codes']
        self.assertEqual(len(codes), 10)
        if acknowledge:
            client.post(reverse('mfa_recovery_codes'), {'action': 'acknowledge', 'saved': 'yes'})
        return codes

    def test_password_only_login_requires_setup(self):
        self.assertRedirects(self.password_login(), reverse('mfa_setup'))
        self.assertNotIn(DEVICE_ID_SESSION_KEY, self.client.session)

    def test_mfa_pages_and_validation_are_in_thai(self):
        self.password_login()
        setup = self.client.get(reverse('mfa_setup'))
        self.assertContains(setup, 'ตั้งค่าแอปยืนยันตัวตน')
        self.assertContains(setup, 'แสดงคิวอาร์โค้ดสำหรับตั้งค่า')
        self.client.post(reverse('mfa_setup'), {'action': 'start'})
        invalid = self.client.post(reverse('mfa_setup'), {'code': ''})
        self.assertContains(invalid, 'กรุณากรอกรหัสยืนยันตัวตน 6 หลัก')

    def test_wrong_password_cannot_start_setup(self):
        self.client.post(reverse('login'), {'username': self.user.username, 'password': 'wrong'})
        self.assertRedirects(
            self.client.post(reverse('mfa_setup'), {'action': 'start'}),
            reverse('login') + '?next=' + reverse('mfa_setup'),
        )
        self.assertFalse(AuthenticatorDevice.objects.exists())

    def test_enrollment_is_mandatory_for_every_role_and_superuser(self):
        for role, _ in UserProfile.ROLE_CHOICES:
            with self.subTest(role=role):
                UserProfile.objects.update_or_create(user=self.user, defaults={'role': role})
                client = Client()
                self.password_login(client)
                self.assertRedirects(client.get(reverse('home')), reverse('mfa_setup'))
        self.user.is_staff = self.user.is_superuser = True
        self.user.save()
        self.password_login()
        self.assertRedirects(self.client.get('/admin/'), reverse('mfa_setup'))

    def test_direct_routes_and_posts_are_blocked_before_mfa(self):
        self.password_login()
        routes = [
            reverse('home'),
            reverse('ticket_list'),
            reverse('create_ticket'),
            '/admin/',
            reverse('ticket_detail', args=[123]),
            reverse('download_attachment', args=[123]),
            reverse('ticket_report_pdf', args=[123]),
            reverse('ticket_report_docx', args=[123]),
            reverse('download_project_attachment', args=[123]),
            reverse('password_change'),
        ]
        for url in routes:
            for method in ('get', 'post'):
                with self.subTest(url=url, method=method):
                    self.assertEqual(getattr(self.client, method)(url).url, reverse('mfa_setup'))

    def test_admin_login_cannot_create_password_only_bypass(self):
        response = self.client.post(
            '/admin/login/', {'username': self.user.username, 'password': 'StrongPassword!123'}
        )
        self.assertEqual(response.url, reverse('login') + '?next=/admin/')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_existing_password_only_session_requires_fresh_password(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse('home')).url, '/login/?next=/')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_enrollment_expiry_requires_login_again(self):
        self.password_login()
        session = self.client.session
        session[mfa.PASSWORD_AT] = time.time() - 601
        session.save()
        self.assertEqual(
            self.client.post(reverse('mfa_setup'), {'action': 'start'}).status_code, 302
        )
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertFalse(AuthenticatorDevice.objects.exists())

    def test_unconfirmed_device_does_not_grant_access_even_with_session_marker(self):
        self.password_login()
        self.client.post(reverse('mfa_setup'), {'action': 'start'})
        device = AuthenticatorDevice.objects.get(user=self.user)
        session = self.client.session
        session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        session.save()
        self.assertEqual(self.client.get(reverse('home')).url, reverse('mfa_setup'))

    def test_qr_is_local_and_secret_is_encrypted(self):
        self.password_login()
        self.client.post(reverse('mfa_setup'), {'action': 'start'})
        response = self.client.get(reverse('mfa_setup'))
        device = AuthenticatorDevice.objects.get(user=self.user)
        self.assertContains(response, 'data:image/png;base64,')
        self.assertNotIn(device.secret, device.encrypted_secret)
        self.assertIn('issuer=SOC+Support+System', device.config_url)
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(response['Referrer-Policy'], 'same-origin')
        self.assertNotContains(response, '<nav id="sidebar">')
        self.assertNotIn(device.secret, json.dumps(dict(self.client.session)))

    def test_pending_secret_is_bound_to_enrollment_session(self):
        self.password_login()
        self.client.post(reverse('mfa_setup'), {'action': 'start'})
        old = AuthenticatorDevice.objects.get(user=self.user)
        old_secret = old.secret
        other = Client()
        self.password_login(other)
        self.assertNotContains(other.get(reverse('mfa_setup')), old_secret)
        other.post(reverse('mfa_setup'), {'action': 'start'})
        self.assertEqual(
            self.client.post(reverse('mfa_setup'), {'code': self.token()}).url, reverse('mfa_setup')
        )
        self.assertFalse(AuthenticatorDevice.objects.get(user=self.user).confirmed)

    def test_bad_or_expired_code_cannot_confirm_enrollment(self):
        self.password_login()
        self.client.post(reverse('mfa_setup'), {'action': 'start'})
        response = self.client.post(reverse('mfa_setup'), {'code': self.token(offset=-5)})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AuthenticatorDevice.objects.get(user=self.user).confirmed)
        self.assertTrue(MFAAudit.objects.filter(event='failed').exists())

    def test_enrollment_requires_recovery_code_acknowledgment(self):
        self.enroll(acknowledge=False)
        self.assertEqual(self.client.get(reverse('home')).url, reverse('mfa_recovery_codes'))
        self.client.post(reverse('mfa_recovery_codes'), {'action': 'acknowledge'})
        self.assertEqual(self.client.get(reverse('home')).url, reverse('mfa_recovery_codes'))
        self.client.post(reverse('mfa_recovery_codes'), {'action': 'acknowledge', 'saved': 'yes'})
        self.assertTrue(AuthenticatorDevice.objects.get(user=self.user).recovery_codes_confirmed)

    def test_recovery_codes_are_hashed_and_removed_from_session_after_ack(self):
        codes = self.enroll()
        self.assertNotIn(mfa.CODE_BUNDLE, self.client.session)
        digests = list(MFARecoveryCode.objects.values_list('digest', flat=True))
        self.assertEqual(len(digests), 10)
        for code in codes:
            self.assertIn(hashlib.sha256(code.replace('-', '').encode()).hexdigest(), digests)
        response = self.client.get(reverse('mfa_recovery_codes'))
        for code in codes:
            self.assertNotContains(response, code)

    def test_next_login_requires_code_and_consumes_recovery_code_once(self):
        codes = self.enroll()
        self.client.post(reverse('logout'))
        self.assertRedirects(self.password_login(), reverse('mfa_verify'))
        response = self.client.post(reverse('mfa_verify'), {'code': codes[0]})
        self.assertEqual(response.url, reverse('home'))
        self.assertEqual(MFARecoveryCode.objects.count(), 9)
        self.assertTrue(MFAAudit.objects.filter(event='recovery_used').exists())
        self.client.post(reverse('logout'))
        self.password_login()
        self.assertEqual(
            self.client.post(reverse('mfa_verify'), {'code': codes[0]}).status_code, 200
        )
        self.assertNotIn(DEVICE_ID_SESSION_KEY, self.client.session)

    def test_totp_is_replay_protected_across_sessions(self):
        self.enroll()
        device = AuthenticatorDevice.objects.get(user=self.user)
        self.client.post(reverse('logout'))
        self.password_login()
        self.assertEqual(
            self.client.post(reverse('mfa_verify'), {'code': self.token(device)}).status_code, 200
        )
        self.assertNotIn(DEVICE_ID_SESSION_KEY, self.client.session)

    def test_fresh_totp_completes_login_and_rotates_session(self):
        self.enroll()
        self.client.post(reverse('logout'))
        self.password_login(next_url=reverse('ticket_list'))
        before = self.client.session.session_key
        with patch('time.time', return_value=time.time() + 31):
            response = self.client.post(reverse('mfa_verify'), {'code': self.token()})
        self.assertEqual(response.url, reverse('ticket_list'))
        self.assertNotEqual(before, self.client.session.session_key)
        self.assertNotIn(mfa.PASSWORD_AT, self.client.session)

    def test_rate_limit_persists_across_logins_and_setup_restart(self):
        self.password_login()
        self.client.post(reverse('mfa_setup'), {'action': 'start'})
        self.client.post(reverse('mfa_setup'), {'code': self.token(offset=-5)})
        client = Client()
        self.password_login(client)
        client.post(reverse('mfa_setup'), {'action': 'start'})
        self.assertEqual(client.post(reverse('mfa_setup'), {'code': self.token()}).status_code, 200)
        self.assertEqual(
            AuthenticatorDevice.objects.get(user=self.user).throttling_failure_count, 1
        )

    def test_external_next_url_is_ignored(self):
        self.password_login(next_url='https://evil.example/')
        self.assertEqual(self.client.session[mfa.NEXT_URL], reverse('home'))

    def test_other_users_device_marker_is_rejected(self):
        self.enroll()
        device = AuthenticatorDevice.objects.get(user=self.user)
        other = User.objects.create_user('other', password='AnotherPassword!123')
        client = Client()
        client.force_login(other)
        session = client.session
        session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        session.save()
        self.assertTrue(client.get(reverse('home')).url.startswith('/login/'))

    def test_public_health_reset_and_logout_remain_accessible(self):
        self.assertEqual(self.client.get('/healthz').status_code, 200)
        self.assertEqual(self.client.get(reverse('password_reset')).status_code, 200)
        self.password_login()
        self.assertEqual(self.client.post(reverse('logout')).status_code, 302)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_password_reset_keeps_mfa_and_does_not_log_in(self):
        self.enroll()
        self.client.post(reverse('logout'))
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.user.refresh_from_db()
        token = default_token_generator.make_token(self.user)
        url = reverse('password_reset_confirm', args=[uid, token])
        redirected = self.client.get(url).url
        self.client.post(
            redirected,
            {
                'new_password1': 'ReplacementPassword!123',
                'new_password2': 'ReplacementPassword!123',
            },
        )
        self.assertTrue(AuthenticatorDevice.objects.get(user=self.user).confirmed)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertEqual(
            self.client.post(
                reverse('login'),
                {'username': self.user.username, 'password': 'ReplacementPassword!123'},
            ).url,
            reverse('mfa_verify'),
        )

    def test_reset_revokes_verified_sessions_and_audits_operator(self):
        self.enroll()
        actor = User.objects.create_superuser('recovery-admin', password='StrongAdminPassword!123')
        call_command(
            'reset_mfa',
            self.user.username,
            actor=actor.username,
            reason='IT-123 identity checked in person',
            stdout=StringIO(),
        )
        self.assertFalse(AuthenticatorDevice.objects.exists())
        self.assertTrue(self.client.get(reverse('home')).url.startswith('/login/'))
        audit = MFAAudit.objects.get(event='reset')
        self.assertEqual(audit.actor, actor)
        self.assertEqual(audit.reason, 'IT-123 identity checked in person')
        self.assertEqual(self.password_login().url, reverse('mfa_setup'))

    def test_reset_requires_valid_operator_and_reason(self):
        with self.assertRaises(CommandError):
            call_command(
                'reset_mfa', self.user.username, actor=self.user.username, reason='verified'
            )
        actor = User.objects.create_superuser('reset-admin', password='StrongAdminPassword!123')
        with self.assertRaises(CommandError):
            call_command('reset_mfa', self.user.username, actor=actor.username, reason=' ')

    def test_regeneration_requires_password_and_code(self):
        codes = self.enroll()
        response = self.client.post(
            reverse('mfa_recovery_codes'), {'password': 'wrong', 'code': codes[0]}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MFARecoveryCode.objects.count(), 10)
        response = self.client.post(
            reverse('mfa_recovery_codes'), {'password': 'StrongPassword!123', 'code': codes[0]}
        )
        self.assertEqual(response.url, reverse('mfa_recovery_codes'))
        new_codes = self.client.get(reverse('mfa_recovery_codes')).context['codes']
        self.assertFalse(set(codes) & set(new_codes))
        self.assertEqual(MFARecoveryCode.objects.count(), 10)
        self.assertEqual(self.client.get(reverse('home')).url, reverse('mfa_recovery_codes'))

    def test_recovery_bundle_is_encrypted_and_expires(self):
        codes = self.enroll(acknowledge=False)
        self.assertNotIn(codes[0], self.client.session[mfa.CODE_BUNDLE])
        with patch('time.time', return_value=time.time() + 601):
            response = self.client.get(reverse('mfa_recovery_codes'))
        self.assertIsNone(response.context['codes'])
        self.assertNotIn(mfa.CODE_BUNDLE, self.client.session)

    def test_stale_recovery_generation_cannot_be_acknowledged(self):
        self.enroll(acknowledge=False)
        import uuid

        AuthenticatorDevice.objects.filter(user=self.user).update(recovery_generation=uuid.uuid4())
        self.client.post(reverse('mfa_recovery_codes'), {'action': 'acknowledge', 'saved': 'yes'})
        self.assertFalse(AuthenticatorDevice.objects.get(user=self.user).recovery_codes_confirmed)

    def test_superuser_needs_mfa_then_can_access_admin(self):
        self.user.is_staff = self.user.is_superuser = True
        self.user.save()
        self.enroll()
        self.assertEqual(self.client.get('/admin/').status_code, 200)
        self.assertEqual(self.client.get('/admin/login/').url, '/admin/')

    def test_no_secrets_in_audit_records(self):
        codes = self.enroll()
        device = AuthenticatorDevice.objects.get(user=self.user)
        audit_text = str(list(MFAAudit.objects.values()))
        self.assertNotIn(device.secret, audit_text)
        for code in codes:
            self.assertNotIn(code, audit_text)

    def test_csrf_is_required_for_setup(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        session = client.session
        session[mfa.PASSWORD_AT] = time.time()
        session.save()
        self.assertEqual(client.post(reverse('mfa_setup'), {'action': 'start'}).status_code, 403)
        self.assertFalse(AuthenticatorDevice.objects.exists())

    @override_settings(AXES_ENABLED=True)
    def test_axes_still_locks_out_password_attempts(self):
        for _ in range(5):
            self.client.post(
                reverse('login'), {'username': self.user.username, 'password': 'wrong'}
            )
        self.assertEqual(self.password_login().status_code, 429)
        self.assertNotIn('_auth_user_id', self.client.session)

    @override_settings(MFA_ENCRYPTION_KEYS=[])
    def test_missing_key_fails_configuration_check(self):
        self.assertEqual(mfa_configuration(None)[0].id, 'accounts.E001')

    def test_key_rotation_can_read_old_ciphertext(self):
        encrypted = encrypt('example-secret')
        new_key = Fernet.generate_key().decode('ascii')
        with override_settings(MFA_ENCRYPTION_KEYS=[new_key, TEST_MFA_KEY]):
            self.assertEqual(decrypt(encrypted), 'example-secret')
            fresh = encrypt('new-secret')
        self.assertEqual(Fernet(new_key).decrypt(fresh.encode()).decode(), 'new-secret')


from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from django.db import connection, connections
from django.test import TransactionTestCase
from unittest import skipUnless


@skipUnless(connection.vendor == 'postgresql', 'PostgreSQL row-lock guarantees')
@override_settings(MFA_ENCRYPTION_KEYS=[TEST_MFA_KEY])
class MFAConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.user = User.objects.create_user('concurrent-mfa', password='StrongPassword!123')
        self.device = AuthenticatorDevice.objects.create(
            user=self.user,
            name='Concurrency test',
            confirmed=True,
            encrypted_secret=encrypt(base64.b32encode(b'concurrency-key-12345').decode('ascii')),
        )

    def concurrent_verify(self, token):
        barrier = Barrier(2)

        def worker():
            try:
                device = AuthenticatorDevice.objects.get(pk=self.device.pk)
                barrier.wait(timeout=10)
                return device.verify_token(token)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker) for _ in range(2)]
            return sorted(future.result(timeout=15) for future in futures)

    def test_two_simultaneous_requests_cannot_reuse_totp(self):
        totp = TOTP(base64.b32decode(self.device.secret))
        self.assertEqual(self.concurrent_verify(f'{totp.token():06d}'), [False, True])

    def test_two_simultaneous_requests_cannot_reuse_recovery_code(self):
        code = '0123456789abcdef0123456789abcdef'
        MFARecoveryCode.objects.create(
            device=self.device, digest=hashlib.sha256(code.encode()).hexdigest()
        )
        self.assertEqual(self.concurrent_verify(code), [False, True])
        self.assertFalse(MFARecoveryCode.objects.exists())


@override_settings(MFA_ENABLED=False)
class MFADisabledTests(TestCase):
    """With the feature switched off, login is password-only and no enrolment or
    verification is required — but authentication itself is still enforced."""

    def setUp(self):
        self.user = User.objects.create_user(
            'nomfa-user', 'nomfa@example.test', 'StrongPassword!123'
        )
        UserProfile.objects.create(
            user=self.user, role=UserProfile.ROLE_SOC_STAFF,
            department='Test', phone='000', tier=UserProfile.TIER_T1,
        )

    def login(self, next_url=''):
        return self.client.post(
            reverse('login'),
            {'username': self.user.username, 'password': 'StrongPassword!123', 'next': next_url},
        )

    def test_password_only_login_reaches_app_without_2fa(self):
        # Lands on the normal post-login destination, not an MFA setup page.
        self.assertRedirects(self.login(), reverse('home'), fetch_redirect_response=False)
        # A protected page renders instead of bouncing to enrolment/verification.
        self.assertEqual(self.client.get(reverse('ticket_list')).status_code, 200)
        # No authenticator device is created.
        self.assertFalse(AuthenticatorDevice.objects.exists())

    def test_unauthenticated_access_is_still_redirected_to_login(self):
        self.assertEqual(self.client.get(reverse('ticket_list')).status_code, 302)

    def test_startup_check_skips_key_requirement_when_disabled(self):
        with override_settings(MFA_ENCRYPTION_KEYS=[]):
            self.assertEqual(mfa_configuration(None), [])

    def test_mfa_ui_is_hidden_and_direct_urls_return_to_home(self):
        login_page = self.client.get(reverse('login'))
        self.assertNotContains(login_page, 'ขั้นตอนที่ 1 จาก 2')
        self.login()
        for name in ('mfa_setup', 'mfa_verify', 'mfa_recovery_codes'):
            with self.subTest(name=name):
                self.assertRedirects(self.client.get(reverse(name)), reverse('home'))
