import sys
from datetime import timedelta
from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY')

DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = [
    h.strip() for h in config('ALLOWED_HOSTS', default='localhost,127.0.0.1').split(',')
    if h.strip()
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    # Third-party
    'axes',   # login brute-force protection / account lockout
    # Project apps
    'apps.incidents',
    'apps.accounts',
    'apps.dashboard',
    'apps.wazuh_ingest',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'config.middleware.ContentSecurityPolicyMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Must be LAST — wraps authentication to record failed logins and enforce
    # lockouts (django-axes).
    'axes.middleware.AxesMiddleware',
]

# ── Authentication backends ────────────────────────────────────────────────
# AxesStandaloneBackend MUST be first: it short-circuits authentication for a
# locked-out client before credentials are ever checked. The default
# ModelBackend follows for normal password verification.
AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'apps.wazuh_ingest.context_processors.pending_triage_count',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST'),
        'PORT': config('DB_PORT'),
        'CONN_MAX_AGE': config('DB_CONN_MAX_AGE', default=0, cast=int),
        'CONN_HEALTH_CHECKS': True,
        'OPTIONS': {
            'sslmode': config('DB_SSLMODE', default='prefer'),
        },
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Password-reset links are single-use (Django's PasswordResetTokenGenerator)
# and expire quickly to reduce the impact of a compromised mailbox or link.
PASSWORD_RESET_TIMEOUT = 60 * 60
# Limit requests by both a privacy-preserving email hash and client IP. Values
# are deliberately configurable for operational tuning without code changes.
PASSWORD_RESET_RATE_WINDOW_SECONDS = config(
    'PASSWORD_RESET_RATE_WINDOW_SECONDS', default=15 * 60, cast=int
)
PASSWORD_RESET_RATE_LIMIT_PER_EMAIL = config(
    'PASSWORD_RESET_RATE_LIMIT_PER_EMAIL', default=3, cast=int
)
PASSWORD_RESET_RATE_LIMIT_PER_IP = config(
    'PASSWORD_RESET_RATE_LIMIT_PER_IP', default=10, cast=int
)

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Bangkok'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'

MEDIA_URL  = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'home'   # → dashboard
LOGOUT_REDIRECT_URL = 'login'

# ── Security hardening ─────────────────────────────────────────────────────
# Always-on — safe over both HTTP and HTTPS:
SESSION_COOKIE_HTTPONLY = True       # session cookie unreadable from JavaScript
SESSION_COOKIE_SAMESITE = 'Lax'      # CSRF defense-in-depth
CSRF_COOKIE_SAMESITE    = 'Lax'
SECURE_CONTENT_TYPE_NOSNIFF = True   # X-Content-Type-Options: nosniff
X_FRAME_OPTIONS = 'DENY'             # clickjacking (with XFrameOptionsMiddleware)
# Session/auth cookie must be a SESSION cookie (no Expires/Max-Age) so it is
# discarded when the browser closes — there is no "remember me" feature here.
# Prevents a persistent auth cookie lingering on shared workstations (CWE-539).
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# HTTPS-dependent — turn these ON in production behind TLS via .env. They
# default OFF so an internal HTTP deployment keeps working: enabling secure
# cookies without HTTPS withholds the cookie (breaking login) and SSL_REDIRECT
# would cause redirect loops. See .env.example for the recommended prod values.
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', default=False, cast=bool)
CSRF_COOKIE_SECURE    = config('CSRF_COOKIE_SECURE',    default=False, cast=bool)
SECURE_SSL_REDIRECT   = config('SECURE_SSL_REDIRECT',   default=False, cast=bool)
SECURE_HSTS_SECONDS   = config('SECURE_HSTS_SECONDS',   default=0,     cast=int)
SECURE_HSTS_INCLUDE_SUBDOMAINS = config('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=True, cast=bool)
SECURE_HSTS_PRELOAD            = config('SECURE_HSTS_PRELOAD',            default=True, cast=bool)
# In a TLS deployment this keeps reset links HTTPS even if a proxy forwards a
# request to Django over HTTP. It follows SSL redirect by default; explicitly
# set it only for an HTTPS deployment that does not redirect every request.
PASSWORD_RESET_USE_HTTPS = config(
    'PASSWORD_RESET_USE_HTTPS', default=SECURE_SSL_REDIRECT, cast=bool
)
# Deployed behind a TLS-terminating reverse proxy (nginx/traefik) that sets
# X-Forwarded-Proto? Set USE_PROXY_SSL_HEADER=True so Django trusts it and
# request.is_secure() reflects the client→proxy leg. This is REQUIRED for
# SECURE_SSL_REDIRECT/HSTS to work behind a proxy — without it Django sees the
# proxy→app HTTP leg, never redirects (or loops). Only enable when the proxy
# strips any client-supplied X-Forwarded-Proto, otherwise the header is
# spoofable. The bundled nginx.conf sets X-Forwarded-Proto $scheme.
_BEHIND_PROXY = config('USE_PROXY_SSL_HEADER', default=False, cast=bool)
if _BEHIND_PROXY:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Only trust X-Forwarded-For when the reverse proxy strips a client-supplied
# header. The bundled nginx configuration does so before forwarding traffic.
TRUST_X_FORWARDED_FOR = config(
    'TRUST_X_FORWARDED_FOR', default=_BEHIND_PROXY, cast=bool
)

# ── Login brute-force protection (django-axes) ─────────────────────────────
# Locks out a client after AXES_FAILURE_LIMIT failed logins for a cooloff
# window, then auto-clears. Lockout is keyed on the (username, IP) pair so an
# attacker hammering one account from one host is stopped, without one shared
# NAT IP locking every account in the building.
# Disabled under the test runner: lockout state would otherwise leak between
# tests that exercise the login view, and client.login() authenticates without
# a request object.
AXES_ENABLED = 'test' not in sys.argv
AXES_FAILURE_LIMIT   = config('AXES_FAILURE_LIMIT', default=5, cast=int)
AXES_COOLOFF_TIME    = timedelta(
    minutes=config('AXES_COOLOFF_MINUTES', default=15, cast=int)
)
AXES_LOCKOUT_PARAMETERS = [['username', 'ip_address']]
AXES_RESET_ON_SUCCESS = True          # a good login clears that client's tally
AXES_LOCKOUT_TEMPLATE = 'registration/lockout.html'
# Behind the bundled nginx reverse proxy, trust exactly one X-Forwarded-For hop
# so lockouts key on the real client IP, not the proxy's. Without a proxy Axes
# uses REMOTE_ADDR directly.
if _BEHIND_PROXY:
    AXES_IPWARE_PROXY_COUNT = config('AXES_PROXY_COUNT', default=1, cast=int)

# ── Content-Security-Policy (applied by config.middleware) ─────────────────
# Defense-in-depth against XSS / clickjacking / data exfiltration.
#   • script-src is NONCE-based: the middleware swaps {NONCE} for a fresh
#     per-request value and drops 'unsafe-inline', so an injected inline
#     <script> without the nonce is blocked. Inline event handlers are gone
#     from the templates for the same reason (nonces don't cover on*= attrs).
#   • style-src keeps 'unsafe-inline' — inline style= attributes are pervasive
#     in the Bootstrap templates and can't carry a nonce.
#   • Everything else is locked to 'self' plus the one CDN the UI loads
#     (Bootstrap + Chart.js from jsdelivr).
# Flip *_REPORT_ONLY on to trial changes without enforcing.
_CSP_CDN = 'https://cdn.jsdelivr.net'
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "img-src 'self' data:; "
    f"font-src 'self' {_CSP_CDN}; "
    f"style-src 'self' 'unsafe-inline' {_CSP_CDN}; "
    f"script-src 'self' 'nonce-{{NONCE}}' {_CSP_CDN}; "
    "connect-src 'self'"
)
CONTENT_SECURITY_POLICY_REPORT_ONLY = config(
    'CSP_REPORT_ONLY', default=False, cast=bool
)

# ── Email / SMTP ──────────────────────────────────────────────────────────
# Production: set EMAIL_* vars in .env (see .env.example).
# Local dev:  config/settings_local.py (gitignored) overrides EMAIL_BACKEND to
#             console so notifications print to the terminal instead of hitting
#             SMTP. It is NOT auto-loaded — opt in explicitly per command:
#             py manage.py runserver --settings=config.settings_local
#
# Port guide: 587 = STARTTLS submission (EMAIL_USE_TLS=True)  ← default
#             465 = SMTPS / implicit SSL  (EMAIL_USE_SSL=True, TLS=False)
#             25  = plain SMTP relay — do NOT use with EMAIL_USE_TLS=True
# Overridable so a UAT/demo deployment can route mail to the console without a
# code change (gunicorn has no --settings hook the way runserver does):
#   EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
# Default remains real SMTP, so production is unaffected.
EMAIL_BACKEND     = config(
    'EMAIL_BACKEND',
    default='django.core.mail.backends.smtp.EmailBackend',
)
EMAIL_HOST        = config('EMAIL_HOST',         default='')
EMAIL_HOST_USER   = config('EMAIL_HOST_USER',    default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
EMAIL_PORT        = config('EMAIL_PORT',         default=587,   cast=int)
EMAIL_USE_TLS     = config('EMAIL_USE_TLS',      default=True,  cast=bool)
EMAIL_USE_SSL     = config('EMAIL_USE_SSL',      default=False, cast=bool)
# Without this, smtplib has no socket timeout — if the mail server is
# unreachable, send() blocks forever and the whole HTTP request (e.g.
# ticket create/update) hangs even though the DB write already succeeded.
EMAIL_TIMEOUT     = config('EMAIL_TIMEOUT',      default=10,   cast=int)
# DEFAULT_FROM_EMAIL falls back to EMAIL_HOST_USER when not set explicitly.
DEFAULT_FROM_EMAIL = config(
    'DEFAULT_FROM_EMAIL', default=config('EMAIL_HOST_USER', default='')
)

# ── Site URL (used in email notification links) ────────────────────────────
# Set to your public hostname in production, e.g. https://soc.example.com
SITE_URL = config('SITE_URL', default='http://localhost:8088')

# ── Wazuh / OpenSearch alert ingestion ─────────────────────────────────────
OPENSEARCH_HOST        = config('OPENSEARCH_HOST', default='')
OPENSEARCH_PORT        = config('OPENSEARCH_PORT', default=9200, cast=int)
OPENSEARCH_USER        = config('OPENSEARCH_USER', default='')
OPENSEARCH_PASSWORD    = config('OPENSEARCH_PASSWORD', default='')
OPENSEARCH_VERIFY_SSL  = config('OPENSEARCH_VERIFY_SSL', default=True, cast=bool)
# Path to a CA bundle (PEM) for verifying a self-signed/internal Wazuh/OpenSearch
# certificate. If set, takes precedence over OPENSEARCH_VERIFY_SSL=True/False.
OPENSEARCH_CA_BUNDLE  = config('OPENSEARCH_CA_BUNDLE', default='')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
