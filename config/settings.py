from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET-KEY')

DEBUG = config('DEBUG', default=False, cast=bool)

_ALLOWED_HOSTS_DEFAULT = '192.168.100.44,localhost,127.0.0.1,web'
ALLOWED_HOSTS = [
    h.strip() for h in config('ALLOWED_HOSTS', default=_ALLOWED_HOSTS_DEFAULT).split(',')
    if h.strip()
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
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
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

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
# If deployed behind a TLS-terminating reverse proxy (nginx/traefik) that sets
# X-Forwarded-Proto, uncomment so Django trusts it. Only enable when the proxy
# strips any client-supplied X-Forwarded-Proto, otherwise it is spoofable.
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ── Content-Security-Policy (applied by config.middleware) ─────────────────
# Defense-in-depth against XSS / clickjacking / data exfiltration. Scripts and
# styles still allow 'unsafe-inline' (templates use inline <script>/<style>);
# everything else is locked to 'self' plus the one CDN the UI loads
# (Bootstrap + Chart.js from jsdelivr). Tightening script-src to a nonce is the
# recommended next step. Flip *_REPORT_ONLY on to trial changes without
# enforcing.
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
    f"script-src 'self' 'unsafe-inline' {_CSP_CDN}; "
    "connect-src 'self'"
)
CONTENT_SECURITY_POLICY_REPORT_ONLY = config(
    'CSP_REPORT_ONLY', default=False, cast=bool
)

# ── Email / SMTP ──────────────────────────────────────────────────────────
# Production: set EMAIL_* vars in .env (see .env.example).
# Local dev:  settings_local.py overrides EMAIL_BACKEND to console so
#             notifications print to the terminal instead of hitting SMTP.
#
# Port guide: 587 = STARTTLS submission (EMAIL_USE_TLS=True)  ← default
#             465 = SMTPS / implicit SSL  (EMAIL_USE_SSL=True, TLS=False)
#             25  = plain SMTP relay — do NOT use with EMAIL_USE_TLS=True
EMAIL_BACKEND     = 'django.core.mail.backends.smtp.EmailBackend'
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
SITE_URL = config('SITE_URL', default='http://localhost:8000')

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
