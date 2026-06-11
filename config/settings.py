from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET-KEY')

DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = ['192.168.100.44', 'localhost', '127.0.0.1', 'web']

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
EMAIL_PORT        = config('EMAIL_PORT',         default=587,  cast=int)
EMAIL_USE_TLS     = config('EMAIL_USE_TLS',      default=True, cast=bool)
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
OPENSEARCH_VERIFY_SSL  = config('OPENSEARCH_VERIFY_SSL', default=False, cast=bool)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
