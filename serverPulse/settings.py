"""
Django settings for serverPulse project.

Generated by 'django-admin startproject' using Django 4.1.5.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY')
RECAPTCHA_PUBLIC_KEY = os.environ.get('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = os.environ.get('RECAPTCHA_PRIVATE_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'auth_app',
    'admon_global',
    'sysadmin',
    'servers_monitor',
    'conn_servers',
    'django_crontab',
    'captcha'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'serverPulse.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['auth_app/templates', 'admon_global/templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'serverPulse.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

# DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.sqlite3',
#        'NAME': BASE_DIR / 'db.sqlite3',
#    }
# }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get('NAME_DATABASE'),
        'USER': os.environ.get('USER_DATABASE'),
        'PASSWORD': os.environ.get('PASSWORD_DATABASE'),
        'HOST': 'postgres',
        'PORT': '',
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

# Se cambia codificaciónb
LANGUAGE_CODE = 'en-MX'
# Se cambia zona horaria
TIME_ZONE = 'America/Mexico_City'

USE_I18N = True
# Se deshabilita para que tome la hora del sistema
USE_TZ = False


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = '/static/'

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),

]

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')


# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


#  Security settings
# Sessions and cookies

# Sessions storages based in DB
SESSIONS_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_DB_TABLE = 'django_sessions'

# True only in production, Session cookies only sended over HTTPS
SESSION_COOKIE_SECURE = False

# If value is True, sessions cannot be accesed via Javascript
# False only in development enviroment
SESSION_COOKIE_HTTPONLY = False

# Only in production. this value can be changed to restrict the cookie session only in specified domain ("example.com")
SESSION_COOKIE_DOMAIN = None

# This setting prevents the cookie from being sent in cross-site request
SESSION_COOKIE_SAMESITE = "Strict"

# This setting means that browsers ensure that cookie is only sended under HTTPS, use this setting combined with SESSION_COOKIE_SECURE
SESSION_COOKIE_SECURE = False

# The cookie session will be destroy when the browser is close
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Cronjob for delete all register ipv4, attemps and timestamp_last_attemps from auth_app
CRONJOBS = [
    ('0 0 * * *', 'auth_app.cron.DeleteAttemptsJob')
]
