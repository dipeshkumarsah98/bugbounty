# settings/production.py

from .base import *

DEBUG = False

ALLOWED_HOSTS = ['your-production-domain.com']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'postgres',
        'USER': 'postgres.fzvcibrecogszppgeosz',
        'PASSWORD': 'Aztos6MoBeoVyIin',
        'HOST': 'aws-0-us-east-1.pooler.supabase.com',
        'PORT': '6543',
    }
}