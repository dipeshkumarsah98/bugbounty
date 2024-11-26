# settings/development.py

from .base import *

DEBUG = True

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
