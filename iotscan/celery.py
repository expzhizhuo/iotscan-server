"""
@Project ：iotscan 
@File    ：celery.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/6/25 15:15 
"""
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iotscan.settings')

app = Celery('iotscan')
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks(['apps.task'])
