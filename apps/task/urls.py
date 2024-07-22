"""
@Project ：iotscan 
@File    ：urls.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/4/9 14:11 
"""
from django.urls import path, include
from rest_framework import routers
from .views import ScanListView, ScanResultListView, SearchTaskResultView


class TaskAPIView:
    router = routers.DefaultRouter(trailing_slash=False)
    router.register(r'tasklist', ScanListView, basename='获取扫描任务列表')
    router.register(r'get_task_result', ScanResultListView, basename='获取扫描结果列表')
    router.register(r'result', SearchTaskResultView, basename='获取资产结果列表')

    urlpatterns = [
        path(r'', include(router.urls)),
    ]
