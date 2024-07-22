"""
@Project ：iotscan 
@File    ：urls.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/7/14 15:31
"""
from django.urls import path, include
from rest_framework import routers

from apps.home.views import *


class HomeAPIView:
    router = routers.DefaultRouter(trailing_slash=False)
    router.register(r'list', HomeView, basename='home主页统计接口')
    router.register(r'poc_count', PocCountView, basename='poc数量统计接口接口')
    # router.register(r'user_setting', SetUserPasswordView, basename='用户修改密码接口')

    urlpatterns = [
        path(r'', include(router.urls)),
    ]
