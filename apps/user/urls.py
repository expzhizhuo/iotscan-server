"""
@Project ：iotscan 
@File    ：urls.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/3/26 11:48 
"""
from django.urls import path, include
from rest_framework import routers

from apps.user.utils.MyTokenObtainPairView import FormulaTokenObtainPairView
from apps.user.views import *


class UsersAPIView:
    router = routers.DefaultRouter(trailing_slash=False)
    router.register(r'logout', AuthUserView, basename='退出登录接口')
    router.register(r'getuserinfo', GetUserInfoView, basename='获取用户信息接口')
    router.register(r'user_setting', SetUserPasswordView, basename='用户修改密码接口')

    urlpatterns = [
        path(r'', include(router.urls)),
        path(r'login', FormulaTokenObtainPairView.as_view(), name='登录接口')
    ]
