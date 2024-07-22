"""
@Project ：iotscan 
@File    ：urls.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/4/9 21:34 
"""
from django.urls import path, include
from rest_framework import routers
from .views import *


class ToolsAPIView:
    router = routers.DefaultRouter(trailing_slash=False)
    router.register(r'poc_list', PocListView, basename='获取poc列表相关操作接口')
    router.register(r'proxysetting', ProxySettingView, basename="代理信息相关操作接口")
    router.register(r'fofasetting', FofaSettingView, basename="fofa api接口相关操作")
    router.register(r'report', ReportExportView, basename='报告导出模块')

    urlpatterns = [
        path(r'', include(router.urls)),
    ]
