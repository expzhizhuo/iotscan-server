"""iotscan URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path, include
from rest_framework import routers
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from apps.user.urls import UsersAPIView
from apps.task.urls import TaskAPIView
from apps.tools.urls import ToolsAPIView
from apps.home.urls import HomeAPIView

router = routers.DefaultRouter(trailing_slash=False)

# 配置生成swagger接口文档
schema_view = get_schema_view(
    openapi.Info(
        title="AssetsServer API接口文档",
        default_version='v2',
        description="Assets Server API",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="zhizhuoshuma@163.com"),
        license=openapi.License(name="zhizhuo"),
    ),
    public=True,
    # permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    # re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0),
    #         name='schema-json'),
    # path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    # path(r'redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path(r'api/v1/', include(router.urls), name='default'),
    path(r'api/v1/users/', include(UsersAPIView), name='用户操作接口'),
    path(r'api/v1/tasks/', include(TaskAPIView), name='任务操作接口'),
    path(r'api/v1/tools/', include(ToolsAPIView), name='工具类操作接口'),
    path(r'api/v1/home/', include(HomeAPIView), name='home主页统计类接口'),
    # path('admin/', admin.site.urls),
]
