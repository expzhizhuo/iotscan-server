"""
@Project ：iotscan 
@File    ：AuthPermission.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/3/26 13:02 
"""
from rest_framework.authentication import BaseAuthentication
from rest_framework import permissions
from rest_framework_simplejwt import authentication


class CustomPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user and obj.created_by == request.user:
            return True
        return False

    def islogin(self, request, view, obj):
        print(self)
        if request.user and obj.created_by == request.user:
            return True
        return False


class CustomAuthentication(BaseAuthentication):
    """
    重写全局的自定义认证逻辑
    """

    def authenticate(self, request):
        # your custom authentication logic here
        return None


class JWTAuthAction(authentication.JWTAuthentication):
    """
    重写JWTAuthentication认证逻辑
    """

    def authenticate(self, request):
        """
        自己的认证逻辑
        :param request:
        :return:
        """

        if request.auth:
            return True
        return False


class SuperPermissions(permissions.BasePermission):
    """
    权限判定
    """

    def has_permission(self, request, view):
        if request.user.is_superuser == 1 or request.user.permissions == 1:
            return True
        return False


class SinglePermission(permissions.BasePermission):
    """
    个人权限判断: 业务操作只允许操作自己创建的任务
    """

    def has_permission(self, request, view):
        params_user_id = request.GET.get('user_id') or request.POST.get('user_id')
        if params_user_id is None:
            return False
        else:
            if request.user.id == params_user_id:
                return True
            else:
                return False


class IsAuthAction(permissions.IsAuthenticated):
    """
    自定义的身份信息认证，用于验证token是否合法
    """

    def has_permission(self, request, view):
        """
        继承IsAuthenticated重写新的自定义认证逻辑
        :param request:
        :param view:
        :return:
        """
        if request.auth:
            # 自定义的认证逻辑
            return True
        return False
