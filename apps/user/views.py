import uuid

from django.contrib.auth.models import auth
from django.db.models import Q
from rest_framework.throttling import ScopedRateThrottle

from common.response import response
from .serializers import *
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from common.throttling import *

import logging

log = logging.getLogger('users')


# Create your views here.
class AuthUserView(viewsets.ViewSet):
    """
    用户登陆退出等操作接口
    """
    http_method_names = ["post"]
    permission_classes = [IsAuthenticated]

    @staticmethod
    def create(request):
        """
        用户退出登陆接口
        :param 认证信息
        :return:json
        """
        log.info(f'用户{request.user}进行退出登陆')
        try:
            user = request.user
            logout_data = LogoutSerializer(data=request.POST)
            if logout_data.is_valid():
                print(logout_data.data)
                auth.logout(request)
                print(user)
                # user.blacklist_token(logout_data.data.get("refresh"))
                token = RefreshToken(logout_data.data.get("refresh"))
                token.blacklist()
                # 这里要去redis中删除这个用户所对应的认证，并且讲认证信息添加黑名单中
                return response.success('退出成功')
            else:
                return response.error("退出失败，参数不正确")
        except Exception as e:
            log.error(f'用户{request.user}退出登陆接口出错，错误信息{e}')
            return response.server_error(str(e))


class GetUserInfoView(viewsets.ViewSet):
    http_method_names = ['get', 'post']
    serializer_class = AuthUserSerializers
    queryset = AuthUser.objects.all()
    permission_classes = [IsAuthenticated]

    @staticmethod
    def list(request, pk=None):
        """
        获取用户信息接口
        :param request:
        :param pk:
        :return:
        """
        log.info(f'用户{request.user}执行获取用户信息接口操作')
        try:
            userlist = AuthUserSerializers(request.user)
            return response.success(userlist.data)
        except Exception as e:
            log.error(f'用户{request.user}执行获取用户信息接口操作出错，出错信息{e}')
            return response.server_error(str(e))

    @action(detail=False, methods=['post'], permission_classes=[])
    def login(self, request):
        """
        登陆接口
        :param request:
        :return:
        """
        return response.success()

    @action(methods=['get'], detail=False, permission_classes=[IsAdminUser])
    def get_user_list(self, request, pk=None):
        """
        获取用户列表
        :param request:
        :param pk:
        :return:
        """
        log.info(f'用户{request.user}执行获取用户列表口操作')
        keyword = request.query_params.get('search', None)
        if keyword is not None:
            query = Q(id__startswith=keyword) | Q(username__contains=keyword) | Q(phone__contains=keyword) | Q(
                last_login_ip__contains=keyword)
            User_List = AuthUser.objects.filter(query, is_active=True).order_by('-date_joined')
        else:
            User_List = AuthUser.objects.filter(is_active=True).order_by('-date_joined')
        page = UsersPageNumberPagination()
        page_data = page.paginate_queryset(queryset=User_List, request=request, view=self)
        data = AuthUserSerializers(page_data, many=True, read_only=True)
        page.get_paginated_response(data.data)
        return response.success({"total": page.page.paginator.count, "list": data.data})


class SetUserPasswordView(viewsets.ViewSet):
    queryset = AuthUser.objects.all()

    @action(methods=['post'], detail=False, permission_classes=[IsAdminUser])
    def create_user(self, request, pk=None):
        """
        创建用户接口，仅管理员访问
        :param request:
        :param pk:
        :return:
        """
        log.info(f"用户{request.user}进行用户创建操作")
        try:
            create_data = CreateUserSerializers(data=request.data)
            if create_data.is_valid():
                CreateUserSerializers.save(create_data)
                log.info(f"用户{create_data.data.get('username')}创建成功")
                return response.success(f"用户{create_data.data.get('username')}创建成功")
            else:
                log.info(f"用户{request.user}创建用户失败，失败原因：{create_data.errors}")
                return response.error(create_data.errors.get('non_field_errors')[0])
        except Exception as e:
            log.error(e)
            return response.server_error(e)

    @action(methods=['post'], detail=False, permission_classes=[IsAdminUser])
    def delete_user(self, request, pk=None):
        """
        删除用户
        :param request:
        :param pk:
        :return:
        """
        log.info(f'用户{request.user}执行用户删除操作')
        user_id = request.data.get('user_id')
        try:
            if not user_id:
                return response.error("请传入用户id")
            user_info = AuthUser.objects.filter(id=user_id).values('id', 'username', 'permissions',
                                                                   'is_superuser').first()
            login_user_info = AuthUser.objects.filter(id=request.user.id).values('id', 'username', 'permissions',
                                                                                 'is_superuser').first()
            if not user_info:
                return response.error("异常用户id")
            if str(user_info.get('username')) == str(login_user_info.get('username')):
                return response.error("无法操作自己账户")
            if (user_info.get('permissions') == 1 and str(user_info.get('is_superuser')) == "True") or (
                    login_user_info.get('permissions') == 1 and
                    str(login_user_info.get('is_superuser')) != "True" and
                    user_info.get('permissions') == 1):
                return response.error("当前用户权限无法删除此用户")
            delete_info = AuthUser.objects.filter(id=user_id).delete()
            if delete_info:
                return response.success("删除成功")
            else:
                return response.error("删除失败")
        except Exception as e:
            log.error(f"删用户{user_id}出错，错误信息：{e}")
            return response.server_error("异常输入")

    @action(methods=['post'], detail=False, permission_classes=[IsAuthenticated])
    def ChangePassword(self, request, pk=None):
        """
        修改密码接口
        :param request:password
        :param pk:
        :return:
        """
        log.info(f'用户{request.user}执行密码修改操作')
        try:
            if 'new_password' not in request.data:
                return response.error('请输入新密码')
            elif 'old_password' not in request.data:
                return response.error('请输入旧密码')
            elif request.data['new_password'] == request.data['old_password']:
                return response.error('新密码和旧的密码相同！')
            elif request.data['new_password'] != request.data['old_password']:
                serializer = SetPasswordSerializers(data=request.data, context={'username': request.user})
                if serializer.is_valid():
                    serializer.update(request.user, serializer.validated_data)
                    return response.success('密码修改成功')
                else:
                    if 'new_password' in serializer.errors:
                        return response.error('new_password ' + serializer.errors['new_password'][0])
                    elif 'old_password' in serializer.errors:
                        return response.error('old_password ' + serializer.errors['old_password'][0])
                    return response.error(serializer.errors)
            else:
                return response.error('请认真填写表单数据')
        except Exception as e:
            log.error(f'用户{request.user}执行密码修改操作出错，错误信息{e}')
            return response.server_error(e)

    @action(methods=['get'], detail=False, permission_classes=[IsAuthenticated],
            throttle_classes=[MinuteUserRateThrottle])
    def reset_api_key(self, request):
        """
        重置api key
        :param request:
        :return:
        """
        log.info(f'用户{request.user}执行重置api key接口操作')
        AuthUser.objects.filter(id=request.user.id).update(api_key=uuid.uuid4())
        return response.success("重置成功")
