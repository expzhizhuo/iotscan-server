"""
@Project ：iotscan 
@File    ：MyTokenObtainPairView.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/3/26 11:19 
"""
from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.core.cache import cache
from django.utils import timezone
from apps.models.models import AuthUser
from common.device import device_tools


class FormulaTokenObtainPairSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        username = attrs['username']
        password = attrs['password']
        failed_attempts = cache.get(f'failed_login_attempts_{username}', 0)
        if failed_attempts >= 5:
            ttl = cache.ttl(f'failed_login_attempts_{username}')
            remaining_time = ttl if ttl > 0 else 0
            return {"code": "400", "msg": f"超过当天最大尝试次数，请{remaining_time}秒稍后再试!", "data": ""}

        user = authenticate(username=username, password=password)
        if user is None:
            cache.set(f'failed_login_attempts_{username}', failed_attempts + 1, timeout=6000)
            return {"code": "400", "msg": "用户名或者密码错误!", "data": ""}
        # 登陆成功重置登陆失败次数
        cache.delete(f'failed_login_attempts_{username}')
        # Token creation
        refresh = RefreshToken.for_user(user)
        data = {'refresh': str(refresh), 'token': str(refresh.access_token), 'username': user.username,
                'id': user.id}

        if user.is_superuser:
            data['permissions'] = 1
        else:
            data['permissions'] = user.permissions
        xff_ip = self.context['request'].META.get('HTTP_X_FORWARDED_FOR')
        if xff_ip is not None:
            ip = self.context['request'].META.get('HTTP_X_FORWARDED_FOR').split(',')[0]
        else:
            ip = self.context['request'].META.get('X-Real-IP')
        networks_info = device_tools.get_network_info()
        scan_ips = [ip for item in networks_info for key in ('ipv4', 'ipv6') for ip in
                    (item.get(key) if isinstance(item.get(key), list) else [item.get(key)]) if item.get(key)]
        if ip in scan_ips:
            ip = "未知IP"
        AuthUser.objects.filter(pk=user.id).update(last_login_ip=ip, last_login=timezone.now())

        return {"code": "200", "msg": "success", "data": data}


class FormulaTokenObtainPairView(TokenObtainPairView):
    serializer_class = FormulaTokenObtainPairSerializer
