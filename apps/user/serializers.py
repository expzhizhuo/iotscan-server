"""
@Project ：iotscan 
@File    ：serializers.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/3/26 11:29 
"""
from django.utils import timezone
from rest_framework import serializers
from ..models.models import AuthUser
from django.contrib.auth import authenticate
from rest_framework.pagination import PageNumberPagination


class UsersPageNumberPagination(PageNumberPagination):
    """
    分页相关配置
    """
    allowed_page_sizes = [10, 20, 50]
    default_page_size = 10
    max_page_size = 50
    page_query_param = 'page'
    page_size_query_param = 'page_size'

    def get_page_size(self, request):
        request.GET.get(self.page_size_query_param)
        page_size = request.query_params.get(self.page_size_query_param)
        if page_size and int(page_size) in self.allowed_page_sizes:
            return int(page_size)
        return self.default_page_size


class LogoutSerializer(serializers.Serializer):
    """
    用户退出登陆模型序列化
    """
    refresh = serializers.CharField(allow_blank=False)


class MaskedMobileField(serializers.CharField):
    """
    查询用户信息手机号打码函数
    """

    def to_representation(self, value):
        # 隐藏手机号中间几位，并返回形如'133****8520' 的字符串
        if value is None or len(value) == 0:
            return None
        # 隐藏手机号中间几位，并返回形如'133****8520' 的字符串
        return value[:3] + '****' + value[7:]


class AuthUserSerializers(serializers.ModelSerializer):
    """
    用户信息序列化模型
    """
    id = serializers.UUIDField(required=True)  # 必填项
    phone = MaskedMobileField(error_messages={"required": "手机号不能为空"})
    last_login = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    create_time = serializers.DateTimeField(source='date_joined', format="%Y-%m-%d %H:%M:%S")

    class Meta:
        model = AuthUser
        fields = ["id", "username", "permissions", "email", "phone", "api_key", "last_login", "create_time",
                  "last_login_ip"]


class CreateUserSerializers(serializers.ModelSerializer):
    """
    创建用户序列化模型
    """
    PermissionChoice = (
        (0, '普通用户权限'),
        (1, '管理员权限')
    )

    username = serializers.CharField(required=True, max_length=20)
    phone = serializers.CharField(required=True, max_length=11, min_length=11)
    password = serializers.CharField(required=True, max_length=255)
    password_again = serializers.CharField(write_only=True)
    permissions = serializers.ChoiceField(choices=PermissionChoice, default=0)
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        password = attrs.get('password')
        password_again = attrs.pop('password_again')
        if password != password_again:
            raise serializers.ValidationError('两次密码不一致')
        phone = attrs.get('phone')
        if AuthUser.objects.filter(phone=phone).exists():
            raise serializers.ValidationError('手机号已存在')
        email = attrs.get('email')
        if AuthUser.objects.filter(email=email).exists():
            raise serializers.ValidationError('邮箱已存在')
        username = attrs.get('username')
        if AuthUser.objects.filter(username=username).exists():
            raise serializers.ValidationError('用户名已经存在')
        return attrs

    def save(self, **kwargs):
        user = AuthUser(
            username=self.validated_data['username'],
            phone=self.validated_data['phone'],
            email=self.validated_data['email'],
            permissions=self.validated_data['permissions'],
            date_joined=timezone.now()
        )
        user.set_password(self.validated_data['password'])
        user.save()
        return user

    class Meta:
        model = AuthUser
        fields = ('id', 'email', 'username', 'phone', 'password', 'password_again', 'permissions')


class SetPasswordSerializers(serializers.ModelSerializer):
    """
    用户修改密码模型序列化
    """
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True, min_length=8, max_length=20)

    def validate_old_password(self, old_password):
        if not authenticate(username=self.context.get('username'), password=old_password):
            raise serializers.ValidationError("原密码错误，请重新输入")
        return old_password

    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance

    class Meta:
        model = AuthUser
        fields = ['id', 'new_password', 'old_password']
