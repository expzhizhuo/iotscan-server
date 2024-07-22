"""
@Project ：iotscan 
@File    ：serializers.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/4/9 21:24 
"""
import ast
import json

from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination
from ..models.models import *


class ToolsPageNumberPagination(PageNumberPagination):
    """
    分页相关配置
    """
    allowed_page_sizes = [10, 20, 50, 100]
    default_page_size = 10
    max_page_size = 100
    page_query_param = 'page'
    page_size_query_param = 'page_size'

    def get_page_size(self, request):
        request.GET.get(self.page_size_query_param)
        page_size = request.query_params.get(self.page_size_query_param)
        if page_size and int(page_size) in self.allowed_page_sizes:
            return int(page_size)
        return self.default_page_size


class GetPocListSerializers(serializers.ModelSerializer):
    """
    poc列表序列化模型
    """
    create_user = serializers.SerializerMethodField()
    create_time = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S')

    def get_create_user(self, obj):
        return {
            "id": obj.create_user.id,
            "create_username": obj.create_user.username
        }

    class Meta:
        model = Vulnerability
        fields = ['id', 'poc_name', 'vul_author', 'vul_name', 'vul_range', 'vul_type', 'vul_desc', 'vul_leakLevel',
                  'has_exp', 'vul_device_name', 'vul_vulDate', 'vul_createDate', 'vul_updateDate', 'create_time',
                  'create_user']


class GetProxyInfoSerializers(serializers.ModelSerializer):
    """
    代理信息列表序列化模型
    """
    create_user = serializers.SerializerMethodField()
    host = serializers.IPAddressField()
    port = serializers.CharField(max_length=5, required=True)
    proxy_status = serializers.ChoiceField
    create_time = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S')

    def get_create_user(self, obj):
        return {
            "id": obj.create_user.id,
            "username": obj.create_user.username
        }

    class Meta:
        model = ProxySetting
        fields = '__all__'


class SaveProxyInfoSerializers(serializers.ModelSerializer):
    """
    代理信息列表序列化模型
    """
    host = serializers.IPAddressField()
    port = serializers.CharField(max_length=5, required=True)
    proxy_type = serializers.ChoiceField

    def create(self, validated_data):
        # 检查是否已经存在相同的数据
        instance, created = ProxySetting.objects.get_or_create(**validated_data)
        if not created:
            # 如果已经存在相同的数据，返回错误信息
            raise serializers.ValidationError(["当前代理配置已经存在，请检查输入是否正确"])
        return instance

    class Meta:
        model = ProxySetting
        fields = '__all__'


class UpdataProxySettingSerializers(serializers.ModelSerializer):
    """
    代理配置保存序列化模型
    """
    id = serializers.IntegerField(read_only=True)
    host = serializers.IPAddressField()
    port = serializers.CharField(max_length=5, required=True)
    proxy_type = serializers.ChoiceField
    proxy_status = serializers.ChoiceField

    def update(self, instance, validated_data):
        # updatainfo = {
        #     'host': host,
        #     'port': port,
        #     'proxy_type': type,
        #     'proxy_username': username,
        #     'proxy_password': password,
        #     'proxy_status': status,
        #     'user': request.user.id
        # }
        print(validated_data)
        instance.host = validated_data.get("host")
        instance.port = validated_data.get("port")
        instance.proxy_username = validated_data.get("proxy_username")
        instance.proxy_password = validated_data.get("proxy_password")
        instance.proxy_type = validated_data.get("proxy_type")
        instance.proxy_status = validated_data.get("proxy_status")
        instance.update()
        return instance

    class Meta:
        model = ProxySetting
        fields = '__all__'


class GetFofaSettingSerializers(serializers.ModelSerializer):
    """
    fofa配置信息列表序列化模型
    """
    create_user = serializers.SerializerMethodField()
    create_time = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S')

    def create(self, validated_data):
        # 检查是否已经存在相同的数据
        instance, created = FofaSetting.objects.get_or_create(**validated_data)
        if not created:
            # 如果已经存在相同的数据，返回错误信息
            raise serializers.ValidationError(["当前fofa配置已经存在，请检查输入是否正确"])
        return instance

    def get_create_user(self, obj):
        return {
            "id": obj.create_user.id,
            "create_username": obj.create_user.username
        }

    class Meta:
        model = FofaSetting
        fields = '__all__'


class SaveFofaSettingSerializers(serializers.ModelSerializer):
    """
    fofa配置保存操作的序列化模型
    """
    fofa_email = serializers.EmailField()
    fofa_size = serializers.IntegerField(max_value=10000)
    fofa_status = serializers.ChoiceField

    def create(self, validated_data):
        # 检查是否已经存在相同的数据
        instance, created = FofaSetting.objects.get_or_create(**validated_data)
        if not created:
            # 如果已经存在相同的数据，返回错误信息
            raise serializers.ValidationError(["当前fofa配置已经存在，请检查输入是否正确"])
        return instance

    def update(self, instance, validated_data):
        instance.fofa_email = validated_data.get("fofa_email")
        instance.fofa_key = validated_data.get("fofa_key")
        instance.update()
        return instance

    class Meta:
        model = FofaSetting
        fields = '__all__'


class VerifyExportXlsxReportSerializers(serializers.ModelSerializer):
    """
    导出资产xlsx报告验证模型
    """
    task_ids = serializers.UUIDField(required=True)

    class Meta:
        model = IotTaskFingerResult
        fields = ['task_ids']


class ExportXlsxReportDataSerializers(serializers.ModelSerializer):
    """
    导出资产xlsx报告数据格式模型
    """

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret['cert'] = json.loads(ret['cert'])
        ret['cdn_ip_list'] = ast.literal_eval(ret['cdn_ip_list'])
        return ret

    class Meta:
        model = IotTaskFingerResult
        fields = ['host', 'port', 'port_service', 'scan_type', 'url', 'scheme', 'cms', 'title', 'status_code',
                  'redirect_num', 'server', 'is_cdn', 'cdn_ip_list', 'icon_hash', 'icp', 'cert', 'country', 'province',
                  'city', 'isp']
