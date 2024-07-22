"""
@Project ：iotscan 
@File    ：serializers.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/4/9 13:57 
"""
import json
import ast

from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination
from ..models.models import *


class TasksPageNumberPagination(PageNumberPagination):
    """
    分页相关配置
    """
    allowed_page_sizes = [10, 50, 100, 1000]
    default_page_size = 10
    max_page_size = 1000
    page_query_param = 'page'
    page_size_query_param = 'page_size'

    def get_page_size(self, request):
        request.GET.get(self.page_size_query_param)
        page_size = request.query_params.get(self.page_size_query_param)
        if page_size and int(page_size) in self.allowed_page_sizes:
            return int(page_size)
        return self.default_page_size


class TaskScanCreateSerializers(serializers.ModelSerializer):
    """
    任务创建序列化模型
    """
    PORT_TYPE = (
        ("ALL", "1-65535"),
        ("TOP10", "常见的10个端口"),
        ("TOP100", "常见的100个端口"),
        ("TOP1000", "常见的1000个端口")
    )
    POC_TYPE = (
        (-1, '不使用poc'),
        (0, '全部'),
        (1, '低危'),
        (2, '中危'),
        (3, '高危'),
        (4, '严重'),
        (5, '特定poc扫描'),
    )
    SPEED_TYPE = (
        (0, '低速'),
        (1, '中速'),
        (2, '高速')
    )
    host = serializers.ListField(required=True, max_length=30000, min_length=1)
    desc = serializers.CharField(required=True, max_length=20)
    is_use_port_scan = serializers.BooleanField()  # 用来判断传进来的是true还是false
    port_type = serializers.ChoiceField(PORT_TYPE)
    is_use_proxy = serializers.BooleanField()
    is_use_domainscan = serializers.BooleanField()
    domain_type = serializers.CharField(max_length=10)
    poc_type = serializers.ChoiceField(POC_TYPE)
    scanning_speed = serializers.ChoiceField(SPEED_TYPE)
    poc_warehouse_ids = serializers.ListField(required=True)

    class Meta:
        model = TargetManager
        fields = (
            'host', 'desc', 'is_use_port_scan', 'port_type', 'is_use_proxy', 'is_use_domainscan', 'domain_type',
            'poc_type', 'scanning_speed', 'poc_warehouse_ids')


class TaskScanSerializers(serializers.ModelSerializer):
    """
    任务列表序列化模型
    """
    create_user = serializers.SerializerMethodField()
    desc = serializers.CharField(required=True, max_length=20)
    create_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    progress = serializers.SerializerMethodField()

    @staticmethod
    def get_create_user(obj):
        return {
            "id": obj.create_user.id,
            "username": obj.create_user.username
        }

    @staticmethod
    def get_progress(obj):
        if obj.task_count == 0:
            return 0
        return round(obj.finish_task_count / obj.task_count * 100, 2)

    class Meta:
        model = TargetManager
        fields = (
            'id', 'desc', 'status', 'poc_type', 'scanning_speed', 'task_count', 'finish_task_count', 'progress',
            'create_time', 'create_user')


class SearchTaskListSerializers(serializers.ModelSerializer):
    """
    任务列表搜索序列化模型
    """
    search = serializers.CharField(max_length=50)

    class Meta:
        model = TargetManager
        fields = ['search']


class GetTaskStatusSerializers(serializers.ModelSerializer):
    """
    获取扫描任务状态序列化模型
    """

    create_user = serializers.SerializerMethodField()
    progress = serializers.SerializerMethodField()
    poc_count = serializers.SerializerMethodField()
    host = serializers.SerializerMethodField()
    create_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    update_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")

    @staticmethod
    def get_create_user(obj):
        return {
            "username": obj.create_user.username
        }

    @staticmethod
    def get_progress(obj):
        if obj.task_count == 0:
            return 0
        return round(obj.finish_task_count / obj.task_count * 100, 2)

    @staticmethod
    def get_poc_count(obj):
        return obj.poc_warehouse_ids.all().count()

    @staticmethod
    def get_host(obj):
        import ast
        try:
            host_list = ast.literal_eval(obj.host)
            return host_list if isinstance(host_list, list) else [host_list]
        except (ValueError, SyntaxError):
            return [obj.host]

    class Meta:
        model = TargetManager
        fields = (
            'id', 'desc', 'scanning_speed', 'host', 'task_count', 'finish_task_count', 'status', 'proxy_type',
            'poc_type', 'is_domain', 'create_time', 'update_time', 'create_user', 'progress', 'poc_count')


class StopOrStartOrDeleteTasksSerializers(serializers.Serializer):
    """
    停止正在运行任务序列化模型
    """
    STATUS = (
        (0, '开始/重启'),
        (1, '暂停'),
        (2, '停止'),
        (3, '重启')
    )
    task_ids = serializers.UUIDField(required=True)
    task_status = serializers.ChoiceField(choices=STATUS)

    class Meta:
        model = TargetManager
        fields = ['task_ids', 'task_status']


class DeleteTaskSerializers(serializers.ModelSerializer):
    """
    删除任务序列化模型
    """
    tasks_id = serializers.UUIDField(required=True)

    class Meta:
        model = TargetManager
        fields = ['tasks_id', 'poc_warehouse_ids']


class GetTaskResultVerifySerializers(serializers.ModelSerializer):
    """
    获取扫描结果列表序列化模型
    """
    TASK_TYPE = (
        (0, '端口结果'),
        (1, 'poc结果')
    )
    task_id = serializers.UUIDField(required=True)
    task_type = serializers.ChoiceField(TASK_TYPE, default=0)
    search = serializers.CharField(required=False)

    class Meta:
        model = IotTaskPocResult
        fields = ('task_id', 'task_type', 'search')


class GetTaskPocResultSerializers(serializers.ModelSerializer):
    """
    扫描结果POC列表序列化模型
    """
    host = serializers.CharField(required=True)
    result = serializers.JSONField(required=True)
    create_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    poc_info = serializers.SerializerMethodField()

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret['result'] = json.loads(ret['result'])
        permission = instance.vul_id.vul_permissions
        user_permission = instance.vul_id.create_user.permissions
        is_superuser = instance.vul_id.create_user.is_superuser
        if permission == 1 and user_permission != 1 and is_superuser != 1:
            ret['result']['request'] = '无权限查看'
        return ret

    @staticmethod
    def get_poc_info(instance):
        return {
            "poc_name": instance.vul_id.poc_name,
            "vul_name": instance.vul_id.vul_name,
            "vul_desc": instance.vul_id.vul_desc,
            "vul_leakLevel": instance.vul_id.vul_leakLevel,
            "vul_range": instance.vul_id.vul_range,
            "has_exp": instance.vul_id.has_exp,
            "vul_vulDate": instance.vul_id.vul_vulDate

        }

    class Meta:
        model = IotTaskPocResult
        # fields = ('id', 'status', 'host', 'result')
        fields = '__all__'


class GetTaskPortResultSerializers(serializers.ModelSerializer):
    """
    扫描结果PORT列表序列化模型
    """
    scan_host = serializers.CharField(required=True)
    scan_result = serializers.JSONField(required=True)
    create_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret['scan_result'] = json.loads(ret['scan_result'])
        return ret

    class Meta:
        model = IotTaskPortResult
        fields = '__all__'


class GetFingerResultSerializers(serializers.ModelSerializer):
    """
    获取资产信息序列化模型
    """
    tasks_id = serializers.UUIDField(required=True)

    class Meta:
        model = IotTaskFingerResult
        fields = ['tasks_id']


class GetFingerResultResponseSerializers(serializers.ModelSerializer):
    """
    response输出数据格式化
    """

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret['cert'] = json.loads(ret['cert'])
        ret['cdn_ip_list'] = ast.literal_eval(ret['cdn_ip_list'])
        return ret

    class Meta:
        model = IotTaskFingerResult
        fields = ['host', 'url', 'port', 'scan_type', 'port_service', 'scheme', 'cms', 'title', 'status_code',
                  'redirect_num', 'server', 'is_cdn', 'cdn_ip_list', 'icon_hash', 'icp', 'cert', 'headers', 'country',
                  'province', 'city', 'isp']
