# from django.db import models
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
import uuid


# Create your models here.
class AuthUser(AbstractUser):
    """
    用户表
    """
    PermissionChoice = (
        (0, '普通用户权限'),
        (1, '管理员权限')
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, auto_created=True)
    email = models.EmailField(max_length=50, blank=False, null=False, verbose_name='邮箱')
    username = models.CharField(max_length=20, blank=False, null=False, unique=True, verbose_name='用户名')
    password = models.CharField(max_length=255, blank=False, null=False, verbose_name='密码')
    phone = models.CharField(max_length=11, blank=False, null=False, verbose_name='手机号', unique=True)
    permissions = models.IntegerField(choices=PermissionChoice, blank=False, null=False, verbose_name='用户的身份权限',
                                      default=1)
    api_key = models.CharField(max_length=100, default=uuid.uuid4, editable=False, auto_created=True,
                               verbose_name="用户api接口key")
    last_login_ip = models.GenericIPAddressField(default=None, blank=False, null=True, verbose_name='登陆ip')
    USERNAME_FIELD = 'username'

    class Meta:
        db_table = 'auth_user'

    def __str__(self):
        return self.username

    @staticmethod
    def blacklist_token(token):
        outstanding_token = OutstandingToken.objects.get(token=token)
        BlacklistedToken.objects.create(token=outstanding_token)


class ProxySetting(models.Model):
    """
    系统代理设置表
    """
    PROXY_TYPE = (
        ('HTTP', 'HTTP'),
        ('HTTPS', 'HTTPS'),
        ('SOCKS5', 'SOCKS5')
    )
    ACTIVE_TYPE = (
        (True, '启用'),
        (False, '不启用')
    )
    id = models.AutoField(primary_key=True)
    host = models.CharField(max_length=50, blank=False, null=False, verbose_name='代理设置的host地址')
    port = models.CharField(max_length=5, blank=False, null=False, verbose_name='代理运行的端口')
    proxy_username = models.CharField(max_length=20, blank=True, null=True, verbose_name='代理认证用户名')
    proxy_password = models.CharField(max_length=100, blank=True, null=True, verbose_name='代理认证密码')
    proxy_type = models.CharField(choices=PROXY_TYPE, default='HTTP', max_length=10, null=False, blank=False,
                                  verbose_name='代理类型')
    proxy_status = models.CharField(choices=ACTIVE_TYPE, max_length=10, null=False, blank=False, default=False,
                                    verbose_name='代理状态')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, null=True, blank=True, verbose_name='更新时间')
    create_user = models.ForeignKey(to=AuthUser, null=True, on_delete=models.CASCADE, related_name='proxy_user_id',
                                    to_field='id')

    class Meta:
        db_table = 'proxy_setting'


class Vulnerability(models.Model):
    """
    漏洞poc表
    """
    LEAK_LEVEL = (
        (4, '严重漏洞'),
        (3, '高危漏洞'),
        (2, '中危漏洞'),
        (1, '低危漏洞'),
        (0, '提示信息')
    )
    VUL_Permissions = (
        (0, '注册用户权限'),
        (1, '管理员权限'),
    )
    id = models.UUIDField(primary_key=True, auto_created=True)
    poc_name = models.CharField(max_length=255, blank=False, null=False, db_index=True, verbose_name='poc名称')
    file_name = models.CharField(max_length=255, db_index=True, blank=False, null=False,
                                 verbose_name='pocsuite3漏洞文件名字')
    vul_author = models.CharField(max_length=50, blank=False, null=True, verbose_name='poc作者名字')
    vul_name = models.CharField(max_length=255, blank=False, null=False, verbose_name='漏洞应用名称')
    vul_range = models.CharField(max_length=255, blank=True, null=True, verbose_name='漏洞影响范围')
    vul_type = models.CharField(max_length=255, blank=True, null=True, verbose_name='漏洞类型')
    vul_desc = models.TextField(blank=True, null=True, verbose_name='漏洞描述')
    vul_leakLevel = models.IntegerField(choices=LEAK_LEVEL, null=True, blank=True, default=1, verbose_name='漏洞等级')
    vul_device_name = models.CharField(max_length=200, null=True, blank=True, verbose_name='设备类型')
    vul_permissions = models.IntegerField(choices=VUL_Permissions, null=False, blank=False, default=1,
                                          verbose_name='poc执行结果查看权限')
    vul_vulDate = models.DateField(default=timezone.now, verbose_name='漏洞公开日期', null=True)
    vul_createDate = models.DateField(default=timezone.now, verbose_name='poc编写时间', null=True)
    vul_updateDate = models.DateField(default=timezone.now, verbose_name='poc更新时间', null=True)
    is_active = models.CharField(max_length=10, blank=False, null=False, default=True, verbose_name='是否启用')
    has_exp = models.BooleanField(blank=False, null=False, default=False, verbose_name='是否有exp')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    create_user = models.ForeignKey(to=AuthUser, null=True, on_delete=models.SET_NULL, related_name='vul_user_id',
                                    to_field='id')

    class Meta:
        db_table = 'vulnerability'
        # 创建索引
        indexes = [models.Index(
            fields=['vul_author', 'vul_name', 'vul_type', 'vul_leakLevel',
                    'vul_device_name', 'vul_vulDate'])]


class TargetManager(models.Model):
    """
    创建任务管理中心
    """
    STATUS_TYPE = (
        (-1, '停止'),
        (0, '初始化'),
        (1, '运行中'),
        (2, '完成'),
        (3, '删除'),
        (4, '失败'),
        (5, '未知错误'),
    )
    PROXY_TYPE = (
        (0, '不使用代理'),
        (1, '使用代理'),
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
    id = models.UUIDField(primary_key=True)
    host = models.TextField(null=False, blank=False, verbose_name='目标地址')
    desc = models.CharField(max_length=50, default=None, null=True, blank=True, verbose_name='任务描述')
    status = models.IntegerField(choices=STATUS_TYPE, default=0, null=False, blank=False, verbose_name='任务状态')
    is_domain = models.BooleanField(default=False, null=False, blank=False, verbose_name='是否收集子域名')
    proxy_type = models.IntegerField(choices=PROXY_TYPE, default=0, null=False, blank=False,
                                     verbose_name='是否使用代理')
    poc_type = models.IntegerField(choices=POC_TYPE, default=0, null=False, blank=False, verbose_name='使用的poc类型')
    scanning_speed = models.IntegerField(choices=SPEED_TYPE, default=1, null=False, blank=0, verbose_name='扫描速度')
    task_count = models.IntegerField(default=0, null=False, blank=False, verbose_name='任务数量')
    finish_task_count = models.IntegerField(default=0, null=False, blank=False, verbose_name='任务完成数量')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    update_time = models.DateTimeField(auto_now=True, null=True, blank=True, verbose_name='更新时间')
    create_user = models.ForeignKey(to=AuthUser, on_delete=models.CASCADE, related_name='user_scan_name', to_field='id',
                                    verbose_name='任务创建者')
    poc_warehouse_ids = models.ManyToManyField(to=Vulnerability, related_name='poc_plugins', through='TargetToPocs',
                                               through_fields=['target_id', 'leaking_id'])

    class Meta:
        db_table = 'target_manager'


class TargetToPocs(models.Model):
    """
    多对多表关联中转站
    创建任务管理中心表和漏洞表之间的关联
    """
    target_id = models.ForeignKey(to=TargetManager,
                                  null=True,
                                  blank=False,
                                  on_delete=models.SET_NULL, verbose_name='关联任务管理表')
    leaking_id = models.ForeignKey(to=Vulnerability, null=True, blank=False, on_delete=models.SET_NULL,
                                   verbose_name='关联漏洞表')

    class Meta:
        db_table = 'target_to_poc'
        unique_together = ("target_id", "leaking_id")
        # 索引
        index_together = ['target_id', 'leaking_id']


class IotTasks(models.Model):
    """
    celery任务管理器
    """
    TaskType = (
        (1, '目标扫描'),
        (2, '端口扫描')
    )
    STATUS_CHOICES = (
        (0, '初始化'),
        (1, '进行中'),
        (2, '完成'),
        (3, '失败'),
        (4, '删除'),
        (5, '未知错误')
    )
    id = models.AutoField(primary_key=True)
    business_id = models.ForeignKey(to=TargetManager, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='task_iot_target', to_field='id', verbose_name="任务id")
    business_type = models.IntegerField(choices=TaskType, null=False, blank=False,
                                        verbose_name='任务类型，目标扫描任务or端口扫描任务')
    leaking_house = models.ForeignKey(to=Vulnerability, on_delete=models.SET_NULL,
                                      null=True, blank=True,
                                      related_name='task_leaking_target',
                                      to_field='id', verbose_name='使用的POC')
    task_id = models.CharField(max_length=200, null=False, blank=False, verbose_name='celery任务ID')
    params = models.TextField(default=None, null=True, blank=True,
                              verbose_name='任务参数:任务丢失后重启所使用参数')
    result = models.TextField(default=None, null=True, blank=True, verbose_name='任务结果')
    status = models.IntegerField(choices=STATUS_CHOICES, default=0, verbose_name='celery任务状态')
    start_time = models.DateTimeField(auto_now_add=True, null=False, blank=False,
                                      verbose_name='任务开始时间')
    remark = models.CharField(max_length=800, default=None, null=True, blank=True, verbose_name='异常信息')
    end_time = models.DateTimeField(null=True, blank=True, verbose_name='任务完成时间')
    create_time = models.DateTimeField(auto_now_add=True, null=False, blank=False,
                                       verbose_name="任务创建时间")
    update_time = models.DateTimeField(auto_now=True, null=True, blank=True,
                                       verbose_name="任务更新时间")
    create_user = models.ForeignKey(to=AuthUser, on_delete=models.SET_NULL, null=True, related_name='create_user',
                                    to_field='id', verbose_name='任务创建的用户')

    class Meta:
        db_table = "iot_tasks"
        # 索引
        index_together = ['business_id', 'business_type', 'status', 'task_id']


class IotTaskPortResult(models.Model):
    """
    端口扫描任务结果明细表
    """
    STATUS_CHOICES = (
        (0, 'failure '),
        (1, 'success')
    )
    id = models.AutoField(primary_key=True)
    scan_host = models.CharField(max_length=20, blank=False, null=False, verbose_name='端口扫描的host地址')
    scan_result = models.TextField(default=None, null=True, blank=True, verbose_name='扫描端口的结果，json格式')
    status = models.IntegerField(choices=STATUS_CHOICES, default=1, verbose_name='端口扫描状态')
    iot_task_id = models.ForeignKey(to=IotTasks, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='task_port_result_id', to_field='id', related_query_name='任务id')
    target_id = models.ForeignKey(to=TargetManager, on_delete=models.SET_NULL, null=True, blank=True,
                                  related_name='iot_task_port_result_ids', to_field='id',
                                  related_query_name="主任务id")
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间/任务完成时间')

    class Meta:
        db_table = 'iot_tasks_port_result'


class IotTaskFingerResult(models.Model):
    """
    资产信息表
    """
    id = models.AutoField(primary_key=True)
    host = models.GenericIPAddressField(blank=False, null=False, verbose_name='host地址')
    port = models.IntegerField(blank=False, null=False, verbose_name='端口号')
    scan_type = models.CharField(max_length=10, blank=False, null=False, verbose_name='扫描类型')
    port_service = models.CharField(max_length=255, blank=True, null=True, verbose_name='端口的协议类型')
    url = models.CharField(max_length=255, blank=False, null=False, verbose_name='url地址')
    scheme = models.CharField(max_length=255, blank=True, null=True, verbose_name='http的协议类型')
    cms = models.CharField(max_length=255, blank=True, null=True, verbose_name='指纹信息')
    title = models.TextField(blank=True, null=True, verbose_name='站点的title信息')
    status_code = models.IntegerField(blank=True, null=True, verbose_name='站点状态码')
    redirect_num = models.IntegerField(default=0, blank=False, null=False, verbose_name='站点重定向or跳转次数')
    server = models.CharField(max_length=255, blank=True, null=True, verbose_name='站点的server信息')
    is_cdn = models.BooleanField(default=False, blank=False, null=False, verbose_name='站点是否有cdn')
    cdn_ip_list = models.TextField(blank=True, null=True, verbose_name='域名转ip，验证cdn产生的ip信息')
    icon_hash = models.CharField(max_length=255, blank=True, null=True, verbose_name='icon hash')
    cert = models.TextField(blank=True, null=True, verbose_name='ssl证书信息')
    icp = models.CharField(max_length=100, default=None, blank=True, null=True, verbose_name='ICP备案信息')
    headers = models.TextField(blank=True, null=True, verbose_name='响应头')
    country = models.CharField(max_length=200, default=None, blank=True, null=True, verbose_name='ip国家')
    region = models.CharField(max_length=200, default=None, blank=True, null=True, verbose_name='ip区域')
    province = models.CharField(max_length=200, default=None, blank=True, null=True, verbose_name='ip省份')
    city = models.CharField(max_length=200, default=None, blank=True, null=True, verbose_name='ip城市')
    isp = models.CharField(max_length=200, default=None, blank=True, null=True, verbose_name='ip运营商')
    target_id = models.ForeignKey(to=TargetManager, on_delete=models.SET_NULL, null=True, blank=True,
                                  related_name='iot_task_finger_result_ids', to_field='id',
                                  related_query_name="主任务id")
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间/任务完成时间')

    class Meta:
        db_table = 'iot_tasks_finger_result'


class IotTaskSensitiveInformation(models.Model):
    """
    信息泄漏表，例如备份文件，js ak sk等等
    """
    Type = {
        (0, '备份文件'),
        (1, '敏感信息')
    }
    id = models.AutoField(primary_key=True)
    url = models.CharField(max_length=255, default=None, blank=True, null=True, verbose_name='url地址')
    description = models.CharField(max_length=255, default=None, blank=True, null=True, verbose_name='url信息')
    type = models.IntegerField(choices=Type, default=1, verbose_name='数据类型')
    create_time = models.DateTimeField(auto_now_add=True, verbose_name='发现时间')


class IotTaskPocResult(models.Model):
    """
    POC任务结果明细表
    """
    STATUS_CHOICES = (
        (0, 'failure '),
        (1, 'success')
    )
    id = models.AutoField(primary_key=True)
    vul_id = models.ForeignKey(to=Vulnerability, on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='task_result_leaking_house', to_field='id')
    iot_task_id = models.ForeignKey(to=IotTasks, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='task_poc_result_id', to_field='id', related_query_name='任务id')
    target_id = models.ForeignKey(to=TargetManager, on_delete=models.SET_NULL, null=True, blank=True,
                                  related_name='iot_task_poc_result_ids', to_field='id', related_query_name="主任务id")
    status = models.IntegerField(choices=STATUS_CHOICES, default=1, verbose_name='POC状态')
    host = models.CharField(max_length=130, null=False, blank=False, verbose_name='目标地址')
    result = models.TextField(default=None, null=True, blank=True, verbose_name='POC执行结果')
    create_time = models.DateTimeField(auto_now_add=True, null=False, blank=False, verbose_name='创建时间/任务完成时间')

    class Meta:
        db_table = 'iot_tasks_poc_result'


class ExportReport(models.Model):
    """
    导出报告明细表
    """
    id = models.UUIDField(primary_key=True, auto_created=True)
    create_user = models.ForeignKey(to=AuthUser, on_delete=models.CASCADE, related_name='ExportReportUser',
                                    to_field='id',
                                    verbose_name='创建导出的用户')
    title = models.CharField(max_length=200, null=False, blank=False, verbose_name='报告名字')
    filename = models.CharField(max_length=200, null=False, blank=False, verbose_name='生成的报告文件名字')
    create_time = models.DateTimeField(auto_now_add=True, null=False, blank=False, verbose_name='报告的生成时间')

    class Meta:
        db_table = 'export_report'


class FofaSetting(models.Model):
    """
    fofa相关信息配置表
    """
    id = models.AutoField(primary_key=True)
    fofa_email = models.CharField(max_length=50, null=False, blank=False, verbose_name='fofa邮箱配置')
    fofa_key = models.CharField(max_length=100, null=False, blank=False, verbose_name='fofa key配置')
    fofa_size = models.IntegerField(null=False, blank=False, default=100,
                                    verbose_name='fofa api最大获取数据条数')
    fofa_status = models.CharField(max_length=10, null=False, blank=False, default=False,
                                   verbose_name='是否启用，默认不启用')
    create_time = models.DateTimeField(auto_now=True, null=False, blank=False, verbose_name='报告的生成时间')
    create_user = models.ForeignKey(to=AuthUser, on_delete=models.CASCADE, related_name='FofatUser', to_field='id',
                                    verbose_name='创建fofa api配置用户')

    class Meta:
        db_table = 'fofa_setting'
