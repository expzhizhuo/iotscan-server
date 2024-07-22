import logging
from rest_framework import viewsets
from rest_framework.decorators import action
from common.response import response
from ..models.models import *
from rest_framework import permissions
from common.device import device_tools
from common.permission import Permission

log = logging.getLogger("home-api")


# Create your views here.
class HomeView(viewsets.ViewSet):
    """
    home主页统计类接口
    """
    http_method_names = ['get']
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request, pk=None):
        """
        获取主页统计类接口
        :param request:
        :param pk:
        :return:
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}进行home页面统计操作")
        # 任务统计
        # 默认管理员是系统中所有的
        user_targets = TargetManager.objects.all()
        task_count_total = user_targets.count()
        task_count_finish = user_targets.filter(status=2).count()
        task_count_running = user_targets.filter(status__in=[0, 1]).count()
        task_count_error = user_targets.filter(status__in=[3, 4]).count()
        # poc攻击成功统计
        poc_attack_success = IotTaskPocResult.objects.filter(status=1, target_id_id__isnull=False).count()
        # poc漏洞等级统计
        poc_critical = Vulnerability.objects.filter(vul_leakLevel=4).count()
        poc_high = Vulnerability.objects.filter(vul_leakLevel=3).count()
        poc_middle = Vulnerability.objects.filter(vul_leakLevel=2).count()
        poc_low = Vulnerability.objects.filter(vul_leakLevel=1).count()
        poc_info = Vulnerability.objects.filter(vul_leakLevel=0).count()
        poc_total = poc_critical + poc_high + poc_middle + poc_low + poc_info
        if not IsSuperAdmin:
            user_targets = TargetManager.objects.filter(create_user=request.user)
            task_count_total = user_targets.count()
            task_count_finish = user_targets.filter(status=2).count()
            task_count_running = user_targets.filter(status__in=[0, 1]).count()
            task_count_error = user_targets.filter(status__in=[3, 4]).count()
            # poc攻击成功统计
            poc_attack_success = IotTaskPocResult.objects.filter(status=1, target_id__create_user=request.user,
                                                                 target_id_id__isnull=False).count()
        task_count = dict(task_count_total=task_count_total, task_count_running=task_count_running,
                          task_count_finish=task_count_finish, task_count_error=task_count_error)
        poc_count = dict(poc_total=poc_total, poc_critical=poc_critical, poc_high=poc_high, poc_middle=poc_middle,
                         poc_low=poc_low)

        return response.success(
            dict(count=dict(task_count=task_count, poc_count=poc_count), poc_attack_success=poc_attack_success))

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def get_device_status(self, request, pk=None):
        """
        获取设备状态信息
        :param request:
        :param pk:
        :return:
        """

        return response.success(device_tools.get_device_info())

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def get_device_network(self, request, pk=None):
        """
        获取设备网卡信息
        :param request:
        :param pk:
        :return:
        """
        return response.success(
            dict(count=len(device_tools.get_network_info()), list=device_tools.get_network_info(),
                 data=device_tools.get_network_speed()))

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def get_device_network_speed(self, request, pk=None):
        """
        获取设备网络速率信息
        :param request:
        :param pk:
        :return:
        """
        return response.success(device_tools.get_network_speed_now())


class PocCountView(viewsets.ViewSet):
    """
    POC数量统计接口
    """
    http_method_names = ['get']
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request, pk=None):
        """
        获取系统中POC数量
        :param request:
        :param pk:
        :return:
        """
        log.info(f"用户{request.user}进行poc数量获取")

        poc_total = Vulnerability.objects.all().count()

        return response.success(dict(poc_total=poc_total))
