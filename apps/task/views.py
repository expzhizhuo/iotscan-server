import base64
from celery.result import AsyncResult
from django.db.models import Q, Count
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from common.permission import Permission
from .serializers import *
from common.response import response
from rest_framework.permissions import IsAuthenticated
from .tasks import *
from common.common_task import *
from .utils.VerifyData import *
from iotscan.celery import app as celery_app

log = logging.getLogger('tasks-server-api')


# Create your views here.
class ScanListView(viewsets.ViewSet):
    """
    扫描列表
    """
    http_method_names = ['get', 'post', 'put', 'delete']
    permission_classes = [IsAuthenticated]
    serializer_class = TaskScanSerializers
    queryset = IotTasks.objects.all()

    def list(self, request, pk=None):
        """
        获取任务列表数据
        :return: list
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}执行获取任务列表操作")
        try:
            request_data = SearchTaskListSerializers(data=request.GET)
            if request_data.is_valid():
                keyword = request_data.data.get('search')
                query = Q(id__startswith=keyword) | Q(host__contains=keyword) | Q(desc__contains=keyword) | Q(
                    create_user__username__contains=keyword)
                if IsSuperAdmin:
                    """
                    管理员可以搜索搜有任务数据
                    """
                    tasklist_result = TargetManager.objects.filter(query).order_by('-create_time')
                else:
                    tasklist_result = TargetManager.objects.filter(query, create_user=request.user.id).order_by(
                        '-create_time')
            else:
                if IsSuperAdmin:
                    """
                    非管理员只能查看自己创建的
                    """
                    tasklist_result = TargetManager.objects.all().order_by('-create_time')
                else:
                    tasklist_result = TargetManager.objects.filter(create_user=request.user.id).order_by('-create_time')
            page = TasksPageNumberPagination()
            page_data = page.paginate_queryset(queryset=tasklist_result,
                                               request=request, view=self)
            data = TaskScanSerializers(page_data, many=True)
            page.get_paginated_response(data.data)
            return response.success({"total": page.page.paginator.count, "list": data.data})
        except Exception as e:
            log.error(f"用户{request.user}获取创建扫描任务操作出错，错误信息{e}")
            return response.server_error(e)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def create_task(self, request, pk=None):
        """
        创建扫描任务
        :param request: 请求数据
        :param pk: None
        :return:
        """
        task_count = 0
        log.info(f"用户{request.user}执行创建扫描任务操作")
        # try:
        print(json.dumps(request.data, ensure_ascii=False))
        request_data = TaskScanCreateSerializers(data=request.data)
        if request_data.is_valid():
            tasks_data = request_data.data
            if len(request_data.data.get("host")) == 0:
                return response.error("请输入目标")
            try:
                verify = target_verify(request_data.data.get("host"))
                if not verify:
                    return response.error("异常扫描目标")
                tasks_data.update({"host": verify})
            except Exception as e:
                return response.error(e)
            # 获取poc文件名字
            poc_file = []
            if request_data.data.get("poc_type") == 0:
                poc_file = Vulnerability.objects.all()
            elif request_data.data.get("poc_type") == -1:
                poc_file = []
            elif request_data.data.get("poc_type") == 5:
                for poc_id in request_data.data.get("poc_warehouse_ids"):
                    # 遍历查询出来所有的数据添加到poc_file数组中
                    poc_file_data = Vulnerability.objects.filter(id=poc_id).first()
                    poc_file.append(poc_file_data)
            else:
                poc_file = Vulnerability.objects.filter(vul_leakLevel=request_data.data.get("poc_type"))
            """
            for循环遍历创建扫描任务，一个poc对应多个目标
            一个poc对应多个目标，通过poc数量计算任务数量进而计算任务进度
            但是会出现一个问题，任务表会很大很大
            """
            poc_list = []
            poc_list_ids = []
            for poc in poc_file:
                poc_list.append({"id": str(poc.id), "file_name": poc.file_name})
                poc_list_ids.append(poc.id)
            host_list = tasks_data.get("host")
            if tasks_data.get("is_use_port_scan") and tasks_data.get("poc_type") == -1:
                task_count = len(host_list) * 2
            elif tasks_data.get("is_use_port_scan") and tasks_data.get("poc_type") != -1:
                task_count = len(host_list) * 2 + int(len(poc_list)) * int(len(host_list))
            elif tasks_data.get("poc_type") != -1 and tasks_data.get("is_use_port_scan") is False:
                task_count = len(poc_list)
            # 这里可能需要一个事务去创建数据
            with transaction.atomic():
                tasks_id = iotscan_create.delay(tasks_data, poc_list, request.user.id, 10)
                IotScanCreate = TargetManager.objects.create(
                    id=tasks_id.id,
                    create_user=request.user,
                    host=request_data.data.get("host"),
                    desc=request_data.data.get("desc"),
                    is_domain=request_data.data.get("is_use_domainscan"),
                    poc_type=request_data.data.get("poc_type"),
                    proxy_type=request_data.data.get("is_use_proxy"),
                    scanning_speed=request_data.data.get("scanning_speed"),
                    task_count=task_count  # 任务数量
                )
            IotScanCreate.poc_warehouse_ids.add(*poc_list_ids, through_defaults={})
            return response.success({"messages": "创建成功", "tasks_id": tasks_id.id, "status": 0})
        return response.error("上传数据不完整")
        # except Exception as e:
        #     log.error(f'用户{request.user}执行创建扫描任务操作出错，错误信息{e}')
        #     return response.server_error(e)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def get_tasks_status_details(self, request, pk=None):
        """
        查看单个任务执行状态or进度
        :param request:
        :param pk:
        :return:
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        task_id = request.GET.get("task_id")
        log.info(f"用户{request.user}执行查看任务{task_id}执行状态操作")
        try:
            if task_id is None:
                return response.error("异常请求")
            else:
                if IsSuperAdmin:
                    # 管理员可以查看任何人的任何任务进度
                    tasks_status_result = TargetManager.objects.filter(id=task_id)
                else:
                    # 非管理只能查询自己的
                    tasks_status_result = TargetManager.objects.filter(id=task_id, create_user=request.user)
                data = GetTaskStatusSerializers(tasks_status_result, many=True, read_only=True)
                return response.success(data.data[0])
        except Exception as e:
            log.error(f"用户{request.user}执行查看任务{task_id}执行状态操作出错，错误信息{e}")
            return response.server_error(e)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def task_setting(self, request, pk=None):
        """
        停止正在运行的任务
        :param request:
        :param pk:
        :return:
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户：{request.user}正在进行任务停止操作")
        stop_ids = StopOrStartOrDeleteTasksSerializers(data=request.POST)
        if not stop_ids.is_valid():
            return response.error("上传数据不完整")
        target_list = IotTasks.objects.filter(business_id=stop_ids.data.get("task_ids"), status__in=[0, 1])
        if not IsSuperAdmin:
            target_list = target_list.filter(create_user=request.user)
        tasks_list = list(target_list.values_list('task_id', flat=True))
        if stop_ids.data.get('task_status') == 0:
            for i in tasks_list:
                task_result = AsyncResult(i)
                if not task_result.ready() and not task_result.failed():
                    celery_app.control.revoke(task_id=i, signal='SIGTERM', terminate=True)
                with transaction.atomic():
                    task_data = IotTasks.objects.get(task_id=i)
                    poc_info = Vulnerability.objects.filter(id=task_data.leaking_house)
                    new_task = iotscan_pocscan.delay(task_ids=task_data.business_id, config=task_data.params,
                                                     proxy=0, poc=poc_info, timeout=10)
                    t = IotTasks(task_id=new_task.id)
                    t.save()
            TargetManager.objects.filter(id=stop_ids.data.get("task_ids")).update(status=1)
        elif stop_ids.data.get('task_status') == 1:
            # 将撤销操作放入Celery任务中异步执行以提高响应性
            revoke_celery_tasks.delay(tasks_list)
            TargetManager.objects.filter(id=stop_ids.data.get("task_ids")).update(status=-1)
        elif stop_ids.data.get('task_status') == 2:
            # 将撤销操作放入Celery任务中异步执行以提高响应性
            revoke_celery_tasks.delay(tasks_list)
            TargetManager.objects.filter(id=stop_ids.data.get("task_ids")).update(status=-1)
        else:
            return response.error("异常操作")
        return response.success("操作成功")

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def task_delete(self, request, pk=None):
        """
        删除任务操作
        :param request:
        :param pk:
        :return:
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}进行任务删除操作")
        delete_data = DeleteTaskSerializers(data=request.POST)
        if delete_data.is_valid():
            tasks_id = delete_data.data.get('tasks_id')
            if IsSuperAdmin:
                # 管理员可以删除任何人的
                delete_list_info = TargetManager.objects.filter(id=tasks_id)
            else:
                delete_list_info = TargetManager.objects.filter(id=tasks_id, create_user=request.user)
            if delete_list_info:
                celery_data_info = IotTasks.objects.filter(business_id=tasks_id)
                celery_list = list(celery_data_info.values_list('task_id', flat=True))
                if celery_list:
                    # 将撤销操作放入Celery任务中异步执行以提高响应性
                    remove_task_id = revoke_celery_tasks.delay(celery_list)
                    log.info(f"撤销任务创建完成，任务id{remove_task_id.id}")
                celery_data_info.delete()
                delete_list_info.delete()
                return response.success("删除成功")
            else:
                log.error(f"删除任务{delete_data.data.get('task_id')}出错")
                return response.error("删除失败，当前任务不存在")
        else:
            return response.error(delete_data.errors.get('task_id')[0])


class ScanResultListView(viewsets.ViewSet):
    """
    扫描结果列表
    """
    http_method_names = ['get', 'post']
    queryset = IotTaskPocResult.objects.all()
    permission_classes = [IsAuthenticated]

    def list(self, request, pk=None):
        """
        获取所有扫描结果
        :return: list
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f'用户{request.user}执行获取所有扫描结果操作')
        try:
            verify_data = GetTaskResultVerifySerializers(data=request.GET)
            if verify_data.is_valid():
                task_id = verify_data.data.get('task_id')
                task_type = verify_data.data.get('task_type')
                keyword = verify_data.data.get('search')
                base_query = Q(target_id=task_id)
                if not IsSuperAdmin:
                    base_query &= Q(target_id__create_user=request.user)
                if task_type == 0:
                    query = Q(scan_result__contains=keyword) if keyword else Q()
                    task_result_list = IotTaskPortResult.objects.filter(
                        base_query & query
                    ).exclude(scan_result="[]").order_by('-id')
                elif task_type == 1:
                    query = (Q(vul_id__poc_name__contains=keyword) |
                             Q(vul_id__vul_type__contains=keyword) |
                             Q(vul_id__vul_device_name__contains=keyword) |
                             Q(vul_id__vul_desc__contains=keyword)) if keyword else Q()
                    task_result_list = IotTaskPocResult.objects.filter(base_query & query & Q(status=1)).order_by('-id')
                else:
                    task_result_list = None
                if task_result_list is not None:
                    page = TasksPageNumberPagination()
                    page_data = page.paginate_queryset(queryset=task_result_list, request=request, view=self)
                    serializer_class = GetTaskPortResultSerializers if task_type == 0 else GetTaskPocResultSerializers
                    data = serializer_class(page_data, many=True, read_only=True)
                    page.get_paginated_response(data.data)
                    return response.success({"total": page.page.paginator.count, "list": data.data})
                return response.error("输入异常")
            else:
                error_key = next(iter(verify_data.errors))
                return response.error(f"{error_key}{verify_data.errors[error_key][0]}")
        except Exception as e:
            log.error(f'用户{request.user}执行获取扫描结果操作出错，错误信息{e}')
            return response.server_error("系统异常")

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def get_statistics(self, request, pk=None):
        """
        获取资产页面的统计信息
        :param request:
        :param pk:
        :return:
        """
        log.info(f'用户{request.user}执行任务列表操作')
        task_ids = request.GET.get("task_ids")
        query_base64 = request.GET.get("search") or request.data.get("search")
        try:
            if query_base64:
                query = base64.b64decode(query_base64).decode('utf-8', 'ignore')
                print('search', query)
                query = common_tool.dynamic_query(query_str=query)
                print('search sql', query)
                status = IotTaskFingerResult.objects.filter(query, target_id=task_ids,
                                                            status_code__isnull=False).values(
                    "status_code").annotate(count=Count("id")).values('status_code', 'count').order_by('-count')[:10]
                cms = IotTaskFingerResult.objects.filter(query, target_id=task_ids, cms__isnull=False).values(
                    "cms").annotate(
                    count=Count("id")).values('cms', 'count').order_by('-count')[:10]
                scheme = IotTaskFingerResult.objects.filter(query, target_id=task_ids, scheme__isnull=False).values(
                    "scheme").annotate(
                    count=Count("id")).values('scheme', 'count').order_by('-count')[:10]
                title = IotTaskFingerResult.objects.filter(query, target_id=task_ids, title__isnull=False).values(
                    "title").annotate(
                    count=Count("id")).values('title', 'count').order_by('-count')[:10]
                port = IotTaskFingerResult.objects.filter(query, target_id=task_ids, port__isnull=False).values(
                    "port").annotate(
                    count=Count("id")).values('port', 'count').order_by('-count')[:10]
                port_service = IotTaskFingerResult.objects.filter(query, target_id=task_ids, port__isnull=False).values(
                    "port_service").annotate(count=Count("id")).values('port_service', 'count').order_by('-count')[:10]
            else:
                status = IotTaskFingerResult.objects.filter(target_id=task_ids, status_code__isnull=False).values(
                    "status_code").annotate(count=Count("id")).values('status_code', 'count').order_by('-count')[:10]
                cms = IotTaskFingerResult.objects.filter(target_id=task_ids, cms__isnull=False).values("cms").annotate(
                    count=Count("id")).values('cms', 'count').order_by('-count')[:10]
                scheme = IotTaskFingerResult.objects.filter(target_id=task_ids, scheme__isnull=False).values(
                    "scheme").annotate(
                    count=Count("id")).values('scheme', 'count').order_by('-count')[:10]
                title = IotTaskFingerResult.objects.filter(target_id=task_ids, title__isnull=False).values(
                    "title").annotate(
                    count=Count("id")).values('title', 'count').order_by('-count')[:10]
                port = IotTaskFingerResult.objects.filter(target_id=task_ids, port__isnull=False).values(
                    "port").annotate(
                    count=Count("id")).values('port', 'count').order_by('-count')[:10]
                port_service = IotTaskFingerResult.objects.filter(target_id=task_ids, port__isnull=False).values(
                    "port_service").annotate(count=Count("id")).values('port_service', 'count').order_by('-count')[:10]
            return response.success(
                dict(status=status, cms=cms, scheme=scheme, title=title, port=port, port_service=port_service))
        except Exception as e:
            log.error(f"获取资产统计信息报错，错误信息:{e}")
            return response.success()


class SearchTaskResultView(viewsets.ViewSet):
    """
    资产搜索和聚合接口
    """
    http_method_names = ['get', 'post']
    queryset = IotTaskFingerResult.objects.all()
    permission_classes = [IsAuthenticated]

    def list(self, request, pk=None):
        """
        获取资产列表
        :param request:请求数据包
        :param pk:传送参数
        :return:json
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        request_data = GetFingerResultSerializers(data=request.GET)
        log.info(f'用户{request.user}执行获取资产扫描结果操作')
        if request_data.is_valid():
            if IsSuperAdmin:
                result_list = IotTaskFingerResult.objects.filter(
                    target_id_id=request_data.data.get('tasks_id')).order_by('-id')
            else:
                result_list = IotTaskFingerResult.objects.filter(target_id_id=request_data.data.get('tasks_id'),
                                                                 target_id__create_user=request.user).order_by('-id')
            page = TasksPageNumberPagination()
            page_data = page.paginate_queryset(queryset=result_list, request=request, view=self)
            data = GetFingerResultResponseSerializers(page_data, many=True, read_only=True)
            return response.success({"total": page.page.paginator.count, "list": data.data})

        return response.error("请求参数错误")

    @action(detail=False, methods=['get', 'post'], permission_classes=[permissions.IsAuthenticated])
    def search(self, request, pk=None):
        """
        使用特定语句进行资产信息搜索
        :param request:
        :param pk:
        :return:
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f'用户{request.user}执行资产搜索操作')
        query_base64 = request.GET.get("query") or request.data.get("query")
        task_ids = request.GET.get("task_ids") or request.data.get("task_ids")
        if not task_ids:
            return response.error("请输入任务id")
        try:
            query = base64.b64decode(query_base64).decode('utf-8', 'ignore')
            query = common_tool.dynamic_query(query_str=query)

            if IsSuperAdmin:
                # 管理可以看所有搜索任何人创建的
                result_list = IotTaskFingerResult.objects.filter(query, target_id=task_ids).order_by('-id')
            else:
                result_list = IotTaskFingerResult.objects.filter(query, target_id=task_ids,
                                                                 target_id__create_user=request.user).order_by('-id')
            page = TasksPageNumberPagination()
            page_data = page.paginate_queryset(queryset=result_list, request=request, view=self)
            data = GetFingerResultResponseSerializers(page_data, many=True, read_only=True)
            return response.success({"total": page.page.paginator.count, "list": data.data})
        except Exception as e:
            log.error(f"搜索资产出错，错误信息:{e}")
            return response.error(f"搜索语句有错，请重新输入！")
