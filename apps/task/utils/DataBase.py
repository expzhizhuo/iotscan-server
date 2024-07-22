"""
@Project ：iotscan 
@File    ：DataBase.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/8/14 02:16 
"""
import json
import logging

from django.db import transaction

from apps.models.models import *
from apps.task.utils.DbConnectClass import handle_db_connections

log = logging.getLogger('tasks-server-api')


def UpdateTargetManagerDataBase(task_ids, status):
    """
    更新总任务表中的任务状态
    :param task_ids:总任务id
    :param status:任务状态
    :return:
    """
    log.info(f"更新总任务id：{task_ids}任务状态")
    with transaction.atomic():
        TargetManager.objects.filter(id=task_ids).update(status=status)
    log.info(f"更新总任务id：{task_ids}任务状态成功")


@handle_db_connections
def UpdateTargetManagerFinishDataBase(task_ids: str, finsh_count: int = 1):
    """
    更新总任务表的完成任务数量
    :param finsh_count: 完成任务数量
    :param task_ids:总任务id
    :return:
    """
    log.info(f"更新总任务id：{task_ids}任务完成数量")
    with transaction.atomic():
        try:
            finish_data = TargetManager.objects.select_for_update().get(id=task_ids)
            if finish_data:
                total = int(finish_data.task_count)
                finish = int(finish_data.finish_task_count)
                diff_count = int(total - finish)
                log.info(f"待完成：{diff_count}")
                log.info(f"总任务数量：{total}")
                log.info(f"完成任务数量：{finish}")
                if finish == total:
                    finish_data.finish_task_count = total
                    finish_data.status = 2
                    finish_data.save()
                    log.info(f"总任务id：{task_ids}所有任务已完成")
                else:
                    if diff_count == 1:
                        finish_data.status = 2
                        finish_data.finish_task_count = total
                        finish_data.save()
                        log.info(f"总任务id：{task_ids}所有任务已完成")
                    else:
                        finish_data.finish_task_count = finish + finsh_count
                        if finish + finsh_count >= total:
                            finish_data.status = 2
                        finish_data.save()
                        log.info(f"总任务id：{task_ids}任务完成数量更新成功")
            else:
                log.error(f"异常总任务id：{task_ids}")
        except Exception as e:
            log.error(f"数据库更新出错，错误信息：{e}")


def CreateTasksToDataBase(tasks_ids, config, tasks_run_ids, create_user, poc=None):
    """
    进行数据库存储
    这里操作的是celery管理表
    :param tasks_ids:业务主键
    :param config:任务启动参数
    :param tasks_run_ids:任务列表
    :param create_user:创建者
    :param poc:poc信息
    :return:
    """
    log.info(f"用户id：{create_user}进行celery任务初始化创建数据")
    log.info(f"任务{tasks_ids}进行数据库保存，保存数据{config, poc, tasks_run_ids}")
    poc_id = None
    if poc is not None:
        poc_id = poc.get("id")
    with transaction.atomic():
        a = IotTasks(
            business_id_id=tasks_ids,
            business_type=1,
            task_id=tasks_run_ids,
            params=config,
            create_user_id=create_user,
            leaking_house_id=poc_id
        )
        a.save()
    log.info("celery任务初始化数据保存成功")


def TestToDb(data):
    """
    测试批量创建任务
    :param data:
    :return:
    """
    log.info(f"需要批量创建任务{len(data)}个")
    create_data = list()
    with transaction.atomic():
        for tasks in data:
            poc_id = None
            if tasks.get('poc') is not None:
                poc_id = tasks.get('poc').get('id')
            create_data.append(
                IotTasks(
                    business_id_id=tasks.get("tasks_ids"),
                    business_type=1,
                    task_id=tasks.get("tasks_run_ids"),
                    params=tasks.get("config"),
                    create_user_id=tasks.get("create_user"),
                    leaking_house_id=poc_id
                )
            )
        IotTasks.objects.bulk_create(create_data)
    log.info("批量创建完成")


@handle_db_connections
def UpdateTasksToDataBase(task_id, data):
    """
    celery任务管理器状态结果更新
    :param task_id:子任务id
    :param data:数据
    :return:
    """
    log.info("celery任务结果数据更新")
    with transaction.atomic():
        try:
            celery_data = IotTasks.objects.get(task_id=task_id)
        except IotTasks.DoesNotExist:
            log.error(f"异常任务id：{task_id}")
            return
        celery_data.status = data.get("status")
        celery_data.result = data.get("result")
        celery_data.remark = data.get("remark")
        celery_data.end_time = data.get("end_time")
        celery_data.save()
    log.info("celery任务结果数据更新成功")


@handle_db_connections
def CreatePortResultToDataBase(task_ids, data, poc_id, task_id):
    """
    创建任务结果明细
    :param task_ids:主任务id
    :param data:执行结果
    :param poc_id:poc id
    :param task_id:子任务id
    :return:
    """
    log.info(f"执行任务结果明细存储")
    log.info(f"存储数据：{task_ids} {json.dumps(data)} {poc_id} {task_id}")
    log.info(f"长度：{len(data)}")
    save_data = list()
    with transaction.atomic():
        # 使用事务处理防止出现条件竞争
        for i in data:
            log.info(f"正在遍历处理结果数据")
            log.info(f"正在处理数据：{i}")
            save_data.append(
                IotTaskPocResult(vul_id_id=poc_id,
                                 iot_task_id_id=IotTasks.objects.get(business_id=task_ids, task_id=task_id).id,
                                 target_id_id=task_ids,
                                 status=i.get("status"),
                                 host=i.get("host"),
                                 result=json.dumps(i.get("result"), ensure_ascii=False)
                                 )
            )
        # 直接批量创建减少io操作
        IotTaskPocResult.objects.bulk_create(save_data)
        log.info(f"主任务：{task_ids}子任务：{task_id}执行结果保存成功")


@handle_db_connections
def CreatePortScanResult(task_ids, data, task_id):
    """
    创建端口扫描结果明细
    :param task_ids:主任务id
    :param data:端口扫描结果
    :param task_id:子任务id
    :return:
    """
    log.info(f"执行端口扫描结果保存操作")
    log.info(f"储存数据{json.dumps(data)}  数据长度{len(data)}")
    save_data = list()
    with transaction.atomic():
        # 事物操作避免出现条件竞争
        save_data.append(
            IotTaskPortResult(
                scan_host=data.get('host'),
                scan_result=json.dumps(data.get("result"), ensure_ascii=False),
                status=data.get("status"),
                iot_task_id_id=IotTasks.objects.get(business_id=task_ids, task_id=task_id).id,
                target_id_id=task_ids
            )
        )
    IotTaskPortResult.objects.bulk_create(save_data)
    log.info(f"主任务：{task_ids}子任务：{task_id}执行结果保存成功")


def CreateFingerScanResult(task_ids, data, task_id):
    """
    创建指纹扫描结果明细
    :param task_ids:主任务id
    :param data:指纹扫描结果
    :param task_id:子任务id
    :return:
    """
    log.info(f"执行指纹扫描结果保存操作")
    log.info(f"储存数据{json.dumps(data)}  数据长度{len(data)}")
    result_list = data.get("result")
    save_data = list()
    with transaction.atomic():
        # 事物操作避免出现条件竞争
        for result in result_list:
            save_data.append(
                IotTaskFingerResult(
                    host=data.get("host"),
                    url=result.get("finger").get("url"),
                    port=result.get("finger").get("port"),
                    scan_type=result.get("finger").get("scan_type"),
                    port_service=result.get("finger").get("port_service"),
                    scheme=result.get("finger").get("scheme"),
                    cms=result.get("finger").get("cms"),
                    title=result.get("finger").get("title"),
                    status_code=result.get("finger").get("status_code"),
                    redirect_num=result.get("finger").get("redirect_num"),
                    server=result.get("finger").get("server"),
                    is_cdn=result.get("finger").get("is_cdn").get("is_cdn"),
                    cdn_ip_list=result.get("finger").get("is_cdn").get("ip_list"),
                    icon_hash=result.get("finger").get("icon_hash"),
                    cert=json.dumps(result.get("finger").get("cert"), ensure_ascii=False),
                    icp=result.get("finger").get("icp"),
                    headers=result.get("finger").get("res_headers"),
                    country=result.get("finger").get("ip_info").get("country"),
                    region=result.get("finger").get("ip_info").get("region"),
                    province=result.get("finger").get("ip_info").get("province"),
                    city=result.get("finger").get("ip_info").get("city"),
                    isp=result.get("finger").get("ip_info").get("isp"),
                    target_id_id=task_ids
                )
            )
        IotTaskFingerResult.objects.bulk_create(save_data)
    log.info(f"主任务：{task_ids}子任务：{task_id}执行结果保存成功")


def CreateSensitiveInformationResult(task_ids, data, task_id):
    """
    创建敏感信息结果明细
    :param task_ids: 主任务id
    :param data: 指纹扫描结果
    :param task_id: 子任务id
    :return:
    """
    log.info(f"执行敏感信息结果保存操作")
    log.info(f"储存数据{json.dumps(data)}  数据长度{len(data)}")
    result_list = data.get("result")


def UpdateTasksCount(task_ids, count):
    """
    更新任务数量
    :param task_ids:主任务id
    :param count:需要新增的数量
    :return:
    """
    log.info("更新总数据库任务数量")
    target = TargetManager.objects.filter(id=task_ids).first()
    target_count = target.task_count + count
    log.info(f"总任务数量为{target_count}，原任务数量为{target.task_count}")
    TargetManager.objects.filter(id=task_ids).update(task_count=target_count)
