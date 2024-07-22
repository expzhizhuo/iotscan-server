"""
@Project ：iotscan 
@File    ：tasks.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/7/14 08:55 
"""
import time
from functools import wraps

from celery.exceptions import SoftTimeLimitExceeded, TimeLimitExceeded
from celery import shared_task, current_task
from common.common_task import *
from common.tools import common_tool
from .utils.DataBase import *
from .module.poc_scan import pocscan
from .module.port_scan import portscan
from .module.finger_scan import FingerScan
from .module.backup_scan import BackupAgent
from .module.domain_scan import domain_scan
from iotscan.celery import app as celery_app

log = logging.getLogger('tasks-server-api')


def handle_task_exception(task_id):
    """处理任务异常装饰器"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log.error(f"任务{task_id}执行出错: {e}", exc_info=True)
                UpdateTargetManagerDataBase(task_id, status=5)
                raise

        return wrapper

    return decorator


def log_task(func):
    """记录任务执行日志的装饰器"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        task_id = current_task.request.id
        log.info(f"任务 {func.__name__}({task_id}) 开始执行")
        try:
            result = func(*args, **kwargs)
            log.info(f"任务 {func.__name__}({task_id}) 执行完成")
            return result
        except Exception as e:
            log.error(f"任务 {func.__name__}({task_id}) 执行失败: {e}")
            raise

    return wrapper


@shared_task(name='iotscan-tasks-create', track_started=True)
@log_task
def iotscan_create(tasks_data, poc_list, create_user, timeout=10):
    """
    创建IoT扫描任务
    :param tasks_data: 任务创建所需的数据
    :param poc_list: POC文件列表
    :param create_user: 创建任务的用户
    :param timeout: 任务超时时间，默认10分钟
    :return: JSON格式的任务创建结果
    """
    log.info("任务创建start")
    tasks_ids = current_task.request.id
    proxy = None
    if tasks_data.get("is_use_proxy"):
        log.info("使用代理进行任务扫描")
        proxy = {}
    log.info(f"正在创建数据 {tasks_data}")
    try:
        if tasks_data.get("is_use_domainscan"):
            log.info("需要进行子域名扫描")
            for host in tasks_data.get("host"):
                tasks_id = uuid.uuid4().hex
                is_domain = common_tool.is_domain_name(domain=host)
                config = {
                    "host": host,
                    "port_type": tasks_data.get("port_type"),
                    "poc_type": tasks_data.get("poc_type"),
                    "poc_list": poc_list,
                    "proxy": proxy,
                    "create_user": str(create_user),
                    "tasks_ids": tasks_ids
                }
                if is_domain:
                    # 子域名扫描任务
                    config.update({"domain": host, "domain_type": tasks_data.get("domain_type")})
                    iotscan_domainscan.apply_async(kwargs={'task_ids': tasks_ids, 'config': config}, task_id=tasks_id)
                else:
                    # 端口扫描任务
                    iotscan_portscan.apply_async(kwargs={'task_ids': tasks_ids, 'config': config}, task_id=tasks_id)
                CreateTasksToDataBase(tasks_ids, json.dumps(config, ensure_ascii=False), tasks_id, create_user)  # 数据库操作
        if tasks_data.get("is_use_port_scan") and not tasks_data.get("is_use_domainscan"):
            log.info("正在创建端口扫描任务")
            log.info(f"需要创建{len(tasks_data.get('host'))}个任务")
            for host in tasks_data.get("host"):
                tasks_id = uuid.uuid4().hex
                config = dict(host=host, port_type=tasks_data.get("port_type"), poc_type=tasks_data.get("poc_type"),
                              poc_list=poc_list, proxy=proxy, create_user=str(create_user))
                # 数据库存储
                CreateTasksToDataBase(tasks_ids, json.dumps(config, ensure_ascii=False), tasks_id, create_user)
                # 创建任务
                iotscan_portscan.apply_async(kwargs={'task_ids': tasks_ids,
                                                     'config': config, }, task_id=tasks_id)
        elif tasks_data.get("poc_type") != -1 and tasks_data.get("is_use_port_scan") is False:
            log.info("正在创建poc扫描任务")
            for poc in poc_list:
                config = {
                    "url": tasks_data.get("host"),
                    "mode": "verify",
                    "poc": [f"{settings.POC_PLUGIN_PATH}/{poc.get('file_name')}"],
                    "proxy": proxy
                }
                tasks_id = uuid.uuid4().hex
                log.info(f"正在生成生成任务，任务id：{tasks_id}")
                # 数据库存储
                CreateTasksToDataBase(tasks_ids, config, tasks_id, str(create_user), poc)
                # 创建任务
                iotscan_pocscan.apply_async(kwargs={'task_ids': tasks_ids,
                                                    'config': config,
                                                    'proxy': 0,
                                                    'poc': poc,
                                                    'timeout': timeout
                                                    }, task_id=tasks_id)
        UpdateTargetManagerDataBase(tasks_ids, status=1)
    except Exception as e:
        log.error(f"任务{tasks_ids}创建出错 {e}")
        if "TypeError" in str(e) or "serializable" in str(e):
            UpdateTargetManagerDataBase(tasks_ids, status=4)
        else:
            UpdateTargetManagerDataBase(tasks_ids, status=5)
    return {"status": "success"}


@shared_task(name='iotscan-server-portscan', track_started=True, queue="portscan", soft_time_limit=120)
@log_task
def iotscan_portscan(task_ids, config):
    """
    执行端口扫描任务，限制端口扫描执行时间20分钟，如果20分钟没有出结果直接捕获异常输出
    :param task_ids:主任务id
    :param config:扫描配置
    :return:json
    """
    task_id = current_task.request.id  # 获取当前任务的id
    log.info(f"扫描任务：{task_id}")
    log.info(f"配置信息：{task_ids, config}")
    poc_type = config.get("poc_type")
    time.sleep(1)  # 每个任务都要等待1秒之后在执行
    result = {}
    try:
        # 实时更新celery数据库中的任务状态
        UpdateTasksToDataBase(task_id, dict(status=1, result=None, remark=None, end_time=None))
        result = portscan.port_scan(config.get("host"), config.get("port_type"))
        log.info(f"端口扫描结果 {result}")
        # 实时更新celery数据库中的任务状态
        UpdateTasksToDataBase(task_id,
                              dict(status=2, result=json.dumps(result, ensure_ascii=False), remark=None,
                                   end_time=timezone.now()))
        # 创建端口扫描结果明细表数据
        CreatePortScanResult(task_ids=task_ids, data=result, task_id=task_id)
        log.info("端口扫描结束")
    except (SoftTimeLimitExceeded, TimeLimitExceeded) as e:
        log.error(f"任务{task_id} 执行超时报错，错误信息：{e}")
        result = dict(error=str(e))
        UpdateTasksToDataBase(task_id,
                              dict(status=3, result=json.dumps(result, ensure_ascii=False), remark=str(e),
                                   end_time=timezone.now()))
    except Exception as e:
        log.error(f"发生未知错误，错误信息：{e}")
        result = dict(error=str(e))
        UpdateTasksToDataBase(task_id,
                              dict(status=5, result=json.dumps(result, ensure_ascii=False), remark=str(e),
                                   end_time=timezone.now()))
    finally:
        if result.get("error") is None and len(result) == 0:
            log.error(f"任务{task_id} 执行异常，未能获取结果")
            UpdateTasksToDataBase(task_id,
                                  dict(status=4, result=json.dumps(result, ensure_ascii=False),
                                       remark="任务执行异常，未能获取结果",
                                       end_time=timezone.now()))
            if poc_type != -1:
                # 更新主任务管理器的状态，如果超时报错那么就是直接完成finger和poc的两个的任务
                UpdateTargetManagerFinishDataBase(task_ids, finsh_count=len(config.get("poc_list")) + 2)
            else:
                UpdateTargetManagerFinishDataBase(task_ids)
        else:
            # 更新主任务管理器的状态
            UpdateTargetManagerFinishDataBase(task_ids)
        result.update(
            dict(poc_type=config.get("poc_type"), poc_list=config.get("poc_list"),
                 create_user=config.get("create_user")))
        iotscan_fingerscan.delay(task_ids, result)
    return {"msg": "success", "desc": "端口扫描", "task_ids": task_ids, "length": len(result), "result": result}


@shared_task(name='iotscan-server-fingerscan', track_started=True, queue="fingerscan")
@log_task
def iotscan_fingerscan(task_ids=None, config=None):
    """
    执行指纹识别任务
    :param task_ids:主任务id
    :param config:配置文件
    :return:json
    """
    log.info("进行指纹识别任务")
    log.info(f"任务id {task_ids},配置信息 {config}")
    result = []
    url_list = []
    backup_url_list = []
    poc_list = config.get("poc_list")
    create_user = config.get("create_user")
    poc_type = config.get("poc_type")
    log.info(f"获取到poc长度 {len(poc_list)}")
    # try:
    if config is not None and config.get("status") != 0 and config.get('error') is None:
        task_id = current_task.request.id
        log.info(f"扫描任务：{task_id}")
        log.info(f"配置信息：{task_ids, config}")
        time.sleep(1)
        log.info(f"指纹扫描配置：{config}")
        result = FingerScan.run(config)
        log.info(f"指纹识别结果 {result}")
        CreateFingerScanResult(task_ids, dict(host=config.get("host"), result=json.loads(result)), task_id)
        for r in json.loads(result):
            if r.get("finger").get("scheme") and r.get("finger").get("scheme").startswith("http"):
                backup_url_list.append(r.get("finger").get("url"))
        host = config.get("host")
        port_list = config.get("result")
        if port_list:
            for port in port_list:
                url_list.append(host + ":" + port.get("port").split("/")[0])
        # 备份文件扫描
        backup_config = dict(
            url_list=backup_url_list,
            proxy=None,
        )
        btasks_id = uuid.uuid4().hex
        log.info(f"正在生成备份文件扫描任务，任务id：{btasks_id}")
        CreateTasksToDataBase(task_ids, backup_config, btasks_id, create_user)
        iotscan_backupscan.apply_async(kwargs={'task_ids': task_ids,
                                               'config': backup_config}, task_id=btasks_id)
        if poc_type != -1:
            for poc in poc_list:
                poc_config = {
                    "url": url_list,
                    "mode": "verify",
                    "poc": [f"{settings.POC_PLUGIN_PATH}/{poc.get('file_name')}"],
                    # "proxy": 'http://127.0.0.1:8080'
                }
                tasks_id = uuid.uuid4().hex
                log.info(f"正在生成poc扫描任务，任务id：{tasks_id}")
                CreateTasksToDataBase(task_ids, config, tasks_id, create_user, poc)
                iotscan_pocscan.apply_async(kwargs={'task_ids': task_ids,
                                                    'config': poc_config,
                                                    'proxy': 0,
                                                    'poc': poc,
                                                    'timeout': 10
                                                    }, task_id=tasks_id)
        # 更新主任务管理器的状态
        UpdateTargetManagerFinishDataBase(task_ids)
    else:
        # 更新主任务管理器的状态
        log.info("更新完成任务次数")
        if poc_type != -1:
            UpdateTargetManagerFinishDataBase(task_ids, finsh_count=int(len(poc_list)) + 1)
        else:
            UpdateTargetManagerFinishDataBase(task_ids)
    # except Exception as e:
    #     log.warning(f"指纹识别出错，错误信息：{e}")
    #     UpdateTargetManagerFinishDataBase(task_ids, finsh_count=int(len(poc_list)) + 1)
    return {"msg": "指纹扫描完成", "result": json.dumps(result)}


@shared_task(name='iotscan-server-pocscan', track_started=True, queue="pocscan")
@log_task
def iotscan_pocscan(task_ids, config, proxy, poc, timeout):
    """
    执行poc扫描任务
    :param task_ids:主任务id
    :param config:pocsuite3执行配置文件
    :param proxy:是否使用代理
    :param poc:poc信息
    :param timeout:超时等待时间
    :return:json
    """
    task_id = current_task.request.id
    log.info(f"扫描任务：{task_id}")
    log.info(f"配置信息：{task_ids, config, proxy, timeout}")
    is_used_proxy, proxy_info = is_use_proxy()
    log.info(is_used_proxy, proxy_info)
    time.sleep(1)  # 每个任务都要等待1秒之后在执行
    # data = {
    #     "start_time": "",  # 开始时间
    #     "status": "",  # poc执行状态
    #     "error_msg": "",  # poc报错信息
    #     "result": "",  # poc直接结果
    #     "end_time": "",  # 结束时间
    #     "remark": "",  # poc执行函数报错信息
    # }
    data = {}
    result_list = list()
    # result_list = [{
    #     "host": "",
    #     "status": "",
    #     "result": "",
    # }]
    # 实时更新celery数据库中的任务状态
    UpdateTasksToDataBase(task_id, dict(status=1, result=None, remark=None, end_time=None))
    pocscan.run_poc(config, data, result_list)
    # 实时更新celery数据库中的任务状态
    UpdateTasksToDataBase(task_id,
                          dict(status=2, result=json.dumps(data), remark=None, end_time=timezone.now()))
    # 创建poc执行结果明细表数据
    CreatePortResultToDataBase(task_ids=task_ids, data=result_list, poc_id=poc.get("id"),
                               task_id=task_id)
    # 更新主任务管理器的状态
    UpdateTargetManagerFinishDataBase(task_ids)
    return {"msg": "success", "desc": "poc扫描", "data": 0, "result": len(result_list)}


@shared_task(name='iotscan-server-backupscan', track_started=True, queue="datascan")
@log_task
def iotscan_backupscan(task_ids=None, config=None):
    """
    备份文件扫描
    :param task_ids:主任务id
    :param config:扫描配置
    :return:
    """
    log.info("进行备份文件扫描任务")
    log.info(f"任务id {task_ids},配置信息 {config}")
    url_list = config.get("url_list")
    proxy = config.get("proxy")
    result = BackupAgent(url_list=url_list, proxy=proxy).run()
    # 更新主任务管理器的状态
    # UpdateTargetManagerFinishDataBase(task_ids)
    return {"msg": "备份文件扫描完成", "result": json.dumps(result)}


@shared_task(name='iotscan-server-domainscan', track_started=True, queue="domainscan")
@log_task
def iotscan_domainscan(task_ids=None, config=None):
    """
    子域名扫描
    :param task_ids:主任务id
    :param config:扫描配置
    :return:
    """
    log.info("进行子域名扫描任务")
    log.info(f"任务id {task_ids},配置信息 {config}")
    is_all = False
    domain = config.get("domain")
    domain_type = config.get("domain_type")
    if domain_type == "ALL":
        is_all = True
    result = domain_scan(domain=domain, is_all=is_all)
    if len(result) > 0:
        # 任务是port+finger，端口扫描结束就是指纹扫描
        if config.get("poc_type") != -1:
            count = len(config.get("poc_list")) * len(result) + (len(result) - 1) * 2 - 1
        else:
            count = (len(result) - 1) * 2 - 1
        UpdateTasksCount(task_ids=task_ids, count=count)
        for re in result:
            tasks_id = uuid.uuid4().hex
            config = dict(host=re, port_type=config.get("port_type"), poc_type=config.get("poc_type"),
                          poc_list=config.get("poc_list"), proxy=config.get("proxy"),
                          create_user=config.get("create_user"))
            # 数据库存储
            CreateTasksToDataBase(task_ids, json.dumps(config, ensure_ascii=False), tasks_id,
                                  config.get("create_user"))
            # 创建任务
            iotscan_portscan.apply_async(kwargs={'task_ids': task_ids,
                                                 'config': config, }, task_id=tasks_id)
        # 更新主任务管理器的状态
        UpdateTargetManagerFinishDataBase(task_ids)
    else:
        if config.get("poc_type") != -1:
            count = len(config.get("poc_list")) + 3
        else:
            count = 3
        # 更新主任务管理器的状态
        UpdateTargetManagerFinishDataBase(task_ids, finsh_count=count)
    return {"msg": "子域名扫描完成", "result": json.dumps(result)}


@shared_task(name='iotscan-server-remove-task', track_started=True)
@log_task
def revoke_celery_tasks(task_ids):
    for task_id in task_ids:
        celery_app.control.revoke(task_id=task_id, signal='SIGTERM', terminate=True)
    return {"msg": "任务撤销完成", "result": f"共计撤销任务{len(task_ids)}个"}
