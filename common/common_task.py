"""
@Project ：iotscan 
@File    ：common_task.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/7/17 10:16 
"""
import json
from datetime import datetime

from django.conf import settings
from django.core.cache import cache

import logging

from django.utils import timezone
from pocsuite3.api import init_pocsuite, start_pocsuite, get_results

log = logging.getLogger('tasks-server-api')


def test(data, a):
    """
    测试方法
    :param data:
    :param a:
    :return:
    """
    g = {"q": "w"}
    a.append(g)
    data.update({'start_time': str(timezone.now())})


def is_use_proxy():
    """
    是否用代理
    """
    data = cache.get("proxy_setting")
    print(data)
    log.info(f"进行任务通用模块，代理{data}可用性检测")
    if data is not None:
        return True, json.loads(data)
    return False, None
