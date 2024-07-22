"""
@Project ：iotscan 
@File    ：agent.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/4/8 12:23 
"""
from apps.task.module.domain_scan.util.agent import agent


def domain_scan(domain: str, is_all: bool = False) -> list:
    """
    主入口函数
    :param domain:主域名
    :param is_all:是否扫描全字典
    :return:
    """
    result = agent(domain=domain, is_all=is_all).run()
    return result
