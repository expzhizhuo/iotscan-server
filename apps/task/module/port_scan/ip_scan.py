"""
@Project ：iotscan 
@File    ：ip_scan.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/10/9 11:38 
"""
import logging
import os
import re

from django.utils import timezone

from apps.task.module import ScanPortType

log = logging.getLogger('tasks-server-api')


class IPScan:
    def __init__(self):
        """
        初始化的全部数据
        """
        self.options = None
        # 默认端口扫描TOP100
        self.port = ScanPortType.TOP1000

    def port_scan(self, ips, scan_type="TOP1000"):
        """
        端口扫描函数，这里使用的是rustscan扫描
        :param ips:ip或者域名，list
        :param scan_type: 端口扫描的类型
        :return:端口信息
        """
        start_time = str(timezone.now())
        status = 0
        result = list()
        port_types = {"TOP1000": ScanPortType.TOP1000, "TOP100": ScanPortType.TOP100, "TOP10": ScanPortType.TOP10,
                      "ALL": ScanPortType.ALL}
        self.port = port_types.get(scan_type, ScanPortType.TOP1000)
        if scan_type == "ALL":
            command_input = f'rustscan --range {self.port} -a {ips} -b 1000 --ulimit 5000 -- -Pn -sS'
            # command_input = f'rustscan --range {self.port} -a {ips} --ulimit 1000 -- -Pn -sS'
        else:
            # command_input = f'rustscan --ports {self.generate_numbers(self.port)} -a {ips} --ulimit 5000 -- -Pn'
            command_input = f'rustscan --ports {self.generate_numbers(self.port)} -a {ips} -b 1000 --ulimit 5000 -- -Pn -sS'
        log.info(f"执行命令{command_input}")
        rust_input = os.popen(command_input).read()
        pattern = re.compile(r'(\d+/\w+\s+[open\w|\s]+\s+[\w\-]+\s+[\w\-]+\s)')
        matches = pattern.findall(rust_input)
        if matches and len(matches) > 0:
            status = 1
            result = [dict(zip(["port", "status", "service", "scan_type"], item.split())) for item in matches if
                      "closed" not in item]
        elif " Error Exit code = 1" in rust_input:
            status = 0
            result = "端口扫描出错，可能权限不足"
        return dict(host=ips, status=status, result=result, start_time=start_time, end_time=str(timezone.now()))

    @staticmethod
    def generate_numbers(number: any) -> str:
        """
        根据指定数字范围生成数字
        :param number: 数字范围
        :return:数字
        """
        result = []
        try:
            split_input = number.split(',')
            for element in split_input:
                if '-' in element:
                    start, end = map(int, element.split('-'))
                    result.extend(range(start, end + 1))
                else:
                    result.append(int(element))
            result.sort()
            return ','.join(map(str, list(set(result))))
        except Exception:
            raise ValueError('异常端口范围')


portscan = IPScan()
