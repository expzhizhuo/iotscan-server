"""
@Project ：iotscan 
@File    ：finger_scan.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/10/19 15:19 
"""
import json

from apps.task.module.finger_scan.util.agent import agent
from concurrent.futures import ThreadPoolExecutor


class FingerScanCLass:
    """
    资产指纹识别模块
    """

    def __init__(self):
        """
        初始化操作
        """

    @staticmethod
    def run(config: dict) -> object:
        """
        执行指纹识别任务，这里使用的线程池去操作，线程大小是10
        :param config:配置文件
        :return:json
        """
        result = list()
        if len(config) != 0 and config.get('status') != 0:
            host = config.get("host")
            port_list = config.get("result")
            if port_list is not None and len(port_list) > 0:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = []
                    for port in port_list:
                        ports = port.get("port").split("/")[0]
                        scan_type = port.get("port").split("/")[1]
                        port_service = port.get("service")
                        url = host + ":" + ports
                        futures.append(executor.submit(
                            agent(url=url, port=ports, port_service=port_service, scan_type=scan_type).run))
                    for future in futures:
                        res = future.result()
                        result.append(dict(finger=json.loads(res)))
        return json.dumps(
            [dict(finger=item) for entry in result if entry.get('finger') for item in entry.get('finger')],
            ensure_ascii=False)


FingerScan = FingerScanCLass()
