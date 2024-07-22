"""
@Project ：iotscan 
@File    ：poc_scan.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/9/24 13:28 
"""
import json
import logging
import random
# from django.utils import timezone
from pocsuite3.api import init_pocsuite, start_pocsuite, get_results
from datetime import datetime as timezone

log = logging.getLogger('tasks-server-api')


class PocScan:
    @staticmethod
    def run_poc(config, item, have_leaking_data):
        """
        poc扫描模块
        :param config: pocsuite3配置文件
        :param item: POC执行结果
        :param have_leaking_data: POC执行报错信息
        :return:
        """
        result = list()
        item.update({'start_time': str(timezone.now())})
        log.info(f"运行POC文件{config}")
        try:
            init_pocsuite(config)
            start_pocsuite()
            res = get_results()
            status = 2
            for r in res:
                log.debug(f'POC攻击状态\n{r.get("status")}')
                log.debug(f'POC运行报错\n{list(r.get("error_msg"))[1]}')
                log.debug(f'POC运行结果\n{json.dumps(r.get("result"))}')
                poc_host_status = 1  # poc的是否执行成功，1 成功 0失败 默认为1 成功
                current_data = dict(r)
                # poc执行失败: 没有风险信息
                if current_data.get('status') == 'failed':
                    status = -1
                    poc_host_status = 0
                    error_msg = current_data.get('error_msg')
                    if isinstance(error_msg, tuple):
                        current_data.update({'error_msg': str(error_msg[1])})
                have_leaking_data.append({'host': current_data.get('url'),
                                          'result': current_data.get('result'),
                                          'status': poc_host_status})
            result.append(have_leaking_data)
            item.update({'status': status,
                         'result': result})
        except Exception as e:
            item.update({'status': -1, 'remark': str(e)})
            result.append(e)
            log.info(f"运行POC出错，错误信息：{e}")
        finally:
            item.update({'end_time': str(timezone.now())})
            log.info('run_poc...result..:{}'.format(result))
        return item, have_leaking_data


pocscan = PocScan()

if __name__ == '__main__':
    config = {
        "url": ['www.baidu.com', 'iot-wiki.cn'],
        "mode": "verify",
        "poc": [f"/Users/zhizhuo/Desktop/开发目录/pocsuite3测试文件/CNVD-2023-08743.yaml"],
        "delay": random.randint(0, 10),
    }
    result = {}
    have_leaking_data = []
    pocscan.run_poc(config=config, item=result, have_leaking_data=have_leaking_data)
    print(result)
    print(have_leaking_data)
