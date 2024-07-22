"""
@Project ：指纹识别 
@File    ：redis_finger_tcp.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/4/3 16:59 
"""
import json
from apps.task.module.finger_scan.util.socket import SocketSend
from apps.task.module.finger_scan.util.core import GetSSLInfo


class TcpFinger(object):
    plugin_name = "Redis TCP指纹插件"
    plugin_version = "1.0.0"
    plugin_author = "zhizhuo"
    plugin_is_active = True

    def __init__(self):
        """
        初始化操作
        """
        self.send_data = "*1\r\n$4\r\ninfo\r\n"

    def _send_data(self, url):
        """
        调用tcp发送tcp数据
        :param url:url地址
        :return:json
        """
        host_list = GetSSLInfo(url=url).get_domain_info()
        host = host_list.get("host")
        port = host_list.get("port")
        res = dict(header="", length=0, body="")
        try:
            res = SocketSend.send_tcp(host=host, port=port, is_ssl=False, send_data=self.send_data)
        except Exception as e:
            pass
        return res

    def run(self, url: str):
        """
        发送redis链接tcp操作
        :param url:url地址
        :return:json
        """
        return self._send_data(url)
