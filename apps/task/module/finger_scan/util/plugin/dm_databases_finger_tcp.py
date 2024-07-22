"""
@Project ：指纹识别 
@File    ：dm_databases_finger_tcp.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/4/3 16:30 
"""
from apps.task.module.finger_scan.util.socket import SocketSend
from apps.task.module.finger_scan.util.core import GetSSLInfo


class TcpFinger(object):
    plugin_name = "达梦数据库TCP指纹插件"
    plugin_version = "1.0.0"
    plugin_author = "zhizhuo"
    plugin_is_active = True

    def __init__(self):
        """
        初始化操作
        """
        self.verify_data = "\x00\x00\x00\x00\x00"
        self.send_data = "00000000c800520000000000000000000000009a000000000000000001020000000001090000000000000000000000000000000000000000000000000000000009000000382e312e322e3139320040000000182fa6db4e39692e3ad5559df6e0a026a77ce475f3097c784125089cd0f5c4de77d239d1946578dcf97840e514363ffdc71db4f7e1e22064e646006a7f7e19c1"

    def _send_data(self, url):
        """
        调用tcp发送tcp数据
        :param url:url地址
        :return:json
        """
        host_list = GetSSLInfo(url=url).get_domain_info()
        host = host_list.get("host")
        port = host_list.get("port")
        is_ssl = host_list.get("is_ssl")
        res = dict(header="", length=0, body="")
        if not is_ssl:
            res = SocketSend.send_tcp(host=host, port=port, is_ssl=False,
                                      send_data=bytes.fromhex(self.send_data))
            res_headers = res.get("header")
            if self.verify_data in res_headers:
                version_index = res_headers.find('@')
                if version_index != -1 and version_index > 8:
                    version = res_headers[version_index - 8:version_index]
                    if version:
                        res.update(dict(header=f"DM Version：{version}\n{res_headers}"))
        return res

    def run(self, url: str):
        """
        发送redis链接tcp操作
        :param url:url地址
        :return:json
        """
        return self._send_data(url)
