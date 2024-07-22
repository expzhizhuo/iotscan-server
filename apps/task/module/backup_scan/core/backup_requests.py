"""
@Project ：backscan 
@File    ：backup_requests.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/12/26 13:15 
"""
import logging
import warnings
import aiohttp
from poc_tool.tools import tools
from urllib3.exceptions import InsecureRequestWarning

from config.config import Config

log = logging.getLogger('tasks-server-api')
# 解决requests的ssl证书warning提示
warnings.filterwarnings('ignore', category=InsecureRequestWarning)


class BackupRequests:
    def __init__(self, url: str, proxy: str = None, timeout: int = None):
        """
        初始化配置信息，其中代理使用格式为http://username:password@yourproxy:port
        :param url:url
        :param proxy:代理信息
        :param timeout:请求超时时间
        """
        self.black_type = Config.BACKUP_BLACK_TYPE
        self.url = url
        self.proxy = proxy
        self.timeout = timeout
        self.headers = {
            'Accept': 'application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, '
                      'application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*',
            'User-agent': tools.get_random_ua(),
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Connection': 'close'
        }

    @staticmethod
    def _get_file_size(content_size):
        """
        根据Content-Length计算文件的大小，并自适应KB, MB, GB单位
        :param content_size: Content-Length结果
        :return: 文件大小字符串，包含单位
        """
        if content_size < 1024:
            return f"{content_size} B"
        elif content_size < 1024 ** 2:
            file_size_kb = content_size / 1024
            return f"{file_size_kb:.2f} KB"
        elif content_size < 1024 ** 3:
            file_size_mb = content_size / (1024 ** 2)
            return f"{file_size_mb:.2f} MB"
        else:  # 1 GB or more
            file_size_gb = content_size / (1024 ** 3)
            return f"{file_size_gb:.2f} GB"

    async def _requests_scan(self):
        """
        发送备份文件扫描请求
        :return:
        """
        data = None
        try:
            if not self.timeout:
                timeout = aiohttp.ClientTimeout(total=10, connect=2, sock_connect=3, sock_read=3)
            else:
                timeout = aiohttp.ClientTimeout(total=self.timeout, connect=2, sock_connect=3, sock_read=3)
                """
                设置超时时间
                total: 整个请求的超时时间，包括连接建立、请求发送、响应接收等所有阶段。如果在该时间内请求没有完成，就会抛出超时异常。在这个例子中，超时时间为10秒。
                connect: 连接建立的超时时间。如果在该时间内连接没有建立成功，就会抛出超时异常。在这个例子中，连接建立的超时时间为2秒。
                sock_connect: socket连接建立的超时时间。如果在该时间内socket连接没有建立成功，就会抛出超时异常。在这个例子中，socket
                连接建立的超时时间为3秒。
                sock_read: socket接收数据的超时时间。如果在该时间内没有接收到数据，就会抛出超时异常。在这个例子中，socket
                接收数据的超时时间为3秒。
                """
                # 使用async with创建客户端（会自动关闭，所以我的main函数没有添加close，不然会报错）
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=100, ssl=False),
                                             timeout=timeout) as session:
                async with session.get(url=self.url, headers=self.headers, ssl=False, allow_redirects=False,
                                       timeout=self.timeout, proxy=self.proxy) as resp:
                    if resp.status == 200 and all(
                            content not in resp.headers.get('Content-Type', '') for content in self.black_type):
                        tmp_size = int(resp.headers.get('Content-Length', 0))
                        if tmp_size > 0:
                            data = dict(url=self.url, size=self._get_file_size(content_size=tmp_size))
        except Exception as e:
            log.debug(f"发送备份文件扫描请求出错，错误信息：{e}")
        return data

    def run(self):
        """
        总入口函数
        :return:
        """
        return self._requests_scan()
