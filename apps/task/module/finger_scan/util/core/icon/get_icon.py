"""
@Project ：指纹识别 
@File    ：get_icon.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/10/16 15:44 
"""
import base64
import logging
from urllib.parse import urlparse
import mmh3
from poc_tool.tools import tools

from apps.task.module.finger_scan.util.socket.req import requests_retry_session

log = logging.getLogger('tasks-server-api')


class GetIconHash(object):
    """
    获取icon hash的相关操作
    """

    def __init__(self, icon_url: str, retries: int = 3):
        """
        初始化相关操作
        :param icon_url:url地址
        :param retries:重试次数
        """
        self.icon_url = icon_url
        self.retries = retries
        self.headers = {
            'Accept': 'application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, '
                      'application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*',
            'User-agent': tools.get_random_ua(),
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Connection': 'close'
        }
        self.file_header = ['89504E470', '89504e470', '000001000', '474946383', 'FFD8FFE00', 'FFD8FFE10', '3c7376672',
                            '3c3f786d6']

    @staticmethod
    def _get_default_icon_url(icon_url):
        """
        获取默认icon的hash值
        :param icon_url:url地址
        :return:default icon url
        """
        parsed_url = urlparse(icon_url)
        base_url = f'{parsed_url.scheme}://{parsed_url.netloc}/'
        base_path = parsed_url.path
        # 默认favicon地址
        favicon_url = None
        if base_path:
            favicon_url = base_url + "favicon.ico"
        return favicon_url

    def _get_icon_hash(self, icon_url):
        """
        获取icon的hash值
        :param icon_url:url地址
        :return:hash
        """
        log.debug(f"icon url地址 {icon_url}")
        icon_hash = None
        if icon_url.startswith('data:image/vnd.microsoft.icon'):
            icon_base64_list = icon_url.split(';base64,')
            if len(icon_base64_list) > 1:
                try:
                    icon_base64 = icon_base64_list[1]
                    icon_hash = mmh3.hash(base64.encodebytes(base64.b64decode(icon_base64)))
                except Exception as e:
                    log.debug(f"icon base64解密出错，错误信息 {e}")
                    pass
        if icon_url.startswith('http'):
            req = requests_retry_session(retries=self.retries)
            try:
                resp = req.get(url=icon_url, headers=self.headers, verify=False,
                               allow_redirects=True, timeout=5)
                if resp.status_code == 200 and len(resp.content) != 0:
                    for fh in self.file_header:
                        if resp.content.hex().startswith(fh):
                            icon_hash = mmh3.hash(base64.encodebytes(resp.content))
            except Exception as e:
                log.debug(f'icon获取报错，错误信息 {e}')
        return icon_hash

    def run(self):
        """
        主入口函数
        :return:
        """
        icon_hash = self._get_icon_hash(icon_url=self.icon_url)
        if icon_hash is None:
            default_icon_url = self._get_default_icon_url(icon_url=self.icon_url)
            if default_icon_url:
                log.debug(f"重置为默认icon地址尝试请求 {default_icon_url}")
                icon_hash = self._get_icon_hash(icon_url=default_icon_url)
        return icon_hash
