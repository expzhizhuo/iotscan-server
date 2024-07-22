"""
@Project ：指纹识别 
@File    ：finger_v2.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/12/18 10:50 
"""
import json
import logging
import requests
from poc_tool.tools import tools

from apps.task.module.finger_scan.util.socket.req import requests_retry_session

log = logging.getLogger('tasks-server-api')


class GetFinger(object):

    def __init__(self, res: requests.Response, content: dict):
        """
        初始化信息
        :param content:title和icon_hash数据
        :param res:response数据
        """
        self.res = res
        self.content = content
        self.headers = {
            'Accept': 'application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, '
                      'application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*',
            'User-agent': tools.get_random_ua(),
            'X-Forwarded-For': tools.get_random_ip(),
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Connection': 'close'
        }
        finger_path = f'config/iotscan.json'
        with open(finger_path, 'r', encoding='utf-8') as file:
            self.finger_list = json.load(file)

    @staticmethod
    def _check_keyword(method, location, keywords, title, icon_hash, banner, body):
        """
        指纹匹配函数
        :param method:匹配类型
        :param location:匹配位置
        :param keywords:关键词
        :param title:title
        :param icon_hash:icon_hash
        :param banner:response headers
        :param body:response body
        :return:cms
        """
        match = False
        if method == 'keyword':
            if location == 'body':
                match = all(keyword in body for keyword in keywords)
            elif location == 'banner':
                match = all(keyword in banner for keyword in keywords)
            elif location == 'title':
                match = title is not None and all(keyword in title for keyword in keywords)
        elif method == 'icon_hash' and location == 'icon_hash':
            match = any(keyword in str(icon_hash) for keyword in keywords)
        elif method == 'other':
            if location == 'body':
                match = any(keyword in body for keyword in keywords)
            elif location == 'banner':
                match = any(keyword in banner for keyword in keywords)
            elif location == 'title':
                match = title is not None and any(keyword in title for keyword in keywords)
        return match

    def _run_get_finger(self, url: str, title: str, icon_hash: str, banner: str, body: str):
        """
        获取指纹
        :param title:站点标题
        :param url:url地址
        :param icon_hash:icon hash
        :param banner:response headers
        :param body:response body
        :return:cms
        """

        finger_list = self.finger_list.get('finger')
        for f in finger_list:
            cms = f.get('cms')
            method = f.get('method')
            path = f.get('path')
            req_method = f.get('req_method')
            location = f.get('location')
            keywords = f.get('keyword')

            if body or title:
                if self._check_keyword(method, location, keywords, title, icon_hash, banner, body):
                    return cms
            if path:
                resp = self._make_request(url, path, req_method)
                if resp:
                    banner = str(resp.headers)
                    body = resp.text
                    if self._check_keyword(method, location, keywords, title, icon_hash, banner, body):
                        return cms
        return None

    def _make_request(self, url, path, req_method):
        """
        发送path指纹请求函数
        :param url:url
        :param path:url path
        :param req_method:请求方式
        :return:
        """
        # log.warning(f"发送请求，验证路径{path}")
        req = requests_retry_session()
        try:
            # 请求制定path路径应该不跟随请求
            resp = getattr(req, req_method)(url=url + path, headers=self.headers, timeout=10, verify=False,
                                            allow_redirects=False)
            if resp.status_code < 400 or resp.status_code >= 500:
                log.debug(f"请求成功，状态码 {resp.status_code}")
                return resp
        except Exception as e:
            log.debug(f"验证路径{path}请求错误，错误信息 {e}")
        return None

    def run(self):
        """
        获取指纹信息主入口函数
        :return:
        """
        title = self.content.get("title")
        icon_hash = self.content.get("icon_hash")
        banner = self.res.headers
        body = self.res.text
        url = self.res.request.url
        cms = self._run_get_finger(url=url, title=title, icon_hash=icon_hash, banner=str(banner), body=body)
        log.warning(f"识别到cms {cms}")
        return cms
