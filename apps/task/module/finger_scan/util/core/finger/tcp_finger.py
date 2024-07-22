"""
@Project ：指纹识别 
@File    ：tcp_finger.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/10/19 12:32 
"""
import logging
import re

log = logging.getLogger('tasks-server-api')


class GetTcpFinger(object):
    """
    tcp通信的结果指纹判断
    """

    def __init__(self, res: dict):
        """
        初始化配置信息
        :param res:tcp 返回数据包json格式
        """
        self.res = res

    @staticmethod
    def _get_finger_title(data):
        """
        获取title信息
        :param data:body数据
        :return:str
        """
        title = None
        try:
            if data is not None:
                title_list = re.findall(r'<title>(.*?)</title>', data, re.I | re.M | re.S)
                title = None if not title_list else str(title_list[0]).translate(
                    str.maketrans("", "", "\r\n\t")).replace(
                    "  ", "")
        except Exception as e:
            log.debug(f"获取tcp请求结果title出错 {e}")
            title = None
        return title

    def _get_tcp_finger(self):
        """
        获取tcp响应指纹数据
        :return:json
        """
        _cms = None
        header = self.res.get("header")
        body = self.res.get("body")
        _title = self._get_finger_title(body)
        if _title is None:
            self.res.update({"header": ""})
        if 'SSH' in header:
            _cms = 'SSH'
        elif 'FTP' in header or ('ftp' in header and '220--' in header):
            _cms = 'FTP'
        elif 'mysql' in header or 'MYSQL' in header or 'MySQL' in header:
            _cms = "MYSQL"
        elif 'DENIED Redis' in header or 'CONFIG REWRITE' in header or 'NOAUTH Authentication' in header or '-ERR wrong number of arguments for' in header:
            _cms = "Redis"
        elif 'DM Version' in header:
            _cms = "达梦数据库"
        log.debug(f"tcp 命中指纹 {_cms}")
        return dict(cms=_cms, title=_title)

    def run(self):
        """
        主入口函数
        :return:cms
        """
        return self._get_tcp_finger()
