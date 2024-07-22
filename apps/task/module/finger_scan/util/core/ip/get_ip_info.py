"""
@Project ：指纹识别 
@File    ：get_ip_info.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/1/18 16:15 
"""
from urllib.parse import urlparse
from .xdbSearcher import XdbSearcher
import socket


class GetIPInfo(object):
    def __init__(self, ip: str):
        """
        初始化配置信息
        :param ip:ip地址
        """
        self.ip = socket.gethostbyname(urlparse(ip).netloc.split(":")[0])
        self.dbPath = f'config/ip2region.xdb'
        self.searcher = XdbSearcher(contentBuff=XdbSearcher.loadContentFromFile(dbfile=self.dbPath))

    def _search(self):
        """
        查询ip地址信息
        :return:json
        """
        region_str = self.searcher.search(self.ip)
        self.searcher.close()
        region_list = region_str.split("|")
        return dict(ip=self.ip, country=region_list[0], region=region_list[1], province=region_list[2],
                    city=region_list[3], isp=region_list[4])

    def run(self):
        """
        程序主入口函数
        :return:
        """
        return self._search()


if __name__ == '__main__':
    # ip = "153.37.254.159"
    # ip = "106.54.99.93"
    # ip = "101.42.156.174"
    ip = "https://www.baidu.com"
    print(urlparse(ip))
    ip_addr = socket.gethostbyname(urlparse(ip).netloc.split(":")[0])
    print(ip_addr)
    # ip = ip_addr
    # result = GetIPInfo(ip=ip).run()
    # print(result)
