"""
@Project ：domainscan 
@File    ：agent.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/1/23 12:49 
"""
import re
import ipaddress
import aiodns
from config import Config
import asyncio
from ..core.explode import ExplodeDomain
from poc_tool.tools import tools
from ..core.get_domain_api import *
import logging

log = logging.getLogger('tasks-server-api')


class DomainScanAgent(object):
    def __init__(self, domain: str, proxy: dict = None, timeout: int = 5, retries: int = 3, domain_dict: dict = None,
                 is_all: bool = False):
        """
        初始化配置文件
        :param domain:domain
        :param proxy:代理
        :param timeout:超时时间
        :param retries:重试次数
        """
        if proxy is None:
            proxy = {}
        self.domain = domain
        self.proxy = proxy
        self.timeout = timeout
        self.retries = retries
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop, rotate=True)
        self.resolver.nameservers = Config.DNS_NAMESERVERS
        self.d_type = "A"
        self.headers = {
            'Accept': 'application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, '
                      'application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*',
            'User-agent': tools.get_random_ua(),
            'Scan': 'DomainScan',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Connection': 'close'
        }
        if domain_dict is not None:
            self.domain_dict = domain_dict
        else:
            self.domain_dict = Config.SmallDomainList
        if is_all is True:
            self.domain_dict = Config.BigDomainList

    @staticmethod
    def is_ip(domain):
        """
        验证是否是ip
        :param domain:domain
        :return:
        """
        try:
            ipaddress.ip_address(domain.strip())
            return True
        except Exception:
            return False

    @staticmethod
    def is_private(domain):
        """
        验证是否是内网ip
        :param domain:domain
        :return:
        """
        try:
            return ipaddress.ip_address(domain.strip()).is_private
        except Exception:
            return False

    def _verify_domain(self):
        """
        验证是否是域名资产
        :return:
        """
        domain_regex = re.compile(r'^(?:http[s]?://)?(?:\*\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+(?:/[^\s]*)?$')
        match = domain_regex.match(self.domain)
        if match:
            domain = match.group()
            domain = re.sub(r'^http[s]?://', '', domain)
            domain = domain.split('/')[0]
            if self.is_ip(domain):
                return None
            # 分割域名
            parts = domain.split('.')
            # 提取主域名
            if len(parts) > 2 and parts[-2] in ['com', 'co', 'net', 'org', 'gov', 'edu']:
                # 对于 '.com.cn' 这样的情况，我们需要提取最后三部分
                domain = '.'.join(parts[-3:])
            else:
                # 否则，我们提取最后两部分
                domain = '.'.join(parts[-2:])
            return domain
        else:
            return None

    def _domain_query(self, domain, d_type: str = None):
        """
        查询DNS结果
        :param domain:domain
        :param d_type:类型
        :return:
        """
        try:
            if d_type is None:
                d_type = self.d_type
            f = self.resolver.query(domain, d_type)
            res = self.loop.run_until_complete(f)
            result = [i.host for i in res]
        except Exception as e:
            log.debug(f"查询是否是黑名单错误，错误信息:{e}")
            result = []
        return result

    def _check_domain_analysis(self, domain: str, d_type: str = "CNAME"):
        """
        检查域名是否是泛解析，使用CNAME进行泛解析判断
        :param domain:domain
        :param d_type:类型
        :return:
        """
        try:
            domains = tools.get_random_str(6) + '.' + domain
            log.debug(f"随机生成域名 {domains}")
            f = self.resolver.query(domains, d_type)
            res = self.loop.run_until_complete(f)
            if res:
                return True
        except Exception as e:
            log.debug(f"CNAME DNS泛解析判断出错，错误信息 {e}")
            log.debug(f"{domain} 非泛解析域名")
        return False

    @staticmethod
    def _check_domain(domain_list: list):
        """
        检查是否是合法域名
        :param domain_list:域名列表
        :return:list
        """
        new_list = []
        regex = re.compile(
            r'^(https?://)?((\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*)(:\d+)?(/.*)?$'
        )
        for domain in domain_list:
            r = regex.match(domain)
            if r:
                new_list.append(domain)
        return new_list

    def run(self):
        """
        程序主入口函数
        :return:
        """
        result = []
        domain = self._verify_domain()
        log.info(f"开始处理主域名{domain}")
        if not domain:
            return result
        # 获取dns响应ip结果，判断是否是黑名单资产
        dns_list = self._domain_query(domain=domain)
        log.debug(f"DNS获取A记录ip为{dns_list}")
        if len(dns_list) > 1:
            log.info("此资产疑似为CND资产")
        # 判断是不是泛解析资产
        is_analysis = self._check_domain_analysis(domain=domain)
        if is_analysis:
            log.debug(f"{domain} 是泛解析域名")
        log.info(f"执行API子域名信息获取")
        # 先从API去获取DNS解析记录
        result = GetCrt(domain=domain).run()
        log.debug(f"API结果获取结束，长度{len(result)}")
        if not is_analysis:
            # 默认执行小字典爆破
            log.info("执行子域名爆破")
            loop = asyncio.get_event_loop()
            result_dns = loop.run_until_complete(ExplodeDomain(domain=domain, domain_dict=self.domain_dict).run())
            log.debug(f"字典爆破结果长度{len(result_dns)}")
            for d in result_dns:
                result.append(d)
        log.info(f"子域名合法性检测")
        domain_result = self._check_domain(domain_list=list(set(result)))
        log.info(f"子域名收集结束，子域名总个数为{len(domain_result)}")
        return domain_result
