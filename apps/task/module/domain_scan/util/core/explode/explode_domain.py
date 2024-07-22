"""
@Project ：domainscan 
@File    ：explode_domain.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/1/23 13:01 
"""
import asyncio
import concurrent
from concurrent.futures import ThreadPoolExecutor
import sys
import aiodns
from config import Config
import logging

log = logging.getLogger('tasks-server-api')


class ExplodeDomain(object):
    """
    子域名字典爆破
    """

    def __init__(self, domain: str, dict_type: int = 1, timeout: int = 5, retries: int = 3, domain_dict: dict = None):
        """

        :param domain:domain
        :param dict_type:字典类型
        :param timeout:超时时间
        :param retries:重试次数
        """
        self.domain = domain
        self.dict_type = dict_type
        self.timeout = timeout
        self.retries = retries
        self.d_type = "A"
        if domain_dict is not None:
            self.domain_dict = domain_dict
        else:
            self.domain_dict = Config.SmallDomainList

    def query_domain(self, domain):
        """
        验证子域名是否存在
        :param domain:
        :return:
        """
        result = None
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        resolver = aiodns.DNSResolver(loop=loop, rotate=True)
        resolver.nameservers = Config.DNS_NAMESERVERS
        try:
            f = resolver.query(domain, self.d_type)
            res = loop.run_until_complete(f)
            if res:
                result = domain
        except Exception:
            pass
        finally:
            if loop and not loop.is_closed():
                loop.close()
        return result

    def _get_domain(self):
        """
        爆破子域名
        :return:
        """
        a = 0
        result = []
        log.info(f"开始爆破主域名{self.domain}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for domain in self.domain_dict:
                domains = f"{domain}.{self.domain}"
                future = executor.submit(self.query_domain, domains)
                futures.append(future)
            try:
                for future in concurrent.futures.as_completed(futures, timeout=600):
                    a = a + 1
                    print(f"{a} / {len(self.domain_dict)} progress:{a / len(self.domain_dict) * 100:.2f} %", end='\n')
                    sys.stdout.flush()  # 手动刷新缓冲区，确保输出立即显示
                    try:
                        res = future.result()
                        if res:
                            result.append(res)
                    except concurrent.futures.TimeoutError:
                        print(f"Query timed out for domain: {domains}")
            except Exception as e:
                log.error(f"DNS域名爆破出错，错误信息{e}")
                pass

        return result

    async def run(self):
        """
        程序主入口函数
        :return:
        """
        return self._get_domain()
