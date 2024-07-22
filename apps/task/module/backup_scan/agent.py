"""
@Project ：iotscan 
@File    ：agent.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/12/26 16:06 
"""
import asyncio
import logging
from urllib.parse import urljoin
from apps.task.module.backup_scan.core.backup_requests import BackupRequests
from apps.task.module.backup_scan.core.get_backup_filename import GetBackupFilename
from poc_tool.tools import tools

# from poc_tool import log, LOGGER, LoggingLevel

log = logging.getLogger('tasks-server-api')


# LOGGER.setLevel(LoggingLevel.DEBUG)


class BackupAgent:
    def __init__(self, url_list: list, threads: int = 50, proxy: str = None, timeout: int = None):
        """
        初始化配置信息
        :param url_list:url
        :param threads:扫描速度
        :param proxy:代理
        :param timeout:超时时间
        """
        self.url_list = url_list
        self.max_threads = 50
        self.proxy = None
        self.timeout = 3
        if threads != 50:
            self.max_threads = threads
        if proxy:
            self.proxy = proxy
        if timeout:
            self.timeout = timeout

    async def producer(self, queue: asyncio.Queue, url_list: list):
        for scan_url in url_list:
            log.debug(f"正在扫描：{scan_url}")
            await queue.put(scan_url)
        for _ in range(self.max_threads):
            await queue.put(None)  # 用于标记队列结束的值

    async def consumer(self, queue: asyncio.Queue, semaphore: asyncio.Semaphore, async_result: dict):
        while True:
            scan_url = await queue.get()
            print(scan_url)
            if scan_url is None:
                queue.task_done()
                break
            async with semaphore:  # 使用信号量限制并发
                try:
                    res = await asyncio.wait_for(BackupRequests(url=scan_url, proxy=self.proxy).run(),
                                                 timeout=self.timeout)
                    async_result[scan_url] = res
                except asyncio.TimeoutError:
                    log.debug(f"任务超时: {scan_url}")
                finally:
                    queue.task_done()

    @staticmethod
    def _get_backup_filename_list(url_list: list):
        """
        获取备份文件字典
        :param url_list:url
        :return:list
        """
        result_dict = []
        for urls in url_list:
            urls = tools.get_url_format(urls)
            BackupDict = GetBackupFilename(urls).run()
            for d in BackupDict:
                scan_url = urljoin(urls, d)
                result_dict.append(scan_url)
        return result_dict

    async def _scan(self, scan_dict: list):
        """
        请求运行函数
        :param scan_dict:扫描url地址
        :return:
        """
        async_result = {}
        # 使用 Semaphore 控制并发
        semaphore = asyncio.Semaphore(self.max_threads)
        queue = asyncio.Queue(maxsize=self.max_threads)
        # 启动生产者和消费者任务
        producer_task = asyncio.create_task(self.producer(queue, scan_dict))
        consumer_tasks = [asyncio.create_task(self.consumer(queue, semaphore, async_result)) for _ in
                          range(self.max_threads)]
        # 等待生产者任务完成
        await producer_task
        # 等待队列中的所有项目被处理
        await queue.join()
        # 等待所有消费者任务取消完成
        await asyncio.gather(*consumer_tasks, return_exceptions=True)
        return [async_result[r] for r in async_result]

    def _agent(self):
        """
        主运行函数
        :return:json
        """
        log.debug(f"开始生成扫描字典")
        scan_dict = self._get_backup_filename_list(url_list=self.url_list)
        log.debug(f"开始请求，需要请求次数: {len(scan_dict)}")
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        black_result = loop.run_until_complete(self._scan(scan_dict=scan_dict))
        return list(filter(None, black_result))

    def run(self):
        """
        入口函数
        :return:json
        """
        return self._agent()


if __name__ == '__main__':
    url = ['101.42.156.174:21', '101.42.156.174:22', '101.42.156.174:53', '101.42.156.174:111', '101.42.156.174:888',
           '101.42.156.174:3000', '101.42.156.174:3003', '101.42.156.174:3306']
    result = BackupAgent(url_list=url).run()
    print(result)
