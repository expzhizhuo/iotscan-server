"""
@Project ：backscan 
@File    ：get_backup_filename.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/12/26 12:26 
"""
from config.config import Config
import logging

log = logging.getLogger('tasks-server-api')


class GetBackupFilename(object):
    def __init__(self, url):
        """
        初始化配置信息
        """
        self.backup_filename_suffix = Config.BACKUP_FILENAME_SUFFIX
        self.backup_filename_default_dict = Config.DEFAULT_INFO_DICT
        self.url = url

    def _get_domain_info_dict(self):
        """
        格式化url信息
        :return:
        """
        url_domain = self.url.split('://')[-1].split('/')[0].split(':')[0]
        url_port = self.url.split(':')[-1] if ':' in self.url else "80"
        www_host = ""
        www = url_domain.split('.')
        if ':' in url_domain:
            url_domain = url_domain.split(':')[0]
            www = url_domain.split('.')
        for i in range(1, len(www)):
            www_host += www[i]
        Domain_Dict = [url_domain, url_domain.replace('.', ''), url_domain.replace('.', '_'), www_host,
                       url_domain.split('.', 1)[-1], (url_domain.split('.', 1)[1]).replace('.', '_'), www[0], www[1],
                       url_port]
        return list(set(Domain_Dict))

    def _get_random_filename_dict(self):
        """
        生成备份文件名字
        :return:
        """
        Backup_Dict = []
        for su in self.backup_filename_suffix:
            for tm in self.backup_filename_default_dict:
                Backup_Dict.extend([tm + su])
        Domain_Dic = self._get_domain_info_dict()
        log.debug(f"推算生成url字典长度{len(Domain_Dic)}，url字典数据{Domain_Dic}")
        for s in self.backup_filename_suffix:
            for d in Domain_Dic:
                Backup_Dict.extend([d + s])
        Backup_Dict = list(set(Backup_Dict))
        log.debug(f"生成总字典长度{len(Backup_Dict)}，字典数据{Backup_Dict}")
        return Backup_Dict

    def run(self):
        """
        主入口函数
        :return:
        """
        return self._get_random_filename_dict()


if __name__ == '__main__':
    url1 = "192.168.1.1"
    result = GetBackupFilename(url1).run()
    print(result)
    print(len(result))
