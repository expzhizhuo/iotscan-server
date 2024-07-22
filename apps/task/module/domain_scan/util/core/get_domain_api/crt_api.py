"""
@Project ：domainscan 
@File    ：crt_api.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/3/18 13:48 
"""
import json
import warnings
from bs4 import BeautifulSoup
import requests
from poc_tool import tools
import logging

log = logging.getLogger('tasks-server-api')

requests.packages.urllib3.disable_warnings()
warnings.filterwarnings('ignore')


class GetCrt(object):
    def __init__(self, domain: str):
        """
        初始化操作
        """
        self.crt_api_url = 'https://crt.sh'
        self.domain = domain
        self.headers = {
            'Accept': 'application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, '
                      'application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*',
            'User-agent': tools.get_random_ua(),
            'Scan': 'DomainScan',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Connection': 'close'
        }

    @property
    def _request_api(self):
        """
        请求API在线查询站点获取记录
        :return:
        """
        crt_result = []
        params = {"q": self.domain}
        try:
            resp = requests.get(url=self.crt_api_url, headers=self.headers, params=params, verify=False, timeout=60,
                                allow_redirects=False)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                matching_cells = soup.find_all('td', string=lambda text: text and self.domain in text)
                for cell in matching_cells:
                    if 'outer' not in cell.get('class', []):
                        if cell.text.startswith('*.'):
                            crt_result.append(cell.text.lstrip('*.'))
                        else:
                            crt_result.append(cell.text)
        except Exception as e:
            log.error(f"API接口crt.sh获取DNS记录出错，错误信息：{e}")
        return list(set(crt_result))

    def run(self):
        """
        主入口执行函数
        :return:
        """
        return self._request_api


if __name__ == '__main__':
    url = "wgpsec.org"
    result = GetCrt(domain=url).run()
    print(json.dumps(result))
    print(len(result))
