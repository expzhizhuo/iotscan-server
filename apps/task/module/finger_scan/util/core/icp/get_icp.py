"""
@Project ：指纹识别 
@File    ：get_icp.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/1/14 18:38 
"""
from bs4 import BeautifulSoup


class GetIcpInfo(object):
    """
    获取站点的icp备案信息
    """

    def __init__(self, body: str):
        """
        初始化配置信息
        """
        self.body = body
        self.forbidden_strings = ['.js', '.html', '.txt', '.css', '/', 'script', '<', '>']

    def _get_icp_info(self):
        """
        获取ICP备案信息
        :return:ICP备案信息
        """
        search_tags = ["script", "css", "js", "div", "<", ">", "div"]
        if any(tag in self.body for tag in search_tags):
            soup = BeautifulSoup(self.body, 'html.parser')
            icp_info = soup.find(string=lambda text: text and "ICP" in text)
            results = icp_info.strip() if icp_info else None
            if results:
                if len(results) > 50 or any(fs in results for fs in self.forbidden_strings):
                    return None
                split_result = results.split("：", 1)
                if len(split_result) == 2:
                    return split_result[1]
        else:
            results = None
        return results

    def run(self):
        """
        主入口函数
        :return:icp备案信息
        """
        return self._get_icp_info()
