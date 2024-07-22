"""
@Project ：指纹识别 
@File    ：test.py.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/4/3 15:27 
"""


class TcpFinger(object):
    plugin_name = "TCP 指纹请求测试"
    plugin_version = "1.0.0"
    plugin_author = "zhizhuo"
    plugin_is_active = False

    def __init__(self):
        """
        初始化内容
        """

    def run(self, url: str):
        print("执行成功")
        return dict(header="", length=0, body="")
