"""
@Project ：iotscan 
@File    ：__init__.py.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/9/24 13:26 
"""

from config.config import Config


class ScanPortType:
    TOP10 = Config.TOP_10
    TOP100 = Config.TOP_100
    TOP1000 = Config.TOP_1000
    ALL = "0-65535"
