"""
@Project ：iotscan 
@File    ：throttling_requests.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/3/14 11:24 
"""

from rest_framework.throttling import AnonRateThrottle, UserRateThrottle


class MinuteUserRateThrottle(UserRateThrottle):
    scope = 'limit_per_minute'


class HourUserRateThrottle(UserRateThrottle):
    scope = 'limit_per_hour'
