"""
@Project ：指纹识别 
@File    ：req.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/1/29 09:31 
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry


def requests_retry_session(retries: int = 3, backoff_factor=0.3, status_forcelist=(500, 502, 504),
                           session=None, ):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session
