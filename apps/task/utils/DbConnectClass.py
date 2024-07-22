"""
@Project ：iotscan 
@File    ：DbConnectClass.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/10/14 19:52 
"""
import logging
import django.db

log = logging.getLogger('tasks-server-api')


def handle_db_connections(func):
    def func_wrapper(*args, **kwargs):
        django.db.close_old_connections()
        log.info(f'{func.__name__} run before do close old connection')
        result = func(*args, **kwargs)
        log.info(f'{func.__name__} run after do close old connection')
        django.db.close_old_connections()

        return result

    return func_wrapper
