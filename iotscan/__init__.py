from .celery import app as celery_app
# 解决ModuleNotFoundError: No module named 'pymysql'报错
import pymysql

pymysql.install_as_MySQLdb()

# 确保django启动的时候celery也自动启动
__all__ = ('celery_app',)
