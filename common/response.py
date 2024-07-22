"""
@Project ：iotscan 
@File    ：response.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/3/21 11:23 
"""
from rest_framework.response import Response


class response:
    def success(self: object = None, msg='success'):
        return Response({
            'code': 200,
            'msg': str(msg),
            'data': self
        })

    def error(self: object = None, msg='error'):
        return Response({
            'code': 400,
            'msg': str(msg),
            'data': str(self)
        })

    def server_error(self: object = None, msg='server error'):
        return Response({
            'code': 500,
            'msg': str(msg),
            'data': str(self)
        })
