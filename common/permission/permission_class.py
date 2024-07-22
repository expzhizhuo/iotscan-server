"""
@Project ：iotscan 
@File    ：permission_class.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/10/12 11:30 
"""


class PermissionVerify:
    """
    自定义的权限验证方法
    """

    @staticmethod
    def IsSuperAdmin(request):
        """
        验证是否是管理员权限
        :param request:请求数据
        :return:True or False
        """
        if request.user.is_superuser == 1 or request.user.permissions == 1:
            return True
        return False


Permission = PermissionVerify()
