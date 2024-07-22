"""
@Project ：iotscan 
@File    ：AuthProcess.py.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/3/26 11:22 
"""


# 登录身份验证 自定义 错误返回
class ExceptionChange:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_template_response(self, request, response):
        """
        重写全局认证返回报错
        :param request:
        :param response:
        :return:
        """
        if hasattr(response, 'data'):
            data = response.data
            if isinstance(data, dict) is True:
                if "detail" in data.keys():
                    # 用户名或密码错误
                    if data.get("detail") == "找不到指定凭据对应的有效用户":
                        del response.data["detail"]
                        response.data["code"] = 400
                        response.data["msg"] = "用户名或者密码错误!"

                    # 验证信息过期 token 过期
                    elif data.get("detail") == "此令牌对任何类型的令牌无效":
                        del response.data["detail"]
                        del response.data["messages"]
                        response.data["code"] = 401
                        response.data["msg"] = "登录已过期，请重新登录"

                    # 验证信息不包含用户信息
                    elif data.get("detail") == "令牌未包含用户标识符":
                        del response.data["detail"]
                        # del response.data["messages"]
                        response.data["code"] = 403
                        response.data["msg"] = "用户认证信息异常"

                    # 未使用验证信息 未带验证信息请求
                    elif data.get("detail") == "身份认证信息未提供。":  # 身份认证信息未提供。
                        del response.data["detail"]
                        response.data["code"] = 403
                        response.data["msg"] = "未提供用户认证信息"

                    # refresh 无效或者过期
                    elif data.get("detail") == "令牌无效或已过期":  # 身份认证信息未提供。
                        del response.data["detail"]
                        response.data["code"] = 401
                        response.data["msg"] = "令牌无效或已过期"

                    # 不受支持的请求方式
                    elif "不被允许" in data.get("detail"):
                        response.data["code"] = 405
                        response.data["msg"] = response.data["detail"]
                        del response.data["detail"]

                    # 其他类型报错返回
                    else:
                        response.data["code"] = 400
                        response.data["msg"] = response.data["detail"]
                        del response.data["detail"]

                # username和password字段未提供
                elif "username" in data.keys() and "password" in data.keys():
                    del response.data["username"]
                    del response.data["password"]
                    response.data["code"] = 400
                    response.data["msg"] = "请输入用户名和密码"

                # username字段未提供
                elif "username" in data.keys():
                    del response.data["username"]
                    response.data["code"] = 400
                    response.data["msg"] = "请输入用户名"

                # password字段未提供
                elif "password" in data.keys():
                    del response.data["password"]
                    response.data["code"] = 400
                    response.data["msg"] = "请输入密码"
            elif 'ErrorDetail' in str(response.data):
                error_data = response.data[0]
                del response.data[0]
                response.data = {"code": 400, "msg": 'error', "data": error_data}
            else:
                response.data["code"] = 400
                response.data["msg"] = response.data["detail"]
                del response.data["detail"]
        return response
