import json
import os

import requests
from django.core.cache import cache
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone
from rest_framework.decorators import action
from common.permission import Permission

from common.response import response
from rest_framework import viewsets
from ..models.models import *
from .serializers import *
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from pocsuite3.api import init_pocsuite
from pocsuite3.lib.core.data import kb
from iotscan import settings
from django.db.models import Q
# django自带的模糊查询
import logging
from common.tools import common_tool
from ..user.utils.AuthPermission import SuperPermissions, IsAuthAction
from common.FileEncrypt import filetools
from common.export_report import ExportXlsx

log = logging.getLogger('tools-api')


# Create your views here.
class PocListView(viewsets.ViewSet):
    """
    poc相关操作接口
    """
    http_method_names = ['get', 'post']
    permission_classes = [IsAuthenticated]
    serializer_class = GetPocListSerializers
    queryset = Vulnerability.objects.all()

    def list(self, request):
        """
        获取poc列表
        :param request:
        :return:list
        """
        log.info(f"用户{request.user}执行获取poc列表操作")
        try:
            if request.GET.get("id"):
                poc_list = Vulnerability.objects.filter(id=request.GET.get("id")).order_by('-create_time')
            else:
                poc_list = Vulnerability.objects.all().order_by('-create_time')
            page = ToolsPageNumberPagination()
            page_data = page.paginate_queryset(queryset=poc_list,
                                               request=request, view=self)
            data = GetPocListSerializers(page_data, many=True)
            page.get_paginated_response(data.data)
            return response.success({"total": page.page.paginator.count, "list": data.data})
        except Exception as e:
            log.error(f'用户{request.user}执行获取poc列表接口出错，错误信息{e}')
            return response.server_error(e)

    def create(self, request, pk=None):
        """
        读取本地储存的所有poc文件信息
        :param request:
        :param pk:
        :return:json数据结果
        """
        log.info(f'用户{request.user}执行本地POC文件初始化操作')
        # yaml漏洞等级映射表
        severity_mapping = {
            'info': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4,
            'unknown': 0,
            'None': 0,
            '': 0
        }

        # 需要读取的初始化常量
        init_attr = (('name', 'poc_name'), ('author', 'vul_author'), ('appName', 'vul_name'),
                     ('appVersion', 'vul_range'), ('vulType', 'vul_type'),
                     ('desc', 'vul_desc'), ('Level', 'vul_leakLevel'), ('hasexp', 'has_exp'),
                     ('device_name', 'vul_device_name'), ('vulDate', 'vul_vulDate'), ('createDate', 'vul_createDate'),
                     ('updateDate', 'vul_updateDate'))
        yaml_init_attr = (
            ('name', 'poc_name'), ('author', 'vul_author'), ('desc', 'vul_desc'), ('severity', 'vul_leakLevel'))
        # 获取poc文件存放的位置
        plugin_path = settings.POC_PLUGIN_PATH
        poc_plugin_info = list()
        # 数据库同步更新
        # Vulnerability.objects.filter().update(**{'is_active': False})
        # 直接删除数据库中的所有poc存储数据，然后在新增
        # Vulnerability.objects.all().delete()
        total_success = 0
        total_error = 0
        try:
            for file in os.listdir(plugin_path):
                if file in ('__pycache__', '__init__.py', "tools", ".DS_Store"):
                    continue
                file_extension = file.split('.')[-1]
                if file_extension in ('py', 'yaml'):
                    print(f"正在加载POC文件{file}")
                    init_pocsuite({'poc': os.path.join(plugin_path, file)})
                    mod = kb.registered_pocs.get(f'pocs_{file.split(".")[0]}')
                    if not mod:
                        continue
                    existing_poc = Vulnerability.objects.filter(file_name=file).first()
                    if existing_poc:
                        init_attrs = yaml_init_attr if file_extension == "yaml" else init_attr
                        for module_attr, model_attr in init_attrs:
                            # 获取模块属性值
                            mod_value = getattr(mod, module_attr, None)
                            # 如果属性是severity，使用映射字典来转换值
                            if module_attr == 'severity':
                                mod_value = severity_mapping.get((mod_value or '').lower(), mod_value)  # 默认情况下保留原始值
                            # 如果属性是vul_author并且长度超过20，截取前20个字符
                            if module_attr == 'author' and len(mod_value) > 30:
                                mod_value = mod_value[:30]
                            # 使用模型属性名称来设置属性
                            setattr(existing_poc, model_attr, mod_value)
                        existing_poc.save()
                        log.info(f"当前POC文件{file}已更新")
                        total_success += 1
                    else:
                        single_model = Vulnerability(id=uuid.uuid4().hex, file_name=file, create_user=request.user)
                        init_attrs = yaml_init_attr if file_extension == "yaml" else init_attr
                        for module_attr, model_attr in init_attrs:
                            # 获取模块属性值
                            mod_value = getattr(mod, module_attr, None)
                            if mod_value is None:
                                print(f'获取到None {mod_value},文件名 {file}')
                            else:
                                # 如果属性是severity，使用映射字典来转换值
                                if module_attr == 'severity':
                                    mod_value = severity_mapping.get((mod_value or '').lower(), mod_value)  # 默认情况下保留原始值
                                # 如果属性是vul_author并且长度超过20，截取前20个字符
                                if module_attr == 'author' and len(mod_value) > 30:
                                    mod_value = mod_value[:30]
                                # 使用模型属性名称来设置属性
                                setattr(single_model, model_attr, mod_value)
                        poc_plugin_info.append(single_model)
                        total_success += 1
                else:
                    log.info(f'发现异常poc文件信息：{file}')
                    total_error += 1
            Vulnerability.objects.bulk_create(poc_plugin_info)
            data = {"msg": "加载本地poc列表成功", "info": f"成功加载{total_success}个poc,加载失败{total_error}个poc"}
            return response.success(data)
        except Exception as e:
            log.error(f'用户{request.user}执行本地POC文件初始化操作接口出错，错误信息{e}')
            return response.server_error(e)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def search(self, request, pk=None):
        """
        搜索接口，该搜索接口是模糊查询
        :param request:keyword
        :param pk:None
        :return:json
        """
        log.info(f"用户{request.user}执行POC列表模糊查询操作")
        keyword = request.POST.get("keyword")
        if keyword is None:
            return response.error("请输入要查询的内容")
        query = Q(poc_name__contains=keyword) | Q(vul_author__contains=keyword) | Q(vul_author__contains=keyword) | Q(
            vul_type__contains=keyword) | Q(vul_device_name__contains=keyword) | Q(vul_desc__contains=keyword)
        poc_list = Vulnerability.objects.filter(query).order_by('-create_time')
        page = ToolsPageNumberPagination()
        page_data = page.paginate_queryset(queryset=poc_list,
                                           request=request, view=self)
        data = GetPocListSerializers(page_data, many=True)
        page.get_paginated_response(data.data)
        return response.success({"total": page.page.paginator.count, "list": data.data})

    @action(detail=False, methods=['post'], permission_classes=[IsAdminUser])
    def upload_file(self, request, pk=None):
        """
        上传POC文件接口
        :param request:
        :param pk:
        :return:
        """

        log.info(f"用户{request.user}进行poc文件上传操作")
        file_obj = request.FILES.get('file')
        file_name = file_obj.name
        file_size = file_obj.size
        file_type = file_obj.content_type
        file_conent = file_obj.read()
        if file_name.split('.')[-1] != 'bin':
            return response.error("异常文件")
        print('文件内容', file_conent)
        # enfile = filetools.encrypt_file(file_conent)
        # print('加密数据', enfile)
        defile = filetools.decrypt_file(file_conent)
        print('解密数据', defile)
        # with open(f'/Users/zhizhuo/Desktop/poc/test0.bin', 'wb') as f:
        #     f.write(enfile)
        # with open(f'/Users/zhizhuo/Desktop/poc/test1.zip', 'wb') as f:
        #     f.write(defile)
        # with open(f'/Users/zhizhuo/Desktop/poc/test2.zip', 'wb') as f:
        #     f.write(file_conent)
        print(f'File name: {file_name}, File size: {file_size}, File type: {file_type}')
        return response.success()

    @action(detail=False, methods=['post'], permission_classes=[IsAdminUser])
    def delete_poc(self, request, pk=None):
        """
        删除POC
        :param request:
        :param pk:
        :return:
        """
        log.info(f"用户{request.user}执行获取poc删除操作")
        poc_id = request.data.get('poc_id')
        try:
            if not poc_id:
                return response.error("请输入poc_id")
            Poc_Data = Vulnerability.objects.filter(id=poc_id).values("id", "poc_name", "file_name").first()
            poc_file_path = f"{settings.POC_PLUGIN_PATH}/{Poc_Data['file_name']}"
            if not Poc_Data:
                return response.error("异常数据")
            Delete_Data = Vulnerability.objects.filter(id=poc_id).delete()
            os.remove(poc_file_path)
            if Delete_Data:
                return response.success("删除成功")
            else:
                return response.error("删除失败")
        except Exception as e:
            log.error(f"删除poc{poc_id}出错，错误信息 {e}")
            return response.server_error("系统错误")


class ProxySettingView(viewsets.ViewSet):
    """
    代理相关的操作接口
    """
    http_method_names = ['get', 'post', 'delete', 'put']
    permission_classes = [IsAuthenticated]
    serializer_class = GetProxyInfoSerializers, SaveProxyInfoSerializers
    queryset = ProxySetting.objects.all()

    def list(self, request, pk=None):
        """
        获取当前数据库中的所有代理信息
        :param request:
        :param pk:
        :return:json
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}执行获取当前数据库中的所有代理信息操作")
        try:
            if request.GET.get("id"):
                if IsSuperAdmin:
                    proxy_list = ProxySetting.objects.all().order_by('-id')
                else:
                    proxy_list = ProxySetting.objects.filter(id=request.GET.get("id"),
                                                             create_user=request.user).order_by(
                        '-id')
            else:
                if IsSuperAdmin:
                    proxy_list = ProxySetting.objects.all().order_by('-id')
                else:
                    proxy_list = ProxySetting.objects.filter(create_user=request.user).order_by('-id')
            page = ToolsPageNumberPagination()
            page_data = page.paginate_queryset(queryset=proxy_list,
                                               request=request, view=self)
            proxydata = GetProxyInfoSerializers(page_data, many=True)
            page.get_paginated_response(proxydata.data)
            return response.success({"total": page.page.paginator.count, "list": proxydata.data})
        except Exception as e:
            log.error(f"用户{request.user}执行获取当前数据库中的所有代理信息操作出错，错误信息：{e}")
            return response.server_error(e)

    def create(self, request, pk=None):
        """
        新增代理信息
        :param request:
        :param pk:
        :return:json
        """
        log.info(f"用户{request.user}执行新增代理信息操作")
        if request.body is None or len(request.POST) < 2:
            return response.error("请传入必要参数")
        host = request.POST.get("host")
        port = request.POST.get("port")
        type = request.POST.get("type")
        username = request.POST.get("username")
        password = request.POST.get("password")
        if host is None:
            return response.error("请输入代理host信息")
        if port is None:
            return response.error("请输入代理端口号")
        if type is None:
            return response.error("请输入代理类型")
        if common_tool.is_local_ip(host):
            return response.error("请忽输入内网本地ip")
        if common_tool.verify_ip(host) is None:
            return response.error("请输入正确的host地址")
        if int(port) > 65535:
            return response.error("请输入正确的端口号，端口范围1-65535")
        print(request.user.id)
        insert_data = {
            'host': host,
            'port': port,
            'proxy_type': type,
            'proxy_username': username,
            'proxy_password': password,
            'create_user': request.user.id
        }
        result = SaveProxyInfoSerializers(data=insert_data)
        if result.is_valid():
            result.save()
            return response.success("创建成功")
        else:
            print(result.errors)
            if result.errors.get('host'):
                return response.error(result.errors.get('host')[0])
            return response.error(result.errors)

    def destroy(self, request, pk=None):
        """
        删除代理信息
        :param request:
        :param pk:int
        :return:json
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}执行删除代理信息操作")
        try:
            proxy_id = int(pk)
            if proxy_id is None:
                return response.error("请传入id信息")
            # 删除操作
            if IsSuperAdmin:
                # 管理员可以操作所有人的
                result = ProxySetting.objects.filter(id=proxy_id)
            else:
                result = ProxySetting.objects.filter(id=proxy_id, create_user=request.user)
            if result:
                result.delete()
                return response.success("删除成功")
            else:
                return response.error("删除失败，当前信息不存在")
        except Exception as e:
            log.error(f"用户{request.user}执行删除代理信息操作出错，错误信息：{e}")
            return response.server_error(e)

    def update(self, request, pk=None):
        """
        单个代理配置信息修改
        :param request:
        :param pk: int
        :return:
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}执行单个代理配置信息修改操作")
        if pk is None:
            return response.error("请传入关键参数id")
        # 数据库执行更新操作
        host = request.POST.get("host")
        port = request.POST.get("port")
        username = request.POST.get("username")
        password = request.POST.get("password")
        types = request.POST.get("type")
        status = request.POST.get("status")
        updatainfo = {
            'host': host,
            'port': port,
            'proxy_type': types,
            'proxy_username': username,
            'proxy_password': password,
            'proxy_status': status,
        }
        if IsSuperAdmin:
            # 管理员可以操作所有
            getinfo = ProxySetting.objects.filter(id=int(pk))
        else:
            getinfo = ProxySetting.objects.filter(id=int(pk), create_user=request.user)
        if getinfo:
            result = UpdataProxySettingSerializers(instance=getinfo, data=updatainfo)
            if result.is_valid():
                if status == 'True' or status == 1:
                    print("启动此代理")
                    # 设置缓存
                    cache.set("proxy_setting", json.dumps(updatainfo), timeout=None)
                getinfo.update(**updatainfo, create_user=request.user)
                return response.success("更新成功")
            else:
                return response.error(result.errors)
        else:
            return response.error("当前id不存在")

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def test(self, request, pk=None):
        """
        代理验证接口
        :param request:
        :param pk:
        :return:
        """
        log.info(f"用户{request.user}执行代理可用性测试操作")
        id = request.POST.get("id")
        test_url = request.POST.get("url")
        timeout = request.POST.get("timeout")
        if test_url is None or test_url == '':
            test_url = 'http://www.baidu.com'
        if timeout is None or timeout == '':
            timeout = 10
        if id is None or id == '':
            return response.error("请传入关键参数id")
        proxy_data = ProxySetting.objects.filter(id=int(id), create_user=request.user)
        if proxy_data:
            proxy = proxy_data.values()[0]
            proxy_type = proxy.get("proxy_type").lower()
            host = proxy.get("host")
            port = proxy.get("port")
            username = proxy.get("proxy_username")
            password = proxy.get("proxy_password")

            if not username and not password:
                proxyinfo = {
                    'http': f'{proxy_type}://{host}:{port}',
                    'https': f'{proxy_type}://{host}:{port}',
                }
            elif username and not password:
                proxyinfo = {
                    'http': f'{proxy_type}://{username}@{host}:{port}',
                    'https': f'{proxy_type}://{username}@{host}:{port}',
                }
            else:
                proxyinfo = {
                    'http': f'{proxy_type}://{username}:{password}@{host}:{port}',
                    'https': f'{proxy_type}://{username}:{password}@{host}:{port}',
                }
            try:
                res = requests.get(url=test_url, headers={
                    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) by zhizhuo',
                    'Connection': 'close'
                }, proxies=proxyinfo, timeout=int(timeout), verify=False)
                return response.success({"message": "当前代理可用", "res_data": res.text})
            except Exception as e:
                log.error(f"用户{request.user}执行代理可用性测试出错，错误信息：{e}")
                return response.error("当前代理不可用")
        return response.error("异常请求")

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def use_proxy(self, request, pk=None):
        """
        是否启用改代理
        :param request:
        :param pk:
        :return:
        """
        log.info(f"用户{request.user}执行代理是否启用操作")
        try:
            id = request.POST.get("id")
            status = request.POST.get("status")
            proxy_data = ProxySetting.objects.filter(id=int(id), create_user=request.user)
            if status not in ['True', 'False']:
                return response.error("异常状态更新")
            if status == 'True':
                if proxy_data:
                    proxy = proxy_data.values()[0]
                    proxy_type = proxy.get("proxy_type").lower()
                    host = proxy.get("host")
                    port = proxy.get("port")
                    username = proxy.get("proxy_username")
                    password = proxy.get("proxy_password")
                    if not username and not password:
                        proxyinfo = {
                            'http': f'{proxy_type}://{host}:{port}',
                            'https': f'{proxy_type}://{host}:{port}',
                        }
                    elif username and not password:
                        proxyinfo = {
                            'http': f'{proxy_type}://{username}@{host}:{port}',
                            'https': f'{proxy_type}://{username}@{host}:{port}',
                        }
                    else:
                        proxyinfo = {
                            'http': f'{proxy_type}://{username}:{password}@{host}:{port}',
                            'https': f'{proxy_type}://{username}:{password}@{host}:{port}',
                        }
                    proxy_data.update(id=id, proxy_status=status, update_time=timezone.now())
                    cache.set("proxy_setting", json.dumps(proxyinfo), timeout=None)
                    return response.success()
                return response.error("异常操作")
            else:
                proxy_data.update(id=id, proxy_status=status, update_time=timezone.now())
                cache.delete_pattern("proxy_*")  # 删除缓存中的代理配置
                return response.success()
        except Exception as e:
            log.error(f"启动代理报错，错误信息{e}")
            return response.error("异常操作")


class FofaSettingView(viewsets.ViewSet):
    """
    fofa相关配置接口
    """
    http_method_names = ['get', 'post', 'delete', 'put']
    permission_classes = [IsAuthenticated]
    serializer_class = GetFofaSettingSerializers, SaveFofaSettingSerializers
    queryset = FofaSetting.objects.all()

    def list(self, request, pk=None):
        """
        查询当前所有fofa配置
        :param request:
        :param pk:
        :return:
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}执行fofa配置获取操作")
        if request.GET.get("id"):
            """
            查询单个fofa接口的详细配置
            """
            if IsSuperAdmin:
                # 管理员可以查看所有
                fofa_data = FofaSetting.objects.filter(id=request.GET.get("id")).order_by('-id')
            else:
                fofa_data = FofaSetting.objects.filter(id=request.GET.get("id"), create_use=request.user).order_by(
                    '-id')
        else:
            if IsSuperAdmin:
                # 管理员可以查询所有数据库配置信息
                fofa_data = FofaSetting.objects.all().order_by('-id')
            else:
                fofa_data = FofaSetting.objects.filter(create_user=request.user).order_by('-id')
        page = ToolsPageNumberPagination()
        page_data = page.paginate_queryset(queryset=fofa_data,
                                           request=request, view=self)
        data = GetFofaSettingSerializers(page_data, many=True)
        page.get_paginated_response(data.data)
        return response.success({"total": page.page.paginator.count, "list": data.data})

    def create(self, request, pk=None):
        """
        新增fofa配置
        :param request:
        :param pk:
        :return:
        """
        log.info(f"用户{request.user}执行新增fofa配置信息")
        if request.body is None or len(request.POST) < 2:
            return response.error("请传入必要参数")
        fofa_email = request.POST.get("fofa_email")
        fofa_key = request.POST.get("fofa_key")
        fofa_size = request.POST.get("fofa_size")
        fofa_status = request.POST.get("fofa_status")
        if fofa_email is None or fofa_key is None or fofa_size is None:
            return response.error("请认真填写表单")
        if fofa_status not in ['True', 'False']:
            return response.error("非法状态参数传入")
        # 数据库操作
        insert_data = {
            'fofa_email': fofa_email,
            'fofa_key': fofa_key,
            'fofa_size': fofa_size,
            'fofa_status': fofa_status,
            'create_user': request.user.id
        }
        result = SaveFofaSettingSerializers(data=insert_data)
        if result.is_valid():
            result.save()
            return response.success("创建成功")
        else:
            return response.error(result.errors)

    def destroy(self, request, pk=None):
        """
        删除单个fofa节点配置
        :param request:
        :param pk:
        :return:msg
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}执行fofa节点单配置删除操作")
        if pk:
            id = int(pk)
            if IsSuperAdmin:
                result = FofaSetting.objects.filter(id=id)
            else:
                # 非只能删除自己创建的
                result = FofaSetting.objects.filter(id=id, create_user=request.user)
            if result:
                result.delete()
                return response.success("删除成功")
            else:
                return response.error("删除失败，当前信息不存在")

    def update(self, request, pk=None):
        """
        单节点fofa信息更新
        :param request:
        :param pk:
        :return:msg
        """
        IsSuperAdmin = Permission.IsSuperAdmin(request)
        log.info(f"用户{request.user}执行fofa节点单配置更新操作")
        id = int(pk)
        if id is None:
            return response.error("请传入id信息")
        if IsSuperAdmin:
            # 非管理员只能更新自己创建
            fofainfo = FofaSetting.objects.filter(id=id)
        else:
            fofainfo = FofaSetting.objects.filter(id=id, create_user=request.user)
        if fofainfo:
            fofa_email = request.POST.get("fofa_email")
            fofa_key = request.POST.get("fofa_key")
            fofa_size = request.POST.get("fofa_size")
            fofa_status = request.POST.get("fofa_status")
            insert_data = {
                'fofa_email': fofa_email,
                'fofa_key': fofa_key,
                'fofa_size': fofa_size,
                'fofa_status': fofa_status,
                'user': request.user.id
            }
            result = SaveFofaSettingSerializers(fofainfo, data=insert_data)
            if result.is_valid():
                fofainfo.update(**insert_data)
                return response.success("更新成功")
            else:
                return response.error(result.errors)
        else:
            return response.error("当前id不存在")

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def test(self, request, pk=None):
        """
        fofa账户验证接口
        :param request:
        :param pk:
        :return:
        """
        log.info(f"用户{request.user}执行fofa账户验证操作")
        id = request.POST.get("id")
        if id is None or id == '':
            return response.error("请传入关键参数id")
        fofa_data = FofaSetting.objects.filter(id=int(id), create_user=request.user)
        if fofa_data:
            try:
                res = requests.get(url='https://fofa.info/api/v1/info/my', headers={
                    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0) by zhizhuo',
                    'Connection': 'close',
                }, data={
                    'email': fofa_data.values()[0].get("fofa_email"),
                    'key': fofa_data.values()[0].get("fofa_key"),
                }, timeout=10, allow_redirects=False)
                if res.json()['error']:
                    return response.error(res.json().get("errmsg"))
                else:
                    return response.success(res.json())
            except Exception as e:
                log.error(f"用户{request.user}执行fofa账户验证操作出错，fofa官方接口错误信息{e}")
                return response.server_error(e)
        else:
            return response.error("当前信息不存在")


class ReportExportView(viewsets.ViewSet):
    http_method_names = ['get', 'post']
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def export_xlsx(self, request, pk=None):
        """
        导出资产文件
        :param request:
        :param pk:
        :return:
        """
        log.info(f"用户{request.user}执行任务资产导出操作")
        try:
            verify_data = VerifyExportXlsxReportSerializers(data=request.GET)
            if verify_data.is_valid():
                task_ids = verify_data.data.get('task_ids')
                db_out_data = IotTaskFingerResult.objects.filter(
                    target_id_id=task_ids).order_by(
                    'id')
                out_data = ExportXlsxReportDataSerializers(db_out_data, many=True, read_only=True)
                file_bytes = ExportXlsx.get_excel(out_data.data)
                # 设置响应头信息
                res = HttpResponse(content_type='application/vnd.ms-excel')
                res['Content-Disposition'] = f'attachment;filename=iotscan-{task_ids}.xlsx'
                # 设置响应文件的bytes数据
                res.write(file_bytes)
                return res
            else:
                return response.error(f"{list(verify_data.errors.keys())[0]}{list(verify_data.errors.values())[0][0]}")
        except Exception as e:
            log.error(f"导出资产报错，错误信息：{e}")
            return response.server_error(e)
