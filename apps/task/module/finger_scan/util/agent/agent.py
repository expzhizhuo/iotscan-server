"""
@Project ：指纹识别 
@File    ：agent.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/10/16 16:25 
"""
import asyncio
import json
import logging
import os
import re
import warnings
from urllib.parse import urlparse, urljoin
from .load_plugin import LoadPlugin
from typing_extensions import Union
from ..socket.req import requests_retry_session
from ...util.core import (GetIconHash, GetFinger, GetTcpFinger, GetCdnInfo, GetSSLInfo, GetIcpInfo, GetIPInfo)
import requests
from poc_tool.tools import tools
from requests.exceptions import SSLError
from urllib3.exceptions import InsecureRequestWarning
from ...util.socket import SocketSend

log = logging.getLogger('tasks-server-api')
# 解决requests的ssl证书warning提示
warnings.filterwarnings('ignore', category=InsecureRequestWarning)


class FingerAgent:
    """
    指纹识别agent
    """

    def __init__(self, url: str, port: Union[int, str] = None, port_service: str = None, scan_type: str = None,
                 proxy: dict = None, timeout: int = 3, retries: int = 3):
        """
        初始化配置
        :param url:url地址
        :param proxy:代理信息
        :param timeout:超时时间
        :param retries:重试次数
        """
        if proxy is None:
            proxy = {}
        self.url = url
        self.port = port
        self.port_service = port_service
        self.scan_type = scan_type
        self.proxy = proxy
        self.timeout = timeout
        self.retries = retries
        self.plugin_path = os.path.dirname(__file__) + "/../plugin/"
        self.headers = {
            'Accept': 'application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, '
                      'application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*',
            'User-agent': tools.get_random_ua(),
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Connection': 'close'
        }

    @staticmethod
    def verify_data(url: str):
        """
        数据验证
        :param url:url地址
        :return:http or https url
        """
        if url.startswith(('http://', 'https://')):
            return url
        if url.endswith(':80'):
            return f'http://{url[:-3]}'
        if url.endswith(':443'):
            return f'https://{url[:-4]}'
        return f'https://{url}'

    def _get_title(self, url: str, res: requests.models.Response):
        """
        获取站点的title
        :param url:url
        :param res:响应数据
        :return:json
        """
        res.encoding = res.apparent_encoding
        if "charset=\"utf-8\"" in res.text:
            res.encoding = "utf-8"
        # 解析URL
        parsed_url = urlparse(url)
        # 获取基础URL
        base_url = f'{parsed_url.scheme}://{parsed_url.netloc}/'
        # 获取基础路径
        base_path = parsed_url.path
        title = None
        title_url = None
        title_list = re.findall(r'<title>(.*?)</title>', res.text, re.I | re.M | re.S)
        dom_title = re.findall(r'document.title.*?=.*?\((.*?)\)', res.text, re.I | re.M | re.S)
        if title_list:
            title = title_list[0].translate(str.maketrans("", "", "\r\n\t")).replace("  ", "")
            log.debug(f"正则识别到title：{title}")
        if dom_title and len(dom_title) > 0:
            log.debug(f"识别到dom渲染title {dom_title}")
            _title = dom_title[0].replace('"', '')
            invalid_titles = ["title", ".title", "top.", ".login", "=", "||", "''", "null"]
            if any(invalid in _title for invalid in invalid_titles) or "null" in _title.lower():
                log.debug("dom获取到title不符合要求，已pass")
            else:
                log.debug("dom获取到title符合要求，已经重置title")
                title = _title
        i18n_path_list = re.findall(r'type="text/javascript".*?src="(.*?)"', res.text, re.I | re.M | re.S)
        for i18n_path in i18n_path_list:
            if i18n_path.endswith('.js') and 'i18n' in i18n_path:
                path = i18n_path.lstrip('/')
                title_url = urljoin(base_url, path if path.startswith(base_path) else base_path + '/' + path)
                break
        if title_url:
            log.debug(f"识别到国际化开发，正在获取国际化开发js中的title中数据")
            try:
                for _ in range(self.retries):
                    # 允许跟随跳转拿到最后的js内容
                    resp_title = requests.get(url=title_url, headers=self.headers, timeout=5, verify=False,
                                              allow_redirects=True)
                    if resp_title.status_code == 200:
                        title_re = re.findall(r'"top.login.title": "(.*?)",', resp_title.text, re.I | re.M | re.S)
                        log.debug(f"国际化开发js中的title中数据获取成功，{title_re}")
                        if title_re:
                            title = title_re[0]
                            log.debug(f"识别到新title正在替换原有title，新title {title}")
                    break
            except Exception as e:
                log.debug(f"获取国际化开发js中title数据报错，错误信息 {e}")
        return title

    @staticmethod
    def _get_icon_url(url, html):
        """
        获取icon的url地址
        :param html:响应body数据流
        :return:url
        """
        parsed_url = urlparse(url)
        base_url = f'{parsed_url.scheme}://{parsed_url.netloc}/'
        base_path = parsed_url.path
        if "." in base_path or ".htm" in base_path:
            base_path = ""
        favicon_url = base_url + "favicon.ico"
        # 查找icon链接
        icon_index = html.lower().find("<link rel=\"icon\"")
        # 查找shortcut icon链接
        shortcut_index = html.lower().find("<link rel=\"shortcut icon\"")
        # 正则匹配所有href链接
        icon_list = re.findall('href="(.*?)">', html.replace(' ', ''), re.I | re.M | re.S)
        if icon_index == -1 and shortcut_index == -1:
            # 筛选出ico或icon后缀的链接
            image_extensions = ['ico', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'icon']
            ic = [ico for ico in icon_list if ico.split(".")[-1].lower() in image_extensions]
            # 如果有符合条件的链接，更新favicon地址
            if ic:
                favicon_url = base_url + ic[0]
                log.debug(f"发现新icon地址 {favicon_url}")
                if base_path:
                    favicon_path = base_path + ic[0]
                    favicon_url = urljoin(base_url, favicon_path.lstrip('/'))
                    log.debug(f"有原始path已重置url {favicon_url}")
            if base_path and not ic:
                favicon_path = base_path + "/favicon.ico"
                favicon_url = urljoin(base_url, favicon_path.lstrip('/'))
                log.debug(f"使用默认url+path {favicon_url}")
        else:
            # 如果找到icon链接，获取该链接标签
            if icon_index != -1:
                link_tag = html[icon_index:html.find(">", icon_index)]
            else:
                # 如果找到shortcut icon链接，获取该链接标签
                link_tag = html[shortcut_index:html.find(">", shortcut_index)]
            # 从链接标签中提取favicon路径
            favicon_path = re.search('href="([^"]+)"', link_tag)
            if favicon_path:
                favicon_path = favicon_path.group(1)
                # 拼接完整的favicon URL
                favicon_url = urljoin(base_url, favicon_path.lstrip('/'))
                log.debug(f"页面提取到icon url {favicon_url}")
                if not favicon_path.startswith(base_path) and not base_path.lstrip('/') + '/' in html:
                    if "log" in base_path or len(base_path.split("/")) > 3:
                        base_path = base_path.lstrip("/").split("/")
                        base_path.pop()
                        base_path = '/'.join(ba for ba in base_path)
                        log.debug(f"原始path过长or识别到login结尾自动修正，新path {base_path}")
                        favicon_path = base_path + '/' + favicon_path.lstrip('/')
                    else:
                        favicon_path = base_path + '/' + favicon_path.lstrip('/')
                    favicon_url = urljoin(base_url, favicon_path.lstrip('/'))
                    log.debug(f"有原始path且原始path不在favicon_path中已重置url {favicon_url}")

        return favicon_url

    def _echo_data(self, url: str, resp: requests.models.Response):
        """
        处理生成最后的返回语句
        :param resp:response数据
        :return:json
        """
        redirect_url = url
        redirect_num = 0
        old_resp = resp
        if 300 <= resp.status_code < 400:
            redirect_num += 1
            redirect_url = resp.headers.get('Location', '/')
            redirect_url = urljoin(url, redirect_url)
            log.debug(f"30X重定向url地址 {redirect_url}")
            try:
                resp = requests.get(url=redirect_url, headers=self.headers, timeout=5, verify=False,
                                    allow_redirects=True)
            except Exception as e:
                log.debug(f"30X重定向失败 {e}")
                pass
        patterns = [
            (r"window.top.location.href='(.*?)';", 'window.top.location.href'),
            (r"window.location.href='(.*?)';", 'window.location.href'),
            (r'window.location.href="(.*?)"', 'window.location'),
            (r'content=.*?;url=(.*?)>', '<meta http-equiv=refresh content='),
            (r'content=.*?;url=(.*?)"/>', '<meta http-equiv="refresh" content='),
            (r'content="0;URL=(.*?)">', 'content="0;URL=')
        ]
        black_js_redirect = ["script>", "\">", "href=", ".css", ".js", "><"]
        for pattern, text in patterns:
            if text in resp.text:
                redirect_url_list = re.findall(pattern, resp.text.replace(' ', ''), re.I | re.M | re.S)
                if redirect_url_list:
                    redirect_url = redirect_url_list[0].replace("'", "")
                    if all(substring not in redirect_url for substring in black_js_redirect):
                        redirect_url = urljoin(url, redirect_url.lstrip('/'))
                        redirect_num += 1
                        log.debug('js重定向:' + redirect_url)
                        if redirect_url.startswith("http://") and url.startswith("https://"):
                            redirect_url = url
                        else:
                            # js和30x重定向完成之后最后一次跟随重定向
                            try:
                                resp = requests.get(url=redirect_url, headers=self.headers, timeout=5, verify=False,
                                                    allow_redirects=True)
                            except Exception as e:
                                log.debug(f"30X重定向失败 {e}")
                                pass
                        break
                    else:
                        redirect_url = url
        resp.encoding = resp.apparent_encoding
        if (redirect_url.startswith("https://") and url.startswith("http://")) and 300 <= old_resp.status_code < 400:
            resp = old_resp
            redirect_url = url
        # 获取title
        title = self._get_title(redirect_url, resp)
        icon_hash = GetIconHash(self._get_icon_url(redirect_url, resp.text)).run()
        cms = GetFinger(resp, dict(title=title, icon_hash=icon_hash)).run()
        res_headers = tools.get_res_header(resp)
        server = resp.headers.get('Server')
        is_cdn = GetCdnInfo(url=redirect_url).run()
        cert = GetSSLInfo(url=redirect_url).run()
        icp = GetIcpInfo(body=resp.text).run()
        log.debug(f"获取到ICP备案信息 {icp}")
        return dict(title=title, redirect_num=redirect_num, url=redirect_url, icon_hash=icon_hash, cms=cms,
                    status_code=resp.status_code, server=server, is_cdn=is_cdn,
                    res_headers=res_headers, cert=cert, icp=icp)

    def _send_tcp(self, url):
        """
        发送tcp请求
        :param url:url
        :return:json
        """
        _res = dict(header="", length=0, body="")
        host_list = GetSSLInfo(url=url).get_domain_info()
        host = host_list.get('host')
        port = host_list.get("port")
        is_ssl = host_list.get("is_ssl")
        for _ in range(self.retries):
            try:
                _res = SocketSend.send_tcp(host=host, port=port, is_ssl=is_ssl)
                break
            except Exception as e:
                log.debug(f"try error agent tcp {e}")
                if 'timed out' in str(e):
                    break
                continue
        if _res.get('length') == 0:
            """
            尝试更换其他的请求方式，调用所有的tcp请求插件
            """
            plugin_file = LoadPlugin(plugin_id='', plugin_path=self.plugin_path).get_plugin_filename()
            for plugin_id in plugin_file:
                try:
                    plugin_modules = LoadPlugin(plugin_id=plugin_id, plugin_path=self.plugin_path).run()
                    log.debug(
                        f"正在使用插件{plugin_modules.plugin_name}探测指纹信息，插件是否启用{plugin_modules.plugin_name}")
                    if plugin_modules.plugin_is_active:
                        _res = plugin_modules.run(url=url)
                        if _res.get('length') > 0:
                            log.info(f"插件{plugin_modules.plugin_name}请求成功")
                            break
                except Exception as e:
                    log.debug(f"try error agent tcp plugin {e}")
                    continue
        return _res

    def _send_http(self, url):
        """
        发送http请求
        :param url:url
        :return:json
        """
        url = self.verify_data(url)
        is_cdn = GetCdnInfo(url=url).run()
        result = None
        for _ in range(self.retries):
            try:
                resp = self._request_data(url)
                result = self._echo_data(url, resp)
                break
            except ConnectionError as e:
                log.debug(f"捕获到链接异常，异常信息 {e}")
                break
            except Exception as e:
                log.debug(f'http error {e}')
                break
        if result is None:
            result = self._tcp_client(url, is_cdn)
            if not result.get('res_headers'):
                result = None
        return result

    def _send_https(self, url):
        """
        发送https请求
        :param url:url
        :return:json
        """
        is_cdn = GetCdnInfo(url=url).run()
        result = None
        Pass_SSl = False
        for _ in range(self.retries):
            try:
                result = self._echo_data(url, self._request_data(url))
                break
            except SSLError as e:
                log.debug(f'捕获到 ssl证书 {e}')
                Pass_SSl = True
                break
            except ConnectionError as e:
                log.debug(f"捕获到链接异常，异常信息 {e}")
                break
            except Exception as e:
                log.debug(f'https error {e}')
                break
        if result is None and Pass_SSl is False:
            result = self._tcp_client(url, is_cdn)
            if not result.get('res_headers'):
                result = None
        return result

    def _request_data(self, url):
        """
        http请求client
        :param url:url
        :return:response
        """
        req = requests_retry_session()
        return req.get(url=url, headers=self.headers, allow_redirects=False, timeout=5, verify=False)

    @staticmethod
    def _get_tcp_res_status_code(res_headers):
        """
        获取TCP请求响应的状态码
        :param res_headers:tcp请求响应头
        :return:响应状态吗
        """
        server_info = None
        status_code = None
        http_version = None
        status_description = None
        if res_headers.startswith("HTTP"):
            lines = res_headers.split('\n')
            status_line = lines[0]
            parts = status_line.split(' ', 2)
            if len(parts) == 3:
                http_version, status_code, status_description = parts

            server_info = next((line.split("Server:")[1].strip() for line in lines if line.startswith('Server:')), None)
        return dict(http_version=http_version, status_code=status_code, status_description=status_description,
                    server=server_info)

    def _tcp_client(self, url, is_cdn):
        """
        tcp请求client
        :param url:url
        :param is_cdn:True or False
        :return:json
        """
        res = self._send_tcp(url)
        res_headers = res.get("header")
        body = res.get("body")
        server = self._get_tcp_res_status_code(res_headers).get("server")
        status_code = self._get_tcp_res_status_code(res_headers).get("status_code")
        finger_tcp = GetTcpFinger(res=res).run()
        title = finger_tcp.get("title")
        cms = finger_tcp.get("cms")
        icp = GetIcpInfo(body=body).run()
        return dict(title=title, redirect_num=0,
                    url=url,
                    icon_hash=None,
                    cms=cms,
                    status_code=status_code, server=server, is_cdn=is_cdn,
                    res_headers=res_headers, cert=dict(), icp=icp)

    def _verify_server(self, url, result):
        """
        协议验证
        :param url:url地址
        :param result:请求识别结果
        :return:json
        """
        if result is None:
            return None
        cms = result.get("cms")
        res_headers = result.get("res_headers")
        redis_url = result.get("url")
        scheme = None
        if cms == "Redis":
            log.debug("try client redis to get data")
            if redis_url:
                plugin_model = LoadPlugin(plugin_id='redis_finger_tcp', plugin_path=self.plugin_path).run()
                res = json.loads(plugin_model.run(url=self.verify_data(redis_url)))
                result.update(dict(title=None, res_headers=res.get("header")))
        if res_headers and res_headers.startswith("HTTP"):
            scheme_url = result.get("url")
            if scheme_url and scheme_url.startswith('http'):
                scheme = urlparse(scheme_url).scheme
        if not scheme:
            result.update(dict(url=redis_url.replace("http://", "").replace("https://", "")))
        result.update(dict(port=self.port, port_service=self.port_service, scan_type=self.scan_type, scheme=scheme,
                           host=urlparse(url).netloc, ip_info=GetIPInfo(ip=url).run()))
        return result

    async def _http_scan(self, url):
        """
        http格式的数据请求
        :param url:url地址
        :return:json
        """
        if url.endswith(':443'):
            return None
        url = self.verify_data(url).replace('https://', 'http://')
        log.debug(f'http scan url: {url}')
        return self._verify_server(url, self._send_http(url))

    async def _https_scan(self, url):
        """
        https格式的数据请求
        :param url:url地址
        :return:json
        """
        if url.endswith(':80'):
            return None
        url = self.verify_data(url).replace('http://', 'https://')
        log.debug(f'https scan url: {url}')
        return self._verify_server(url, self._send_https(url))

    async def _get_result(self):
        """
        异步时间获取程序执行结果
        :return:
        """
        result = None
        tasks = [
            asyncio.create_task(self._https_scan(url=self.url)),
            asyncio.create_task(self._http_scan(url=self.url))
        ]
        try:
            # 等待所有任务完成，设置超时时间为60秒
            result = await asyncio.wait_for(asyncio.gather(*tasks), timeout=60)
        except asyncio.TimeoutError:
            log.debug("执行超时")
            # 处理超时情况，例如可以取消所有任务
            for task in tasks:
                task.cancel()
        return result

    def run(self):
        """
        指纹扫描的启动函数
        :return:json
        """
        # 这里http和https都进行扫描，优先扫描https，http的tcp请求和https的tcp属于同一种类型，
        # 如果res_headers为空，默认返回None
        agent_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(agent_loop)
        result = agent_loop.run_until_complete(self._get_result())
        # agent_loop.close()
        data = list(filter(None, result))
        if not data:
            data = [dict(title=None, redirect_num=0, url=self.url, port=self.port, port_service=self.port_service,
                         scan_type=self.scan_type, icon_hash=None, cms=None, status_code=None, server=None,
                         is_cdn=GetCdnInfo(url=self.url).run(), res_headers=None, cert=dict(), scheme=None,
                         host=self.url, icp=None, ip_info=GetIPInfo(ip=self.url).run())]
        return json.dumps(data, ensure_ascii=False)
