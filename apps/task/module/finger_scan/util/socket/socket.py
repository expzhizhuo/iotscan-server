"""
@Project ：指纹识别 
@File    ：socket.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/10/11 15:25 
"""
import logging
import socket
import ssl
import io
import gzip
from poc_tool.tools import tools

log = logging.getLogger('tasks-server-api')


class SocketSendModel:
    """
    基于socket封装的请求数据包
    """

    def __init__(self):
        """
        需要初始化的默认数据
        """

    @staticmethod
    def _socket_data(data):
        """
        socket建立链接返回的数据处理
        :param data:二进制数据bytes
        :return:json
        """
        content_length = 0
        index = data.find(b'\r\n\r\n')  # 找到消息头与消息体分割的地方
        head = data[:index]
        body = data[index + 4:]
        try:
            if "gzip" in head.decode('utf-8', 'ignore') and "encoding" in head.decode('utf-8', 'ignore'):
                compressed_data_list = body.split(b"\r\n")
                if len(compressed_data_list) > 1:
                    compressed_data = compressed_data_list[1]
                else:
                    compressed_data = compressed_data_list[0]
                # 解压缩数据
                compressed_stream = io.BytesIO(compressed_data)
                with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as decompressed_stream:
                    body = decompressed_stream.read()
        except Exception as e:
            log.debug(f"gzip数据解密错误 {e}")
        # 获取Content-Length
        headers = head.split(b'\r\n')
        for header in headers:
            if header.startswith(b'Content-Length'):
                content_length = int(header.split(b' ')[-1])
        if content_length == 0:
            # 如果不是http请求的数据，获取不到content_length则直接去TCP返回的所有数据流的长度
            content_length = len(data)
        return dict(header=str(head.decode('utf-8', 'ignore')), length=content_length,
                    body=str(body.decode('utf-8', 'ignore')))

    def send_tcp(self, host, port, is_ssl: str = False, send_data=None, timeout: int = 5):
        """
        发送TCP请求
        :param timeout: 超时时间
        :param send_data: tcp要发送的数据
        :param is_ssl: 是否是https
        :param host:目标地址
        :param port: 端口号
        :return:json
        """
        if send_data is None:
            send_data = f'GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {tools.get_random_ua()}\r\nTypeServer: Scan\r\n\r\n'
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if port == 443 or is_ssl:
                # 判断如果是443端口获取需要https请求，添加对https的请求支持
                sock = ssl.wrap_socket(socket.socket())
                if not sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE):
                    sock = ssl.wrap_socket(socket.socket())
            # 连接服务端
            if sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            sock.connect((host, port))
            log.debug(f"tcp建立链接成功，开始发送数据 {send_data}")
            if isinstance(send_data, bytes):
                sock.send(send_data)
            else:
                sock.send(send_data.encode())
            data = self._socket_data(sock.recv(1024))
            log.debug(f"返回数据 {data}")
            sock.close()
            return data
        except Exception as e:
            if sock:
                sock.close()
            raise ValueError(e)

    def send_udp(self, host, port, is_ssl: str = False, send_data=None, timeout: int = 5):
        """
        发送UDP请求
        :param timeout: 超时时间
        :param send_data: 要发送的udp数据
        :param is_ssl: 是否是https
        :param host:目标地址
        :param port: 端口号
        :return:json
        """
        if send_data is None:
            send_data = f'\n'
        sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if port == 443 or is_ssl:
                # 判断如果是443端口获取需要https请求，添加对https的请求支持
                sock_udp = ssl.wrap_socket(socket.socket())
                if not sock_udp.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE):
                    sock_udp = ssl.wrap_socket(socket.socket())
            sock_udp.settimeout(timeout)
            # 连接服务端
            sock_udp.connect((host, port))
            log.info(f"udp建立链接成功，开始发送数据\n{send_data}")
            if isinstance(send_data, bytes):
                sock_udp.send(send_data)
            else:
                sock_udp.send(send_data.encode())
            data = self._socket_data(sock_udp.recv(1024))
            sock_udp.close()
            return data
        except Exception as e:
            if sock_udp:
                sock_udp.close()
            raise ValueError(e)


SocketSend = SocketSendModel()
