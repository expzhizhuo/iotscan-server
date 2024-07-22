"""
@Project ：iotscan 
@File    ：common.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/9/22 11:30 
"""
import ipaddress
import logging
import re
import socket
import struct

from django.db.models import Q

from config.config import Config

log = logging.getLogger("common")


class Common_tools:
    def __init__(self):
        self.BLACK_IPS = Config.BLACK_IPS
        self.PRIVATE_NETWORKS = Config.PRIVATE_NETWORKS

    @staticmethod
    def is_number(num: any) -> bool:
        """
        验证是否是数字
        :param num:number
        :return:True or False
        """
        try:
            float(num)
            return True
        except ValueError:
            return False

    def is_internal_ip(self, ip: str) -> bool:
        """
        验证是否是内网地址
        :param ip: ip
        :return: True or False
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network_str in self.PRIVATE_NETWORKS:
                private_network = ipaddress.IPv4Network(network_str)
                if ip_obj in private_network:
                    return True
            return False
        except ValueError:
            return False

    def is_local_ip(self, ip: str) -> bool:
        """
        验证是否是本地ip
        :param ip:ip
        :return:True or False
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            for black_ip in self.BLACK_IPS:
                black_network = ipaddress.ip_network(black_ip)
                if ip_obj in black_network:
                    return True
            return False
        except ValueError:
            return False

    def verify_ip(self, ip: str) -> bool:
        """
        验证是否是ip地址
        :param ip:ip
        :return:True or False
        """
        if self.verify_ipv4(ip) or self.verify_ipv6(ip):
            return True
        return False

    @staticmethod
    def verify_ipv4(ip: str) -> bool:
        """
        验证是否是ipv4地址
        :param ip:ip
        :return:True or False
        """
        try:
            socket.inet_pton(socket.AF_INET, ip)
        except socket.error:
            return False
        return True

    @staticmethod
    def verify_ipv6(ip: str) -> bool:
        """
        验证是否是ipv6地址
        :param ip:ip
        :return:True or False
        """
        try:
            socket.inet_pton(socket.AF_INET6, ip)
        except socket.error:
            return False
        return True

    @staticmethod
    def is_domain_name(domain: str) -> bool:
        """
        验证是否是合法域名
        :param domain:域名
        :return:True or False
        """
        pattern = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}(:[1-9][0-9]{0,4})?$"
        if re.match(pattern, domain) and (int(domain.split(':')[-1]) <= 65535 if ':' in domain else True):
            return True
        else:
            return False

    @staticmethod
    def generate_ips(ip_range: str) -> list:
        """
        生成ip地址，例如输入ip地址范围为192.168.1.1-192.168.1.254或者192.168.1.1-254
        :param ip_range:ip地址范围192.168.1.1-192.168.1.254或者192.168.1.1-254或者192.168.1.1/24
        :return:list
        """
        if '/' in ip_range:
            ip, cidr = ip_range.split('/')
            cidr = int(cidr)
            host_bits = 32 - cidr
            netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
            log.info(f'子网掩码：{netmask}')
            start_ip = struct.unpack('!L', socket.inet_aton(ip))[0]
            end_ip = start_ip | ((1 << host_bits) - 1)
            ips = [socket.inet_ntoa(struct.pack('!L', ip)) for ip in range(start_ip, end_ip + 1)]
        elif '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            if '.' in end_ip and len([i for i in end_ip.split('.') if i]) > 3:
                start_ip = struct.unpack('!L', socket.inet_aton(start_ip))[0]
                end_ip = struct.unpack('!L', socket.inet_aton(end_ip))[0]
            else:
                end_ip = struct.unpack('!L', socket.inet_aton('.'.join(start_ip.split('.')[:-1] + [end_ip])))[0]
                start_ip = struct.unpack('!L', socket.inet_aton(start_ip))[0]
            ips = [socket.inet_ntoa(struct.pack('!L', ip)) for ip in range(start_ip, end_ip + 1)]
        else:
            ips = []
        return list(set(ips))

    @staticmethod
    def dynamic_query(query_str):
        """
        SQL语句动态转换
        :param query_str:查询语句
        :return:条件语句
        """
        grammar_list = ["host", "ip", "port", "server", "cms", "title", "status_code", "is_cdn", "headers", "url",
                        "redirect_num", "city", "country", "isp", "province", "region", "scan_type", "port_service",
                        "icp", "cert", "icon_hash", "scheme"]
        query_parts = query_str.split('&&' if '&&' in query_str else '||')
        query = Q()
        connector = 'AND' if '&&' in query_str else 'OR'

        for part in query_parts:
            if '!=' in part:
                key, value = part.split('!=')
                key = key.strip().strip('"')
                if key == "ip":
                    key = key.replace("ip", "host")
                value = value.strip().strip('"')
                if value == 'true':
                    value = 1
                if value == 'false':
                    value = 0
                if key in grammar_list:
                    query = (query & ~Q(**{f'{key}__icontains': value})) if connector == 'AND' else (
                            query | ~Q(**{f'{key}__icontains': value}))
                else:
                    raise ValueError("语句错误")
            elif '==' in part:
                key, value = part.split('==')
                key = key.strip().strip('"')
                if key == "ip":
                    key = key.replace("ip", "host")
                value = value.strip().strip('"')
                if value == 'true':
                    value = 1
                if value == 'false':
                    value = 0
                if key in grammar_list:
                    query = (query & Q(**{key: value})) if connector == 'AND' else (query | Q(**{key: value}))
                else:
                    raise ValueError("语句错误")
            else:
                key, value = part.split('=')
                key = key.strip().strip('"')
                if key == "ip":
                    key = key.replace("ip", "host")
                value = value.strip().strip('"')
                if value == 'true':
                    value = 1
                if value == 'false':
                    value = 0
                if key in grammar_list:
                    query = (query & Q(**{f'{key}__icontains': value})) if connector == 'AND' else (
                            query | Q(**{f'{key}__icontains': value}))
                else:
                    raise ValueError("语句错误")

        return query


common_tool = Common_tools()

if __name__ == '__main__':
    ip = "219.219.0.0-219.219.0.254"
    result = common_tool.generate_ips(ip)
    print(result)
