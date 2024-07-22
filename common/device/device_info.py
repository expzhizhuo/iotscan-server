"""
@Project ：iotscan 
@File    ：device_info.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/8/21 02:29 
"""
import socket
import time

import psutil
import requests


def get_cpu_usage():
    return psutil.cpu_percent()


def get_memory_size():
    return round(psutil.virtual_memory().total / (1024.0 ** 3), 2)


def get_memory_free_size():
    return round(get_memory_size() - get_memory_usage(), 2)


def get_memory_usage():
    return round(get_memory_size() * psutil.virtual_memory().percent / 100, 2)


def get_disk_size():
    return round(psutil.disk_usage('/').total / (1024.0 ** 3), 2)


def get_disk_usage():
    return round(get_disk_size() * psutil.disk_usage('/').percent / 100, 2)


def get_disk_free_size():
    return round(get_disk_size() - get_disk_usage(), 2)


def get_network_info():
    interfaces = psutil.net_if_addrs()
    network_info = []
    for interface_name, interface_addresses in interfaces.items():
        ip_info = {'name': interface_name, 'ipv4': None, 'ipv6': []}
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                ip_info['ipv4'] = address.address
            elif address.family == socket.AF_INET6 and "%" not in address.address:
                ip_info['ipv6'].append(address.address)
            elif address.family == psutil.AF_LINK:
                ip_info['mac'] = address.address
        network_info.append(ip_info)
    return network_info


def get_network_speed():
    result = list()
    net_io_counters = psutil.net_io_counters(pernic=True)
    for nic, addrs in psutil.net_if_addrs().items():
        if nic in net_io_counters:
            for addres in addrs:
                if str(addres.family) == 'AddressFamily.AF_INET':
                    io_counters = net_io_counters[nic]
                    send = round(io_counters.bytes_sent / (1024.0 ** 3), 3)
                    received = round(io_counters.bytes_recv / (1024.0 ** 3), 3)
                    # print(f"NIC: {nic}")
                    # print(f"    Sent: {send} MB/s")
                    # print(f"    Received: {received} MB/s")
                    result.append(dict(nic=nic, send=send, received=received))
    return result


def get_network_speed_new():
    net_io_counters = psutil.net_io_counters()
    return net_io_counters.bytes_sent, net_io_counters.bytes_recv


def get_network_count():
    return len(get_network_info())


def get_process_count():
    return len(psutil.pids())


class DeviceTools:
    def __init__(self):
        """
        初始化操作
        """

    @staticmethod
    def get_device_info():
        """
        获取设备信息
        :return:dict
        """
        return dict(cpu_usage=get_cpu_usage(),
                    memory_size=get_memory_size(),
                    memory_free_size=get_memory_free_size(),
                    memory_usage=get_memory_usage(),
                    disk_size=get_disk_size(),
                    disk_free_size=get_disk_free_size(),
                    disk_usage=get_disk_usage(),
                    network_count=get_network_count(),
                    process_count=get_process_count())

    @staticmethod
    def get_network_info():
        """
        获取网卡信息
        :return:
        """
        return get_network_info()

    @staticmethod
    def get_network_speed():
        """
        获取网卡速率
        :return:list
        """
        return get_network_speed()

    @staticmethod
    def get_network_speed_now():
        """
        获取网卡当前速率
        :return:
        """
        sent_start, recv_start = get_network_speed_new()
        time.sleep(1)
        sent_end, recv_end = get_network_speed_new()
        sent_speed = round((sent_end - sent_start) / 1024, 2)
        recv_speed = round((recv_end - recv_start) / 1024, 2)
        # print(f"Sent: {sent_speed:.2f} KB/s, Received: {recv_speed:.2f} KB/s")
        return dict(send=sent_speed, received=recv_speed)


device_tools = DeviceTools()

# print(f"CPU usage: {get_cpu_usage()}%")
# print(f"Memory Size：{get_memory_size()}G")
# print(f"Memory Free Size：{get_memory_free_size()}G")
# print(f"Memory usage: {get_memory_usage()}%")
# print(f"Disk Size：{get_disk_size()}G")
# print(f"Disk Free Size：{get_disk_free_size()}G")
# print(f"Disk usage: {get_disk_usage()}%")
# print(f"Number of network interfaces: {get_network_count()}")
# print(f"IP addresses: {', '.join(get_network_info()[0])}")
# print(f"MAC addresses: {', '.join(get_network_info()[1])}")
# print(f"Number of processes: {get_process_count()}")
# get_network_speed()
