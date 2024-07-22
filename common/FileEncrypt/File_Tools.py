"""
@Project ：iotscan 
@File    ：File_Tools.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2023/8/20 07:05 
"""
import base64
import os

from Cryptodome.Cipher import AES


class FileTools:

    def __init__(self):
        self._key = "5c44c819appsapi0"
        self._iv = "1234567890123456"

    # 加密函数
    def encrypt_file(self, in_filename):
        """
        文件加密函数
        :param in_filename:输入文件内容，base64加密
        :return:加密后的文件内容
        """
        if in_filename:
            print(self._key)
            print(in_filename)
            payload_data = in_filename + (16 - len(in_filename) % 16) * chr(16 - len(in_filename) % 16).encode()
            encryptor = AES.new(self._key.encode('utf8'), AES.MODE_CBC, self._iv.encode('utf-8'))
            outfile = encryptor.encrypt(payload_data)
        else:
            outfile = None
        return outfile

    # 解密函数
    def decrypt_file(self, in_filename):
        """
        文件的解密函数
        :param in_filename:输入文件内容，base64加密
        :return:解密后的文件内容
        """

        if in_filename:
            decryptor = AES.new(self._key.encode('utf8'), AES.MODE_CBC, self._iv.encode('utf-8'))
            outfile = decryptor.decrypt(in_filename)
            outfile = outfile.rstrip(b"\0")
            outfile = outfile[:-outfile[-1]]
        else:
            outfile = None
        return outfile

    def base64_to_binary(self, data):
        """
        将base64编码的数据转换成二进制数据流
        """
        return base64.b64decode(data)

    def base64_to_encode(self, data):
        """
        将二进制数据流装还成base64
        :param data:
        :return:
        """
        return base64.b64encode(data)


filetools = FileTools()
