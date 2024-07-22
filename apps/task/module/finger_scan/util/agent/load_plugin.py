"""
@Project ：指纹识别 
@File    ：load_plugin.py
@IDE     ：PyCharm 
@Author  ：zhizhuo
@Date    ：2024/4/3 15:31 
"""
import importlib.util
import os


class LoadPlugin(object):
    def __init__(self, plugin_id: str, plugin_path: str):
        """
        初始化配置
        @param plugin_id:插件id
        @param plugin_path:插件目录
        """
        self.plugin_path = plugin_path
        self.plugin_id = plugin_id

    def get_plugin_filename(self, plugin_path: str = None) -> list:
        """
        加载指定目录下的所有文件
        """
        file = []
        if not plugin_path:
            plugin_path = self.plugin_path
        file_list = os.listdir(path=plugin_path)
        for f in file_list:
            full_path = os.path.join(self.plugin_path, f)
            if os.path.isfile(full_path) and "init" not in f and f.endswith(".py"):
                file.append(f)
        return file

    @staticmethod
    def load_module(plugin_name: str, plugin_file: str) -> object:
        """
        加载指定的插件的指定类
        @param plugin_name:类名字
        @param plugin_file:插件地址
        """
        if not plugin_name or not plugin_file:
            return None
        module_spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        return module

    @staticmethod
    def instantiate_classes(module: object) -> any:
        """
        注册类
        @param module:插件内存数据
        """
        return getattr(module, 'TcpFinger')()

    def run(self):
        """
        主入口函数
        """
        if not self.plugin_id:
            return None
        file_path = None
        file_list = self.get_plugin_filename()
        for file in file_list:
            if self.plugin_id in file:
                file_path = self.plugin_path + "/" + file
        module = self.load_module(plugin_name=self.plugin_id, plugin_file=file_path)
        try:
            return self.instantiate_classes(module=module)
        except Exception as e:
            print(f"[-] 加载插件{self.plugin_id}失败")
            return None


class GetPluginInfo:
    """
    获取所有的插件名字
    """

    def __init__(self, plugin_path: str):
        """
        初始化配置文件
        :param plugin_path:插件位置
        """
        self.plugin_path = plugin_path

    def _get_plugin_filename(self):
        """
        获取插件目录下面的所有插件文件名字
        :return:
        """
        file = []
        if not self.plugin_path:
            return file
        file_list = os.listdir(path=self.plugin_path)
        for f in file_list:
            full_path = os.path.join(path, f)
            if os.path.isfile(full_path) and "init" not in f and f.endswith(".py"):
                file.append(f)
        return file

    def run(self):
        """
        主入口函数
        :return:
        """
        return self._get_plugin_filename()


if __name__ == '__main__':
    # plugin = LoadPlugin(plugin_id="test").run()
    # plugin_info = plugin.plugin_name
    # print(plugin.plugin_is_active)
    # print(plugin_info)
    # print(plugin.run())
    path = os.path.dirname(__file__) + "/../plugin"
    get_filename = GetPluginInfo(plugin_path=path).run()
    print(get_filename)
