## 项目简介

本项目为资产测绘平台iotscan的后端server，主要实现功能比较简单，如果你要进行二次开发可以进行参考。

## 环境

本项目中后端所使用的技术栈为django rest formwork、redis、mysql、celey。

## 项目配置

所有的配置文件都在config/config.py中

修改mysql数据库链接配置

```bash
MYSQL_HOST = "localhost"
MYSQL_PORT = 3306
MYSQL_USER = "root"
MYSQL_PASSWORD = ""
```

修改redis链接配置

```bash
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_USER = "default"
REDIS_PASSWORD = "zhizhuo"
```

## 项目部署

***提示**
端口扫描采用的是rustscan，rustscan是基于nmap二次封装，需要提前安装nmap在安装rustscan，端口扫描中有udp扫描，udp扫描需要root权限，所以整个项目需要运行在root权限下。

安装依赖

```shell
pip3 -r install requirements.txt
```

初始化数据库

```shell
python3 manage.py makemigrations

python3 manage.py migrate
```

创建超级用户

```shell
python3 manage.py createsuperuser
```

忘记密码

```shell
python3 manage.py changepassword 用户名
```

项目启动

POC扫描模块要使用单线程来进行处理，原因则是保证数据是唯一可靠的，return出来的数据是一致

django 启动

```shell
python3 manage.py runserver 8000
```

安装rustscan

```shell
wget https://github.com/RustScan/RustScan/releases
dpkg -i 文件名
# 安装提示
ubuntu系统只能安装22.04版本
# 使用命令查看lib6版本
ldd --versio
版本需要 >= 2.34

# mac安装命令
brew install rustscan
```

## Docker环境安装

安装mysql 8.0.23

```shell
docker pull mysql:8.0.34
```

启动

```shell
sudo docker run -d -p 3306:3306 -v /usr/local/mysql/conf:/etc/mysql/conf.d -v /usr/local/mysql/data:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=123456 --restart=always --name  mysql mysql:8.0.34
```

安装redis

```shell
 docker pull redis
```

启动

```shell
sudo docker run -d -p 6379:6379 -v /docker/redis/data:/data --restart=always --name  redis redis:latest --requirepass "zhizhuo"
```

## celery启动

启动主server

```shell
celery  -A iotscan worker  -l debug -n iotscan@main -c 1
```

启动poc扫描server

```shell
celery  -A iotscan worker  -l debug -n iotscan-pocscan@%n -Q pocscan -c 10
```

启动端口扫描server

```shell
celery  -A iotscan worker  -l debug -n iotscan-portscan@%n -Q portscan -c 2
```

启动指纹扫描server

```shell
celery  -A iotscan worker  -l debug -n iotscan-fingerscan@%n -Q fingerscan -c 10
```

启动敏感信息扫描server

```shell
celery  -A iotscan worker  -l debug -n iotscan-datascan@%n -Q datascan -c 10
```

启动子域名扫描server

```shell
celery  -A iotscan worker  -l debug -n iotscan-domainscan@%n -Q domainscan -c 10
```

celery flower 监控GUI启动
本地开发环境

```shell
celery --broker=redis://default:zhizhuo@127.0.0.1:6379/5 flower --port=2323 --address=0.0.0.0
```

## 一键式部署

``` bash
chmod u+x install.sh
sudo ./install.sh
```

## 项目说明

本项目的前端地址为

``` 
https://github.com/expzhizhuo/iotscan-web
```

本项目只进行部分代码开源，整体的架构设计和业务逻辑仅供参考，其实还是有很多小bug的，如果你恰好也想玩资产测绘可以对本项目进行参考。由于本项目为我第一个完整的从0到1的django项目，代码写的有些潦草，如有不懂的地方可以在主页上的联系方式联系到我，开发小白，非安全行业人员忽扰！

