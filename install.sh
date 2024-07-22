#!/bin/bash
# author: zhizhuo

# 检查脚本是否以 root 用户身份运行
if [ "$EUID" -ne 0 ]; then
  echo "请以 root 用户身份运行"
  exit 1
fi

echo "检查更新依赖包..."
sudo apt-get update

echo "开始检查 Python 版本..."
PYTHON_VERSION=$(python3 --version 2>&1)
PYTHON_VERSION_REGEX="Python ([0-9]+)\.([0-9]+)\.([0-9]+)"

if [[ $PYTHON_VERSION =~ $PYTHON_VERSION_REGEX ]]; then
    PYTHON_MAJOR_VERSION=${BASH_REMATCH[1]}
    PYTHON_MINOR_VERSION=${BASH_REMATCH[2]}

    if [ "$PYTHON_MAJOR_VERSION" -gt 3 ] || { [ "$PYTHON_MAJOR_VERSION" -eq 3 ] && [ "$PYTHON_MINOR_VERSION" -ge 8 ]; }; then
        echo "Python 版本高于 3.8"
    else
        echo "Python 版本不高于 3.8，请升级到 3.8 或更高版本。"
        exit 1
    fi
else
    echo "无法解析 Python 版本。"
    exit 1
fi

echo "开始检查 Docker 环境..."

# 如果未安装 Docker，则安装 Docker
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker 未安装，尝试安装 Docker..."
    apt-get install -y docker.io 
else
    echo "Docker 已安装。"
fi

echo "开始检查工具环境..."

# 检查snap命令是否存在
if command -v snap &> /dev/null; then
    echo "Snap已安装。显示Snap版本信息："
    snap --version
else
    echo "Snap未安装。"
    sudo apt install snapd
    sudo systemctl start snapd
    sudo systemctl enable snapd
    echo "Snap安装完成。显示Snap版本信息："
    snap --version
fi

# 如果未安装 Docker Compose，则安装 Docker Compose
if ! command -v docker-compose >/dev/null 2>&1; then
    echo "Docker Compose 未安装，尝试安装 Docker Compose..."
    apt-get install -y python3-pip
    apt-get install -y docker-compose
else
    echo "Docker Compose 已安装。"
fi

# 检查是否安装了nmap
if ! command -v nmap &> /dev/null; then
    echo "未找到nmap，正在尝试安装..."
    sudo apt-get install nmap -y
else
    echo "nmap已经安装。"
fi

# 检查是否安装了rustscan
if ! command -v rustscan &> /dev/null; then
    echo "未找到rustscan，正在安装..."
    dpkg -i iotscan/install/rustscan_2.1.1_amd64.deb 
    sleep 2
    echo "rustscan安装完成。显示rustscan版本信息："
    rustscan --version
else
    echo "rustscan已经安装。显示rustscan版本信息："
    rustscan --version
fi

# 拉取 MySQL、Nginx 和 Redis 的 Docker 镜像
echo "拉取必需的 Docker 镜像..."
docker pull mysql:8.0.34 && echo "MySQL 镜像拉取成功。" ||
{ echo "拉取 MySQL 镜像失败。"; exit 1; }
docker pull nginx && echo "Nginx 镜像拉取成功。" ||
{ echo "拉取 Nginx 镜像失败。"; exit 1; }
docker pull redis && echo "Redis 镜像拉取成功。" ||
{ echo "拉取 Redis 镜像失败。"; exit 1; }

# 检查并准备 Nginx 文件
NGINX_DIR="/home/nginx"
if [ ! -d "$NGINX_DIR" ]; then
    if [ -d "./nginx" ]; then
        cp -r ./nginx "$NGINX_DIR"
        echo "Nginx 文件已复制到 $NGINX_DIR。"
    else
        echo "错误：当前目录中不存在 Nginx 文件。"
        exit 1
    fi
else
    echo "正在清理现有的 Nginx 目录..."
    rm -rf "$NGINX_DIR"
    if [ -d "./nginx" ]; then
        cp -r ./nginx "$NGINX_DIR"
        echo "Nginx 文件已复制到 $NGINX_DIR。"
    else
        echo "错误：当前目录中不存在 Nginx 文件。"
        exit 1
    fi
fi

# 函数：检查端口是否开放
check_port() {
  nc -z localhost "$1" &> /dev/null
  return $?
}

# 函数：启动 Docker 容器并检查端口
start_container() {
  local name=$1
  local image=$2
  local port=$3
  local run_command=$4  

  echo "即将启动的容器: $name"
  echo "使用的镜像: $image"
  echo "使用的端口: $port"

  echo "启动 $name..."
  if $run_command; then
    echo "$name 容器已启动。"
    sleep 5
    if check_port "$port"; then
      echo "$name 已在端口 $port 上运行。"
    else
      echo "启动 $name 失败或端口 $port 未开放。"
      exit 1
    fi
  else
    echo "启动 $name 容器失败。"
    exit 1
  fi
}

# 启动 Docker 容器
start_container "Nginx" "nginx:latest" 80 "docker run -p 80:80 --restart=always --name nginx -v $NGINX_DIR/conf/nginx.conf:/etc/nginx/nginx.conf -v $NGINX_DIR/conf/conf.d:/etc/nginx/conf.d -v $NGINX_DIR/log:/var/log/nginx -v $NGINX_DIR/html:/usr/share/nginx/html -d nginx:latest"
sleep 5
start_container "MySQL" "mysql:8.0.34" 3306 "docker run -p 3306:3306 -v /usr/local/mysql/conf:/etc/mysql/conf.d -v /usr/local/mysql/data:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=123456 --restart=always --name mysql -d mysql:8.0.34"
sleep 5

echo "正在启动Redis"
docker run -p 6379:6379 -v /docker/redis/data:/data --restart=always --name redis -d redis:latest --requirepass 'zhizhuo'
sleep 5
if check_port "6379"; then
    echo "Redis 已在端口 6379 上运行。"
else
    echo "启动 Redis 失败或端口 6379 未开放。"
    exit 1
fi

# 防止mysql数据库在创建数据库的时候出错，这里需要重启一下mysql
echo "正在进行环境检测"
docker restart mysql
sleep 10
echo "检测完成"

# 创建 iotscan 数据库
echo "创建 iotscan 数据库..."
docker exec mysql mysql -u root -p123456 -e "CREATE DATABASE IF NOT EXISTS iotscan CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

echo "数据库创建完成。"

# 安装 Python 依赖
echo "安装 Python 依赖..."
cd iotscan || exit
pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple 
echo "Python 依赖安装完成。"

# 初始化数据库
echo "初始化数据库..."
python3 manage.py makemigrations && python3 manage.py migrate
sleep 1

# 创建超级用户
echo "创建 Django 超级用户..."
echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('zhizhuo', 'zhizhuoshuma@163.com', 'zhizhuo@2023')" | python3 manage.py shell
# 杀掉旧的 Celery 进程
echo "停止旧的 Celery 进程..."
pkill -f 'celery -A iotscan worker'
sleep 2
pkill -f 'celery --broker='
sleep 2

# 启动 Celery worker
echo "启动 Celery worker..."
celery -A iotscan worker -l debug -n iotscan@main -c 2 > /dev/null 2>&1 &
celery -A iotscan worker -l debug -n iotscan-portscan@%n -Q portscan -c 4 > /dev/null 2>&1 &
celery -A iotscan worker -l debug -n iotscan-pocscan@%n -Q pocscan -c 10 > /dev/null 2>&1 &
celery -A iotscan worker -l debug -n iotscan-fingerscan@%n -Q fingerscan -c 5 > /dev/null 2>&1 &
celery -A iotscan worker -l debug -n iotscan-datascan@%n -Q datascan -c 10 > /dev/null 2>&1 &
celery -A iotscan worker -l debug -n iotscan-domainscan@%n -Q domainscan -c 10 > /dev/null 2>&1 &

# 启动 Celery Flower 监控工具
echo "启动 Celery Flower..."
celery --broker=redis://default:zhizhuo@127.0.0.1:6379/5 flower --port=2323 --address=0.0.0.0 > /dev/null 2>&1 &
sleep 1

# 杀掉旧的 Django 服务器进程
pkill -f 'python3 manage.py runserver'
sleep 2

# 启动 Django 服务器
echo "启动 Django 服务器..."
nohup python3 manage.py runserver 0.0.0.0:8000 > /dev/null 2>&1 &

# 返回到脚本开始的目录
cd ..
sleep 2
echo "所有服务已成功启动。"

exit 0
