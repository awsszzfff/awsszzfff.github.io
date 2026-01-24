---
title: "Django"
date: 2026-01-18
updated: 2026-01-18
tags:
  - Others
categories:
  - Others
description: None
---
## 创建与基础构建

```shell
# 项目创建
django-admin startproject 项目名

# 项目启动
python manage.py runserver [IP:PORT]	# 默认 127.0.0.1:8000
# 在拥有manage.py 的文件夹中
# pycharm配置Django支持，settings.py文件

# 给对应项目创建应用
python manage.py startapp APP名字	# eg：user
# settings.py 文件中配置
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "user"	# 直接写 app 名字 或写具体的路径
]

# pycharm Tools Run manage.py Task...
startapp app名字
```

### 静态文件引用

```python
# 配置参数

# 静态文件目录
STATICFILES_DIRS = [
    # 根目录下的文件目录
    "static",
]
```

```python
# 使用

{# 第一句 ： 加载静态文件语法系统 #}
{% load static %}
<script src="../../static/plugins/jQuery/jquery.min.js"></script>	# 传统引用方式
<script src="{% static 'plugins/bootstrap/bootstrap.min.js' %}"></script>	# 静态文件语法引用方式
```


### 数据库操作 ORM

#### 配置数据库连接

```python
# setting.py

# Django 使用的默认的数据库 sqlite3
DATABASES = {
    'default': {
        # 数据库引擎配置 django.db.backends.sqlite3
        'ENGINE': 'django.db.backends.sqlite3',
        # BASE_DIR / 'db.sqlite3' ： 数据库文件
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# 使用MySQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', # 数据库引擎
        'NAME': 'your_db_name',               # 数据库名
        'USER': 'your_user',                  # 用户名
        'PASSWORD': 'your_password',          # 密码
        'HOST': '127.0.0.1',                  # 数据库地址
        'PORT': '3306',                       # 端口号
    }
}

# 启动若报错
# （其中一种修复方式）在__init__.py中添加
import pymysql
pymysql.install_as_MySQLdb()
```

#### 定义模型

在 Django 中，一个类就代表数据库中的一张表。

> ORM 一种将对象与关系型数据库之间的映射的技术，主要实现了以下三个方面的功能：
> 
> - 数据库中的表映射为 Python 中的类
> - 数据库中的字段映射为 Python 中的属性
> - 数据库中的记录映射为 Python 中的实例

```python
from django.db import models

# 定义一个类 必须继承 models.Model
class Student(models.Model):
    # 在Django里面会默认配一个字段作为主键
    # DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

    # name 字符串类型，指定默认长度
    name = models.CharField(max_length=32)

    # age 数字类型字段
    age = models.IntegerField()
```

```shell
# 将 Python代码转换为 SQL 语句结构
python manage.py makemigrations

# 将生成的SQL记录迁移进MySQL数据库中
python manage.py migrate

# PyCharm 中的操作
Tools -> run manage.py task ---> makemigrations ---> migrate 
```

### 项目结构示例

```shell
# 项目目录结构示例
DjangoProject54 # 主项目名 必须
├── DjangoProject54 # 存放Django项目的基本配置的文件夹 和你的项目名是同名的 必须
│   ├── __init__.py # 初始化项目需要加载的代码 后面会写
│   ├── __pycache__ # Python解释器给Django项目的缓存文件  --- 在项目中看不到 不用管
│   │   ├── __init__.cpython-310.pyc # Python解释器缓存文件
│   │   └── settings.cpython-310.pyc # settings 更改后的缓存
│   ├── asgi.py # 上线到服务器之后都需要配置的启动文件 本地的项目不写 不动
│   ├── settings.py # Django的项目配置文件
│   ├── urls.py # 跟路由映射文件
│   └── wsgi.py # 基于 wsgiref 模块分装后的 wsgi 模块 去帮助你 创建 app 不动
├── manage.py # 加载Django项目的所有配置 并帮助我们启动Django项目
├── templates
└── user # 自己创建的 APP 的名字
    ├── __init__.py # 没有东西 后面会写 
    ├── admin.py # 我们在进入后台管系统之后注册内容 现在不写 后面 写
    ├── apps.py # 当前APP 的默认配置 不要瞎改  不要动
    ├── migrations # 数据库迁移记录文件夹 MySQL 将 Python代码定义的数据库结构转换成SQL 语句
    │   └── __init__.py # 没东西但是不允许删除 必须有
    ├── models.py # 存储我们自己定义的数据库模型 自己通过 Python代码定义的数据库字段
    ├── tests.py # Django的测试文件 不用管
    └── views.py # 自己写的业务逻辑在的地方
```

### 基础示例

```python
from django.shortcuts import render, HttpResponse, redirect

# Create your views here.
# 定义视图函数并且有一个 request 参数必写
def index(request):
    # 返回纯文本内容
    return HttpResponse("OK")


def login(request):
    # 返回 页面 对象
    return render(request, "login.html")


def register(request):
    print("欢迎来到注册函数")
    # 重定向路由
    # http://127.0.0.1:8000/register/
    # 自动帮你转接到 http://127.0.0.1:8000/login/
    return redirect("/login/")
    '''
    [27/Sep/2024 04:22:31] "GET /register/ HTTP/1.1" 302 0
    [27/Sep/2024 04:22:31] "GET /login/ HTTP/1.1" 200 145
    '''
```

