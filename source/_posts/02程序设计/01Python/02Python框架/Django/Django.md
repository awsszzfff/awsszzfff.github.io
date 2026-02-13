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
    
    # 返回JSON格式的数据
    data = {"name": "dream", "age": 18}
	# 对 HttpResponse 的 content_type 进行约束 然后对数据进行序列化
    data_str = json.dumps(data)
    return HttpResponse(data_str, content_type="application/json")
    
    # 直接用json数据
    # from django.http import JsonResponse
    # return JsonResponse(info_data, json_dumps_params={"ensure_ascii":False})


def login(request):
    # 返回 简单的页面对象
    return render(request, "login.html")
    
    # 将数据传给页面
    info_data = {"name": "dream", "age": 18}
	return render(request, "render_response.html", info_data)
	# 前端{{ name }} {{ age }}
	
	# 加载局部名称空间
	return render(request, "render_response.html", locals())
	# 前端{{ info_data }} {{ info_data.name }} {{ info_data.age }}


def register(request):
	# 重定向至指定的地址/解析地址
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

#### 数据提交

```python
# register方法中
username = request.POST.get("username")
password = request.POST.get("password")
avatar = request.POST.get("avatar")
hobby = request.POST.getlist("hobby")
gender = request.POST.get("gender")
...

file_obj = request.FILES.get("avatar")
print(file_obj, type(file_obj))
'''
<MultiValueDict: {'avatar': [<TemporaryUploadedFile: Python.png (image/png)>]}>
Python.png <class 'django.core.files.uploadedfile.TemporaryUploadedFile'>
'''
file_data = file_obj.read()
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
file_path = os.path.join(base_dir, "static", 'avatar')
os.makedirs(file_path, exist_ok=True)
with open(os.path.join(file_path, file_obj.name), "wb") as fp:
    fp.write(file_data)

return redirect(reverse("register"))
```

其他方法

```python
# request.FILES 存放所有提交的文件数据
# request.COOKIES 存放所有本地的用户信息
# request.GET 存放 get 请求提交的数据
# request.POST 存放 post 请求提交的数据
# request.META 存放 本地的环境变量和 请求头中的部分参数
# request.body 存放 请求体的二进制数据
# request.get_full_path 存放 完整的路径带参数
print(request.get_full_path())  # /user/request_methods/?username=
# request.get_full_path_info 存放 完整的路径带参数
print(request.get_full_path_info())  # /user/request_methods/?username=
# request.path 存放 当前访问的路径不带参数
print(request.path)  # /user/request_methods/
# request.path_info 存放 当前访问的路径不带参数
print(request.path_info)  # /user/request_methods/
```


## 静态文件引用

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


## 数据操作 ORM

### 配置数据库连接

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

### 定义模型

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
    name = models.CharField(max_length=32, nulll=True, default="")

    # age 数字类型字段
    age = models.IntegerField()
    
    # 在当前类下面配置一个 类 Meta
    class Meta:
        # 定义当前数据库中的表名
        # 若不配置 则以当前 app名_类名 命名
        db_table = "student"
```

```shell
# 将 Python代码转换为 SQL 语句结构
python manage.py makemigrations

# 将生成的SQL记录迁移进MySQL数据库中
python manage.py migrate

# PyCharm 中的操作
Tools -> run manage.py task ---> makemigrations ---> migrate 
```

### 数据操作

为了测试数据的方便，测试运行设置

```python
if __name__ == '__main__':
	# copy manage.py 中main的第一行
	os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'djangoProjectDemo.settings')
	# 导入Django模块
	import django
	# 执行Django启动命令
	 django.setup()
	# 导入Django模型表，随后执行操作
	from user.models import Student
	...
```

数据操作，以上面 Student 为例

- 增

```python
# 模型表.objects.create
Student.objects.create(name="dream",age=18)
# 模型表(字段名=字段值).save()
Student(name="dream01", age=18).save()
```

- 查

```python
# 模型表.objects.all()
result = Student.objects.all()	# 得到一个数据列表
student_obj_one = result[0]	# 取第一条
student_obj_one.name	# 得到指定字段内容
# 模型表.objects.get(属性名=属性值)	空数据或多个数据会报错
Student.objects.get(id=1)
# 模型表.objects.filter()
Student.objects.filter(id=1)
Student.objects.filter(id=1).first()
Student.objects.filter(id=1).last()
# 模型表.objects.exclude(属性名=属性值) 排除符合条件的数据
Student.objects.exclude(name="dream")
```

- 删

```python

Student.objects.filter(id=1).delete()

# 先过滤出制定的对象 然后再删除指定对象
student_obj = Student.objects.get(id=3)
student_obj.delete()
```

- 改

```python
Student.objects.create(
        name="dream",
        age=18
    )
# 模型表.objects.filter(属性名=属性值).update(新的参数)
Student.objects.filter(id=4).update(
        name="dream_1"
    )
# 对象.属性名=属性值 .save() 保存
student_obj = Student.objects.get(id=4)
student_obj.name = "dream_2"
student_obj.save()
```

## 路由操作

可以在项目目录下定义路由，也可以在对应的 app 下定义路由，有限本项目下的路由。

路由定义需放在 urlpatterns 数组中。

### 路由定义

```python
# urls.py
from django.urls import re_path, path
# 无名分组
re_path("page/(\d+)/",page)	# page/1/

def page(request, page_number):
    # 第二个参数接收的是 (\d+) 捕获的值（字符串类型）
    num = int(page_number)
    return HttpResponse(f"Page: {num}")


# 有名分组
re_path("page_name/(?P<page>\d+)/", page_name)	# page_name/1/

def page_name(request, page):
    # 参数名必须和 (?P<page>...) 中的名字完全一致！
    num = int(page)
    return HttpResponse(f"Page: {num}")
```

### 路由解析

```python
# 定义路由
path("login/adsadasd/dsadsadsad/sdasadads/sadsadsadsa/", login, name="login")

# 前端使用
<p><a href="http://127.0.0.1:8000/login/adsadasd/dsadsadsad/sdasadads/sadsadsadsa/">路径很全的网址</a></p>
<p><a href="{% url 'login' %}">路径很全的网址</a></p>

# 后端使用
if a == "1":
    # 不使用路由解析需要将路径写全
    return redirect("/login/adsadasd/dsadsadsad/sdasadads/sadsadsadsa/")
elif a == "2":
    # 使用路由解析动态加载当前 地址
    return redirect(reverse("login"))	# url别名
	# redirect url重定向
	# reverse url反向解析
```

### 路由分发

```python
# 方案一：在每一个 app 的路由上增加标识 --- > 杂乱无章
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index, name="index"),
    
    # SHOP app 下面的路由映射
    path("shop/order/", order, name="order"),
    path("shop/buy/", buy, name="buy"),

    # USER app 下面的路由映射
    # 有名分组 http://127.0.0.1:8000/parse_name/1/
    re_path("^user/parse_name/(?P<id>\d+)/", parse_name, name="parse_name"),
    # 无名分组
    re_path("^user/parse_no_name/(\d+)/", parse_no_name, name="parse_no_name"),
    re_path("^user/parse_name_redirect/(?P<id>\d+)/", parse_name_redirect, name="parse_name_redirect"),
    re_path("^user/parse_no_name_redirect/(\d+)/", parse_no_name_redirect, name="parse_no_name_redirect"),
]
```

```python
# 方案二：方案一如果路由太多 就会导致杂乱无章，于是进行拆解
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index, name="index"),
]
# 当前路由列表中只放自己app下的路由关系
shop_urlpatterns = [
    # SHOP app 下面的路由映射
    path("shop/order/", order, name="order"),
    path("shop/buy/", buy, name="buy"),
]
# 当前路由列表中只放自己app下的路由关系
user_urlpatterns = [
    # USER app 下面的路由映射
    # 有名分组 http://127.0.0.1:8000/parse_name/1/
    re_path("^user/parse_name/(?P<id>\d+)/", parse_name, name="parse_name"),
    # 无名分组
    re_path("^user/parse_no_name/(\d+)/", parse_no_name, name="parse_no_name"),
    re_path("^user/parse_name_redirect/(?P<id>\d+)/", parse_name_redirect, name="parse_name_redirect"),
    re_path("^user/parse_no_name_redirect/(\d+)/", parse_no_name_redirect, name="parse_no_name_redirect"),
]
urlpatterns += shop_urlpatterns
urlpatterns += user_urlpatterns
```

```python
# 方案三：将每一个app下面的 路由拆解到自己的app下面
from user.urls import user_urlpatterns
from shop.urls import shop_urlpatterns
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index, name="index"),
]

urlpatterns += shop_urlpatterns
urlpatterns += user_urlpatterns
```

```python
# 方案四：Django提供给我们分发语法
from shop.views import order, buy
from user.views import parse_name, parse_no_name, parse_name_redirect, parse_no_name_redirect
# 当前路由列表中只放自己app下的路由关系
shop_urlpatterns = [
    # SHOP app 下面的路由映射
    path("order/", order, name="order"),
    path("buy/", buy, name="buy"),
]
# 当前路由列表中只放自己app下的路由关系
user_urlpatterns = [
    # USER app 下面的路由映射
    # 有名分组 http://127.0.0.1:8000/parse_name/1/
    re_path("^parse_name/(?P<id>\d+)/", parse_name, name="parse_name"),
    # 无名分组
    re_path("^parse_no_name/(\d+)/", parse_no_name, name="parse_no_name"),
    re_path("^parse_name_redirect/(?P<id>\d+)/", parse_name_redirect, name="parse_name_redirect"),
    re_path("^parse_no_name_redirect/(\d+)/", parse_no_name_redirect, name="parse_no_name_redirect"),
]

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index, name="index"),
    # shop app
    path("shop/", include(shop_urlpatterns)),
    # http://localhost:8000/user/parse_name_redirect/5/
    path("user/", include(user_urlpatterns))

]
```

```python
# 方案五：在每一个app下面都有一个 urls.py ---> 每一个人都有 一个 urlpatterns
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index, name="index"),
    # shop app
    path("shop/", include("shop.urls")),
    # http://localhost:8000/user/parse_name_redirect/5/
    path("user/", include("user.urls"))
]
# 前提是 每一个app 下面都有一个 urls.py 文件 并且 其中的列表名字必须叫 urlpatterns 并且必须有 空列表
```

## 设置应用名称空间限制

避免同名路由冲突

```python
# 方式一 在每一个 app 下的 urls.py 文件中声明自己的名称空间
app_name="user" # 限制当前  urls.py 文件中定义的所有路由规则归属于 user app
app_name="admin"
# views.py
reverse("user:login")
# reverse("admin:login")


# 方式二 在路由分发的时候就对名称空间进行约束
from django.urls import include
# urlconf_module, app_name = arg
path("user/", include(arg=("user.urls","user"),namespace="user")),
path("admin/", include(arg=("admin.urls","admin"),namespace="admin")),
reverse("user:login")
reverse("admin:login")
```

## 路径转换器

```python
# 2.x版本后使用path和int,str...来定义
path("page_name/<int:page>/", page_name)	

def page_view(request, page):  # page 已经是 int 类型！
    return HttpResponse(f"Page number: {page}")
```

可以自定义路径转换器

```python
# （1）创建一个自定义的 py 文件 ---> 
# 建议是哪个app的自定义转换器就定义在哪个app下面
# （2）定义一个类
class CheckNum:
    # 定义一个参数 正则表达式规则
    regex = r"^"
    # 定义一个函数
    def to_url(self,value):
        '''
        负责将 url 中的参数进行提取
        :param value: 
        :return: 
        '''
    def ro_python(self,value):
        '''
        负责将 提取到的参数转换为符合 Python的任意数据类型
        :param value: 
        :return: 
        '''
# （3）使用
# 第一步注册
from django.urls import register_converter
# 第二步注册 前面是自定义转换器类 后面是转换器名字
register_converter(CheckNum,"aaa")
# 第三步直接在路由中使用 aaa
```

## CBV&FBV

- FBV(function base view) : 在视图函数中处理请求（上面的基础示例）
- CBV(class base view) : 在视图类中处理请求

```python
# 在一个类中定义视图函数并处理请求
# 在视图文件中定义视图类
# 创建类 -> 继承Django的视图类
from django.views import View

class LoginView(View):
	# get 请求
    def get(self, request):
        return render(request, "login.html", locals())

    # post 请求
    def post(self, request):
        username = request.POST.get("username")
        password = request.POST.get("password")
        hobby = request.POST.getlist("hobby")
        gender = request.POST.get("gender")
        avatar_obj = request.FILES.get("avatar")
        print(f"""
        username :>>>> {username}
        password :>>>> {password}
        avatar :>>>> {avatar_obj, type(avatar_obj)}
        hobby :>>>> {hobby}
        gender :>>>> {gender}
        """)
        return redirect(reverse("login"))
        
# 在路由系统中注册当前视图类
path("login/", views.LoginView.as_view(), name="login"),
```


