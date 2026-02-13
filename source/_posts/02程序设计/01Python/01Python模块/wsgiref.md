---
title: wsgiref
date: 2026-01-06
updated: 2026-01-06
tags:
  - Python模块
categories:
  - 程序设计
  - Python
description: None
---

## 原生 Socket Web 服务器

```python
import socket

# --- 1. 业务逻辑层 (与之前类似，但返回的是字符串) ---
def index():
    return "<h1>首页</h1><p>这是从原始 Socket 服务器返回的。</p>"

def hello():
    return "<h1>你好</h1><p>手动解析协议成功！</p>"

def not_found():
    return "<h1>404</h1><p>找不到页面</p>"

# --- 2. 路由映射 ---
URL_PATTERNS = {
    '/': index,
    '/hello': hello,
}

# --- 3. 手动处理服务器逻辑 ---
def run_server():
    # 1. 创建 TCP Socket (IPv4, TCP)
    # 这相当于准备好一个“电话机”
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 允许立即重用地址（防止服务器重启时报端口占用错误）
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # 2. 绑定 IP 和端口
    server_socket.bind(('127.0.0.1', 8000))
    
    # 3. 开始监听 (最大等待连接数为 5)
    server_socket.listen(5)
    print("服务器已启动：http://127.0.0.1:8000")

    while True:
        # 4. 等待客户端连接 (阻塞状态)
        client_connection, client_address = server_socket.accept()
        
        # 5. 接收客户端发来的原始数据 (HTTP 请求报文)
        # 这里的 request_data 是原始字节流
        request_data = client_connection.recv(1024).decode('utf-8')
        
        if not request_data:
            client_connection.close()
            continue

        # --- 手动解析 HTTP 请求报文 ---
        # 典型的请求首行： "GET /hello HTTP/1.1"
        try:
            first_line = request_data.split('\n')[0]
            method = first_line.split(' ')[0]
            path = first_line.split(' ')[1]
        except IndexError:
            path = '/'

        print(f"收到请求: {method} {path}")

        # --- 路由分发 ---
        view_func = URL_PATTERNS.get(path, not_found)
        content = view_func()

        # --- 手动构建 HTTP 响应报文 ---
        # HTTP 响应必须严格遵守格式：
        # 状态行 + 响应头 + 空行(\r\n) + 响应正文
        response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: text/html; charset=utf-8\r\n"
        response += f"Content-Length: {len(content.encode('utf-8'))}\r\n"
        response += "Server: MyRawSocketServer/1.0\r\n"
        response += "\r\n"  # 这是必须的空行，区分头部和正文
        response += content

        # 6. 将响应发送回客户端
        client_connection.sendall(response.encode('utf-8'))
        
        # 7. 关闭当前连接 (短连接模式)
        client_connection.close()

if __name__ == '__main__':
    run_server()
```

## wsgiref 模拟 Web 框架示例

```python
from wsgiref.simple_server import make_server

# --- 1. 业务逻辑层 (View Functions) ---
def index(environ):
    return "<h1>欢迎来到首页！</h1><p>这是一个基于 wsgiref 的迷你框架。</p>"

def hello(environ):
    # 从环境变量中获取 URL 参数或信息
    query_string = environ.get('QUERY_STRING', '无参数')
    return f"<h1>你好！</h1><p>你的查询参数是: {query_string}</p>"

def not_found(environ):
    return "<h1>404 Not Found</h1><p>你要找的内容被外星人抓走了。</p>"

# --- 2. 路由映射表 ---
URL_PATTERNS = {
    '/': index,
    '/hello': hello,
}

# --- 3. 框架核心：WSGI Application ---
def my_awesome_framework(environ, start_response):
    """
    这是框架的核心入口。
    environ: 包含了所有的请求信息 (类似安全分析中的 Request 报文)
    start_response: 用于设置状态码和响应头
    """
    
    # 获取用户请求的路径
    path = environ.get('PATH_INFO', '/')
    
    # 路由分发
    handler = URL_PATTERNS.get(path, not_found)
    
    # 执行业务逻辑获取响应体
    response_body = handler(environ)
    
    # 状态码和响应头
    status = '200 OK' if handler != not_found else '404 NOT FOUND'
    response_headers = [
        ('Content-Type', 'text/html; charset=utf-8'),
        ('Content-Length', str(len(response_body.encode('utf-8')))),
        ('X-Content-Type-Options', 'nosniff') # 安全响应头示例
    ]
    
    # 调用回调函数发送 Header
    start_response(status, response_headers)
    
    # 返回响应体（必须是字节流列表）
    return [response_body.encode('utf-8')]

# --- 4. 启动服务器 ---
if __name__ == '__main__':
    port = 8000
    httpd = make_server('127.0.0.1', port, my_awesome_framework)
    print(f"服务已启动，请访问 http://127.0.0.1:{port}")
    
    # 开始循环监听请求
    httpd.serve_forever()
```

## 前后端分离 jinja2 wsgiref

```plaintext
my_web_app/
├── templates/          # 存放 HTML 模板
│   ├── login.html
│   └── home.html
└── main.py             # 核心逻辑代码
```

`templates/login.html`

```html
<!DOCTYPE html>
<html>
<head><title>登录页面</title></head>
<body>
    <h2>系统登录</h2>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    <form method="POST" action="/login">
        用户名: <input type="text" name="username"><br>
        密  码: <input type="password" name="password"><br>
        <button type="submit">提交</button>
    </form>
</body>
</html>
```

`templates/home.html`

```html
<!DOCTYPE html>
<html>
<head><title>首页</title></head>
<body>
    <h1>欢迎回来, {{ user }}!</h1>
    <p>这是你的秘密科研基地。</p>
    <a href="/login">退出登录</a>
</body>
</html>
```

`main.py`

```python
import urllib.parse
from wsgiref.simple_server import make_server
from jinja2 import Environment, FileSystemLoader

# --- 1. 初始化 Jinja2 环境 ---
# 告诉 Jinja2 去哪找 HTML 文件
env = Environment(loader=FileSystemLoader('templates'))

# --- 2. 逻辑层 (Views) ---

def render_template(template_name, **context):
    """辅助函数：渲染模板并返回字节流"""
    template = env.get_template(template_name)
    content = template.render(**context)
    return content.encode('utf-8')

def login_view(environ):
    """处理登录逻辑"""
    method = environ['REQUEST_METHOD']
    
    # 如果是 GET 请求，直接显示登录框
    if method == 'GET':
        return render_template('login.html')
    
    # 如果是 POST 请求，说明用户提交了表单
    if method == 'POST':
        # 从 WSGI 的输入流中读取提交的数据
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            request_body_size = 0
            
        request_body = environ['wsgi.input'].read(request_body_size).decode('utf-8')
        # 解析数据 (例如: username=admin&password=123)
        params = urllib.parse.parse_qs(request_body)
        
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]

        # 简单的身份验证模拟
        if username == 'admin' and password == 'secure123':
            # 登录成功，跳转首页
            return home_view(environ, username)
        else:
            # 登录失败，带错误信息返回登录页
            return render_template('login.html', error="用户名或密码错误！")

def home_view(environ, username):
    """处理首页逻辑"""
    return render_template('home.html', user=username)

# --- 3. 核心路由层 (App) ---

def app(environ, start_response):
    path = environ.get('PATH_INFO', '/')
    
    # 路由分发
    if path == '/' or path == '/login':
        response_body = login_view(environ)
        status = '200 OK'
    else:
        status = '404 NOT FOUND'
        response_body = b"<h1>404 Page Not Found</h1>"

    # 设置响应头
    headers = [
        ('Content-Type', 'text/html; charset=utf-8'),
        ('Content-Length', str(len(response_body)))
    ]
    start_response(status, headers)
    return [response_body]

# --- 4. 启动服务器 ---
if __name__ == '__main__':
    port = 8080
    with make_server('', port, app) as httpd:
        print(f"Server running on http://127.0.0.1:{port}")
        httpd.serve_forever()
```