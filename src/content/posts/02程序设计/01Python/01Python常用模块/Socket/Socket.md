---
title: "Socket"
date: 2025-08-07
tags:
  - Others
categories:
  - Others
description: None
---
```python
import socket
```

```python

```

## 简单的通信示例 

### 使用 TCP 连接：

```python file:client.py
import socket  
  
# 创建一个TCP/IP套接字对象  
# AF_INET表示使用IPv4地址族  
# SOCK_STREAM表示使用TCP协议类型  
client = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)  
  
# 定义要连接的服务器IP地址和端口号  
ip = '127.0.0.1'  # 服务器IP地址（本地回环地址）  
port = 8001  # 服务器端口号  
  
# 连接到服务器  
# connect()方法需要传入一个包含IP和端口的元组  
client.connect((ip, port))  
  
# 接收服务器发送的数据，参数1024表示最大接收字节数  
# recv()方法会阻塞程序，直到接收到数据  
from_server_to_client_recv_data = client.recv(1024)  # 等待conn.send  
  
# 将接收到的字节数据解码为字符串并打印  
print(from_server_to_client_recv_data.decode())  
  
# 向服务器发送数据，需要先将字符串编码为字节  
from_client_to_server_send_data = "我是来自客户端的一条数据"  
client.send(from_client_to_server_send_data.encode())  
  
# 关闭客户端套接字连接  
client.close()
```

```python file:server.py
import socket  
  
# 创建一个TCP/IP套接字对象  
# AF_INET表示使用IPv4地址族  
# SOCK_STREAM表示使用TCP协议类型  
server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)  
  
# 定义服务器IP地址和端口号  
ip = '127.0.0.1'  # 本地回环地址  
port = 8001  # 端口号  
  
# 将套接字绑定到指定的IP地址和端口  
# bind()方法需要传入一个包含IP和端口的元组  
server.bind((ip, port))  
  
# 开始监听客户端连接请求，参数5表示最大等待连接数  
server.listen(5)  
  
# 接受客户端连接请求，返回一个新的连接对象和客户端地址  
# accept()方法会阻塞程序，直到有客户端连接进来  
conn, addr = server.accept()  # 等待client.connect  
print(f"客户端已连接: {addr}")  
  
# 向客户端发送数据，需要先将字符串编码为字节  
from_server_to_client_send_data = "我是来自服务端的一条数据"  
conn.send(from_server_to_client_send_data.encode())  
  
# 接收客户端发送的数据，参数1024表示最大接收字节数  
from_client_to_server_recv_data = conn.recv(1024)  # 等待client.send  
print(from_client_to_server_recv_data.decode())  
  
# 关闭客户端连接  
conn.close()  
  
# 关闭服务器套接字  
server.close()
```

### 使用 UDP 连接：

```python file:server.py
import socket  
  
# 创建UDP socket对象  
# family=socket.AF_INET 表示使用IPv4地址族  
# type=socket.SOCK_DGRAM 表示使用UDP协议（无连接、不可靠的数据报传输）  
server = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)  
  
# 绑定socket到指定地址和端口  
# '127.0.0.1' 是本地回环地址，8001是端口号  
server.bind(('127.0.0.1', 8001))  
  
# 打印服务器socket对象信息  
print(f"server:>>>{server}")  
  
# 接收来自客户端的数据，缓冲区大小为1024字节  
# recvfrom返回数据和客户端地址信息  
from_client_recv_data, addr = server.recvfrom(1024)  
# 将接收到的字节数据解码为字符串  
from_client_recv_data = from_client_recv_data.decode()  
  
# 打印从客户端接收到的数据  
print(f"server:<<<{from_client_recv_data}")  
  
# 打印客户端地址信息  
print(f"addr:>>>{addr}")  
  
# 准备要发送给客户端的响应数据  
to_client_send_data = "这是来自服务端的一条消息"  
# 将字符串编码为字节流，因为网络传输需要二进制数据  
to_client_send_data = to_client_send_data.encode()  
  
# 向客户端发送数据  
server.sendto(to_client_send_data, addr)  
  
# 关闭服务器socket连接  
server.close()
```

```python file:client.py
import socket  
  
# 创建UDP socket对象  
# family=socket.AF_INET 表示使用IPv4地址族  
# type=socket.SOCK_DGRAM 表示使用UDP协议（无连接、不可靠的数据报传输）  
client = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)  
  
# 准备要发送给服务器的数据  
to_server_send_data = f"这是来自客户端的一条消息"  
# 将字符串编码为字节流，因为网络传输需要二进制数据  
to_server_send_data = to_server_send_data.encode()  
  
# 向指定地址发送数据  
# 目标地址为127.0.0.1:8001（本地回环地址，端口8001）  
client.sendto(to_server_send_data, ('127.0.0.1', 8001))  
  
# 打印客户端socket对象信息  
print(f"client: >>> {client}")  
  
# 接收来自服务器的响应数据，缓冲区大小为1024字节  
from_server_recv_data, addr = client.recvfrom(1024)  
# 将接收到的字节数据解码为字符串  
from_server_recv_data = from_server_recv_data.decode()  
  
# 打印从服务器接收到的数据  
print(f"client: >>> {from_server_recv_data}")  
  
# 关闭客户端socket连接  
client.close()
```

## 模拟

```python

```

## ad

```python

```

