---
title: "Socket"
date: 2025-08-07
tags:
  - Others
categories:
  - Others
description: None
---
## 简单的通信示例

### 使用 TCP 连接

模拟 TCP 客户端发送，服务端回复（循环接收）

```python file:server.py
import socket  
  
# 创建一个TCP/IP套接字对象  
# family : 使用的是哪个套接字家族 （基于网络型的套接字对象）
# type : 使用的是哪种套接字类型 （SOCK_STREAM TCP 协议流式套接字 SOCK_DGRAM UDP 协议报式套接字） 
server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)  

# 定义服务器IP地址和端口号  
ip = '127.0.0.1'  # 本地回环地址  
port = 8001  # 端口号  
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 若端口被占用，强制停止占用进程
# 将套接字绑定到指定的IP地址和端口  
server.bind((ip, port))  

# 开始监听客户端连接请求，参数5表示最大等待连接数  
server.listen(5)  
while True:
	# 接受客户端连接请求，返回一个新的连接对象和客户端地址  
	# accept()方法会阻塞程序，直到有客户端连接进来  
	conn, addr = server.accept()  # 等待 client.connect  
	print(f"客户端地址: {addr}")  
	
	while True:
		try:
			# 持续和当前链接好的客户端进行交互
			# 接收客户端发送的数据，参数1024表示最大接收字节数  
			from_client_to_server_recv_data = conn.recv(1024)  # 等待client.send
			# 判断客户端是否已经断开连接 如果客户端断开连接则这里接收到的数据是 空 就会一直循环
			if not  from_client_to_server_recv_data:
				break
				
			result = from_client_to_server_recv_data.decode()
			if result == 'q':
				break
			print(f"data_from_client :>>>> {result}") 
			# 向客户端发送数据，需要先将字符串编码为字节  
			from_server_to_client_send_data = input("请输入给客户端的数据 :>>>> ").strip()
			conn.send(from_server_to_client_send_data.encode("utf-8"))  
		except Exception as e:
			break
	# 关闭客户端连接  
	conn.close()  
  
# 关闭服务器套接字  
server.close()
```

```python file:client.py
import socket  
  
client = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)  

# 定义要连接的服务器IP地址和端口号  
ip = '127.0.0.1'  # 服务器IP地址（本地回环地址）  
port = 8001  # 服务器端口号  

# 连接到服务器  
client.connect((ip, port))  

while True:
	data_to_server = input("请输入给服务端的数据 :>>>> ").strip()

    # 判断当前客户端输入的内容是否是空数据
    # 如果是空数据就会导致服务端和和客户端阻塞
    if not data_to_server: continue

    client.send(data_to_server.encode("utf-8"))
    if data_to_server == "q":
        break
	
	# 接收来自客户端的数据
    data_from_server = client.recv(1024)
    result = data_from_server.decode()
    if result == "q":
        break
    print(f"data_from_server :>>>> {result}")  
	  
	# 关闭客户端套接字连接  
	client.close()
```

### 使用 UDP 连接

模拟 UDP 客户端发送小写字母，服务端回复大写字母（循环接收）

```python file:server.py
from socket import socket, AF_INET, SOCK_DGRAM
  
# 创建UDP socket对象  
server = socket(family=AF_INET, type=SOCK_DGRAM)  
  
# 监听 socket 到指定地址和端口  
addr = "127.0.0.1"
port = 8001
server.bind((addr, port))  
# 打印服务器socket对象信息  
print(f"server:>>>{server}")  
	  
while True:
	# 持续和当前链接好的客户端进行交互
	# 接收来自客户端的数据，缓冲区大小为1024字节  
	# recvfrom返回数据和客户端地址信息  
	from_client_recv_data, client_addr = server.recvfrom(1024)  	# print(from_client_recv_data) # b'a'
	
	# 将接收到的字节数据解码为字符串并打印
	print(f"server:>>>{from_client_recv_data.decode()}")  # a
	  
	# 打印客户端地址信息  
	print(f"client_addr:>>>{client_addr}")  
	  
	# 准备要发送给客户端的响应数据  
	to_client_send_data = from_client_recv_data.decode().upper()
	# 将字符串编码为字节流，因为网络传输需要二进制数据  
	# 并向客户端发送数据  
	server.sendto(to_client_send_data.encode("utf-8"), client_addr)  
	  
	# 关闭服务器socket连接  
	# server.close()
```

```python file:client.py
from socket import socket, AF_INET, SOCK_DGRAM
  
# 创建UDP socket对象  
server = socket(family=AF_INET, type=SOCK_DGRAM)  
addr = "127.0.0.1"
prot = 8001

while True:
	# 准备要发送给服务器的数据  
	data_to_server = input("请输入给服务端的数据 :>>>> ").strip()
	
	# 判断当前客户端输入的内容是否是空数据
    # 如果是空数据就会导致服务端和和客户端阻塞
    if not data_to_server: continue
    
	client.sendto(data_to_server.encode("utf-8"), (addr, prot))
    data_from_server, server_addr = client.recvfrom(1024)
    print(f"data_from_server :>>>> {data_from_server.decode()}")
	  
	# 关闭客户端socket连接  
	# client.close()
```

## TCP 粘包问题

让服务端知道客户端发来的数据总大小，动态的指定可接收数据大小

eg：模拟客户端下载服务端图片文件（服务端图片 hello.png，客户端输入 hello 即可下载）

```python file:server.py
import hashlib  
import json  
import os.path  
import socket  
import struct  
import subprocess  
  
def read_data(file_name):  
    file_path = os.path.join(os.path.dirname(__file__), file_name + '.png')  
    with open(file_path, 'rb') as fp:  
        data = fp.read()  
    return data  
  
  
server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)  
# 服务器监听的地址和端口  
addr = "127.0.0.1"  
port = 8001  
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
server.bind((addr, port))  
server.listen(5)  
while True:  
    # 用来获取不同客户端连接对象  
    client_socket, client_addr = server.accept()  
    print(f"客户端地址{client_addr}已连接")  
    while True:  
        try:  
            # 持续和当前链接好的客户端进行通信  
            data_from_client = client_socket.recv(1024)  
            # 判断客户端是否已经断开连接，若断开则接收到内容为空  
            if not data_from_client:  
                break  
            file_name = data_from_client.decode('utf-8')  
            # 返回图片  
            if file_name == 'q':  
                break  
            # 下载图片数据到客户端本地  
            file_data = read_data(file_name=file_name)  
            # 统计二进制数据大小  
            data_to_client_bytes_len = len(file_data)  
            print(data_to_client_bytes_len)  
            # 验证数据完整性 ---> md5 哈希值  
            md5 = hashlib.md5()  
            md5.update(file_data)  
            # 拼接一个数据字典 ---> 携带当前文件的信息  
            # 代文件名称 + md5 哈希值 + 文件类型  
            file_data_dict = {  
                "file_name": file_name,  
                "file_hex": md5.hexdigest(),  
                "file_type": "png",  
                # 携带当前文件数据的大小  
                "data_all": data_to_client_bytes_len  
            }  
            file_data_dict_str = json.dumps(file_data_dict)  
            file_data_dict_bytes = file_data_dict_str.encode('utf-8')  
            # 用struct模块将字节总数打包为四字节二进制数据  
            pack_data = struct.pack('i', len(file_data_dict_bytes))  
            # 再去发送数据  
            # 发送字典转成二进制数据打包后的长度  
            client_socket.send(pack_data)  
            # 发送字典转成二进制数据  
            client_socket.send(file_data_dict_bytes)  
            # 发送图片数据  
            client_socket.send(file_data)  
        except Exception as e:  
            break  
    client_socket.close()  
server.close()
```

```python file:client.py
import hashlib  
import json  
import os.path  
import socket  
import struct  
  
client = socket.socket()  
# 客户端链接服务端的地址  
addr = "127.0.0.1"  
port = 8001  
client.connect((addr, port))  
while True:  
    data_to_server = input("请输入请求服务器的数据：>>> ").strip()  
    # 判断当前客户端输入的内容是否是空数据  
    # 如果是空数据就会导致服务端和和客户端阻塞  
    if not data_to_server: continue  
  
    client.send(data_to_server.encode("utf-8"))  
    if data_to_server == "q":  
        break  
    # 最开始接收到的数据一定是四字节的二进制数据  
    pack_data = client.recv(4)  
    # struct 模块将打包的数据进行解包  
    print(pack_data)  
    json_data_length_all = struct.unpack("i", pack_data)[0]  
    # 接收到的结果应该是当前字典转为json字符串后再转为二进制数据的长度  
    file_data_dict = json.loads(client.recv(json_data_length_all))  
    # 提取出当前文件数据的总长度  
    data_length_all = file_data_dict.get("data_all")  
    print(f"data_length_all : >>> {data_length_all}")  
    count_data = 0  
    data = b""  
    buffer_size = 1024  
    while count_data < data_length_all:  
        # 每次提取固定大小的数据  
        data += client.recv(buffer_size)  
        # 计算已经提取了多少的数据  
        count_data += buffer_size  
    # 计算当前总数据的哈希值  
    md5 = hashlib.md5()  
    md5.update(data)  
  
    # 从json字典中取出原本的哈希值  
    file_hex = file_data_dict.get("file_hex")  
    print(f"old_hex : >>> {file_hex}")  
    print(f"new_hex : >>> {md5.hexdigest()}")  
    if file_hex != md5.hexdigest():  
        print("文件已损坏！")  
        break  
    file_name = "nb_" + file_data_dict.get("file_name")  
    file_type = file_data_dict.get("file_type")  
    file_path = os.path.join(os.path.dirname(__file__), file_name + "." + file_type)  
    with open(file_path, "wb") as fp:  
        fp.write(data)
```