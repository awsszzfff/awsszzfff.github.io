---
title: multiprocessing
date: 2025-08-21
tags:
  - Python模块
categories:
  - 程序设计
  - Python
description: multiprocessing 多进程
---
```python
# 多进程
import multiprocessing
```

```python
# 创建子进程对象
process = multiprocessing.Process()

def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, *, daemon=None):
	'''
	group : 当前进程组，默认None，基本不修改
	target: 表示当前需要创建子进程的函数对象
	name : 当前子进程的名字，默认不会改
	args : 在调用上面子进程函数的时候需要传递进去的参数 按照位置传递
	kwargs: 在调用上面子进程函数的时候需要传递进去的参数 按照关键字传递
	daemon：守护进程是否开启
	'''
	
# 子进程启动
process.start()	# 启动子进程，会调用进程中的run()方法
process.run()		# 启动子进程 --- 启动 start 之后会触发 run 的运行
process.is_alive()	# 判断当前子进程的存活状态
process.join()	# 主进程等待所有子进程结束后结束
process.terminate()	# 强制终止进程process
process.close()  # 终止当前子进程

# 子进程的属性
process.daemon	# 守护进程（主进程结束，会自动结束子进程）
    # 在进程启动(start)之前为当前子进程添加额外的参数和限制
    # process.daemon = True
process.name		# 当前子进程的名字
process.pid			# ...
process.exitcode	# 退出状态码，进程在运行时为None...
process.authkey		# 进程的身份验证键，默认是一串 32位的16进制数
```

```python
from multiprocessing import current_process
current_process().pid	# 查看进程pid
```

## 不同方式创建子进程

```python
# 制作多进程的启动入口  
# 方式一：直接使用Process类创建 子进程对象然后启动

from multiprocessing import Process

# 创建子进程程序  
def work(name):  
    print(f"{name} is starting \n")  
    sleep_time = random.randint(1, 6)  
    print(f"{name} is sleeping {sleep_time} s \n")  
    time.sleep(sleep_time)  
    print(f"{name} is ending \n")  
 
def main_object():  
    # （1）实例化得到子进程对象  
    process_one = Process(  
        # target 目标子进程函数 ， 记住给的是内存地址  
        target=work,  
        # args 传入的位置参数，位置参数必须带 , 元组类型  
        args=("work_1",)  
    )  
    process_two = Process(  
        target=work,  
        kwargs={'name': 'work_2'}  
    )  
    # （2）启动子进程  
    process_one.start()  
    process_two.start()

if __name__ = '__main__':
	main_object()
```

```python
# 方式二，直接继承 父类 Process 重写 run 方法
class MyProcess(multiprocessing.Process):  
    def __init__(self, name):  
        super().__init__()  
        self.name = name  
  
    def run(self):  
        print(f"{self.name} is starting \n")  
        sleep_time = random.randint(1, 6)  
        print(f"{self.name} is sleeping {sleep_time} s \n")  
        time.sleep(sleep_time)  
        print(f"{self.name} is ending \n")
        
def main_class():  
    # 创建子进程
    process_one = MyProcess(name='work_1')  
    process_two = MyProcess(name='work_2')  

    process_one.start()  
    process_two.start()
    
if __name__ = '__main__':
	main_class()
```

## 示例

### 示例1

模拟 TCP 服务端接收多个客户端请求，可启动多个客户端向服务端发送数据

```python file:server.py
import multiprocessing  
from socket import socket, AF_INET, SOCK_STREAM,SOL_SOCKET,SO_REUSEADDR  
  
def work(conn,addr):  
    while True:  
        data_from_client = conn.recv(1024)  
        if not data_from_client:  
            conn.close()  
            break  
        print(f"来自于客户端 {addr} 的数据 :>>>> {data_from_client.decode()}")  
        data_from_client_upper = data_from_client.decode().upper()  
        conn.send(data_from_client_upper.encode())  
  
def main():  
    server = socket(family=AF_INET, type=SOCK_STREAM)  
    server.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)  
    server.bind(('127.0.0.1', 9696))  
  
    server.listen(5)  
  
    while True:  
        # 负责接收每一个客户端的链接对象  
        conn, addr = server.accept()  
        # 将当前的链接对象创建程一个子进程  
        task = multiprocessing.Process(  
            target=work, args=(conn,addr)  
        )  
        # 让当前子进程启动  
        task.start()  
  
if __name__ == '__main__':  
    main()
```

```python file:client.py
from socket import socket, AF_INET, SOCK_STREAM  
  
client = socket(family=AF_INET, type=SOCK_STREAM)  
  
client.connect(('127.0.0.1', 9696))  
  
while True:  
    msg = input('请输入要发送的消息：')  
    if not msg: continue  
    client.send(msg.encode('utf-8'))  
  
    data_from_server = client.recv(1024)  
    print(f"服务器返回的数据：{data_from_server.decode('utf-8')}")
```

### 示例2

模拟并发执行，子进程结束后，主进程才会结束

```python
from multiprocessing import Process
import random  
import time  

def timer(func):  
    def inner(*args, **kwargs):  
        start_time = time.time( )  
        res = func(*args, **kwargs)  
        end_time = time.time()  
        print(f"函数 {func.__name__} 运行时间：{end_time - start_time} 秒")  
        return res  
  
    return inner

# 创建子进程程序  
def work(name):  
    sleep_time = random.randint(1, 4)  
	print(f"{name} is starting sleeping {sleep_time}")  
	time.sleep(sleep_time)  
	print(f"{name} is ending sleeping {sleep_time}") 
  
# 通过multiprocessing的对象启动子进程
@timer
def main_object():  

    # 这个生成式在创建多个子进程   
	task_list = [Process(  
		# target 就是需要启动的子进程的函数名  
		target=work,  
		# args 传入的位置参数，位置参数必须带 , 元组类型  
		args=(f"work_{i}",)  
	) for i in range(5)]
	'''
	task = multiprocessing.Process(  
		target=work,  
		kwargs={'name': 'work_2'}  
	)
	'''
    [task.start() for task in task_list]	# start 启动子进程
    [task.join() for task in task_list] 	# join 等待子进程结束
	    
	'''  
	先 start()，后立即 join() (导致 串行)  
	全部 start()，后全部 join() (实现 并发/并行)  
	'''
  
if __name__ == '__main__':  
	print(f"main process is starting ")
    process_work_wait_main()  
    print(f"main process is ending ")
  
# main process is starting    
# ...
# 函数 main_object 运行时间：2.230956554412842 秒    
# main process is ending  
  
# 并行 且主进程等待所有子进程结束后再结束 耗时是最长的子进程的耗时
```

## 进程间通信

### 队列实现进程间通信

```python
from multiprocessing import Process, Queue  
  
def producer(queue):  
    print(f"这是来自主进程的数据 :>>>> {queue.get()}")  
    # 再向主进程返回一个数据  
    queue.put("son process")  
  
def process_main_to_son():  
    # 创建队列对象用来存储数据  
    queue = Queue()  
    # 向子进程传入数据  
    queue.put(f"main process")  
    # 创建子进程  
    process_son = Process(  
        target=producer,  
        args=(queue,)  
    )  
    # 启动当前的子进程  
    process_son.start()  
    # 等待主进程结束前结束子进程  
    process_son.join()  
    print(f"这是来自子进程的数据 :>>>> {queue.get()}")  
  
if __name__ == '__main__':  
    process_main_to_son()
```

示例：模拟生产者消费者通信

```python
import random  
import time  
from multiprocessing import JoinableQueue, Process  
  
  
def producer(name, food, queue):  
    for i in range(2):  
        # 生产数据  
        data = f"{name}生产了第{i}个{food}"  
        # 模拟延迟  
        time.sleep(random.randint(1, 4))  
        queue.put(data)  
        print(f"{name}生产了{data}")  
    # 直接使用 joinablequeue 内置的方法增加结束标志  
    queue.join()  
  
  
def consumer(name, queue):  
    while True:  
        # 获取数据  
        data = queue.get()  
        time.sleep(random.randint(1, 4))  
        print(f"{name}消费了{data}")  
        queue.task_done()  
  
  
def process_one():  
    queue = JoinableQueue()  
    producer_dream = Process(target=producer, args=("dream", "apple", queue))  
    producer_lucy = Process(target=producer, args=("lucy", "pear", queue))  
  
    customer_one = Process(target=consumer, args=("customer_one", queue))  
    customer_two = Process(target=consumer, args=("customer_two", queue))  
  
    customer_one.daemon = True  
    customer_two.daemon = True  
  
    process_list = [producer_dream, producer_lucy, customer_one, customer_two]  
    [task.start() for task in process_list]  
  
    producer_dream.join()  
    producer_lucy.join()  
  
  
if __name__ == '__main__':  
    process_one()
```

### 管道实现进程间通信

```python
import random  
import time  
from multiprocessing import Pipe, Process  
  
  
def producer(name, conn):  
    left_conn, right_conn = conn  
    # 把右侧管道关闭  
    right_conn.close()  
    for i in range(2):  
        # 生产数据  
        data = f"当前大厨 {name} 生产出了第{i}份!"  
  
        # 从左侧管道向管道中添加数据  
        left_conn.send(data)  
        print(f"生产者 {name} :>>>>  {data}")  
        # 模拟延迟  
        time.sleep(random.randint(1, 4))  
    left_conn.close()  
  
  
def customer(name, conn):  
    left_conn, right_conn = conn  
    # 把左侧管道关闭  
    left_conn.close()  
    while True:  
        try:  
            # 取出数据  
            food = right_conn.recv()  
            # 模拟延迟  
            time.sleep(random.randint(1, 4))  
            # 打印数据  
            print(f"消费者 {name} :>>>>  {food}")  
        except:  
            right_conn.close()  
            break  
  
  
def process_one():  
    # 建立媒介 --- 创建管道  
    left_conn, _right_conn = Pipe()  
    
    '''  
    (<multiprocessing.connection.Connection object at 0x12533fee0>, <multiprocessing.connection.Connection object at 0x12533feb0>)    
    '''  
    
    # 先启动消费者，后启动生产者（通常情况下都是如此，上面的队列操作也一样（容量有限，防止阻塞））
    customer_smile = Process(target=customer, args=("smile", (left_conn, _right_conn)))  
    customer_smile.start()  
  
    # 生产数据  
    producer(name="dream", conn=(left_conn, _right_conn))  
  
    left_conn.close()  
    _right_conn.close()  
  
    customer_smile.join()  
  
  
if __name__ == '__main__':  
    process_one()
```

## 互斥锁

解决子线程之间对共享资源的访问冲突问题，保证在同一时刻只有一个线程在访问共享资源，但多进程之间也存在这种问题（多个进程共享同一块内存）



PS：

> 由于Windows没有fork，多处理模块启动一个新的Python进程并导入调用模块。如果在导入时调用Process（），那么这将启动无限继承的新进程（或直到机器耗尽资源）。这是隐藏对Process（）内部调用的原，使用`if __name__ == "__main__"`，这个if语句中的语句将不会在导入时被调用。