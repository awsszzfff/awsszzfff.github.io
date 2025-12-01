---
title: threading
date: 2025-11-30
updated: 2025-11-30
tags:
  - Python模块
categories:
  - 程序设计
  - Python
description: threading 多线程
---
和多进程的操作基本相同 [[multiprocessing]]

```python
import threading
```

```python
from threading import current_thread, active_count
current_process().name	# 线程名
active_count()			# 存活线程数
```

## 不同方式创建子线程

```python
# 方式一：直接使用Thread类创建子线程对象
import random  
import time  
from threading import Thread  
  
  
def timer(func):  
    def inner(*args, **kwargs):  
        start_time = time.time()  
        func(*args, **kwargs)  
        end_time = time.time()  
        print(f"{func.__name__} 运行时间：{end_time - start_time}")  
  
    return inner  
  
  
# 子线程函数  
def work_thread(name):  
    sleep_time = random.randint(1, 6)  
    print(f"{name} is start sleeping  {sleep_time}")  
    time.sleep(sleep_time)  
    print(f"{name} is end sleeping ")  
  
  
@timer  
def process_thread_work():  
    task_list = [Thread(target=work_thread, args=(i,)) for i in range(4)]  
    # 将每一个子进程启动  
    [task.start() for task in task_list]  
    # 阻塞每一个子进程  
    [task.join() for task in task_list]  
  
  
if __name__ == '__main__':  
    print(f"main process start .... ")  
    process_thread_work()  
    print(f"main process end .... ")
```

```python
# 方式二，直接继承 父类 Thread 重写 run 方法
import random  
import time  
from threading import Thread  
  
  
def timer(func):  
    def inner(*args, **kwargs):  
        start_time = time.time()  
        func(*args, **kwargs)  
        end_time = time.time()  
        print(f"{func.__name__} 运行时间：{end_time - start_time}")  
  
    return inner  
  
  
class MyThread(Thread):  
    def __init__(self, input_name):  
        super().__init__()  
        self.name = input_name  
  
    def run(self):  
        sleep_time = random.randint(1, 6)  
        print(f"{self.name} is start sleeping  {sleep_time}")  
        time.sleep(sleep_time)  
        print(f"{self.name} is end sleeping ")  
  
  
@timer  
def my_process_thread():  
    task_list = [MyThread(input_name=i) for i in range(5)]  
    # 将每一个子进程启动  
    [task.start() for task in task_list]  
    # 阻塞每一个子进程  
    [task.join() for task in task_list]  
  
  
if __name__ == '__main__':  
    print(f"main process start .... ")  
    my_process_thread()  
    print(f"main process end .... ")
```

## 示例

TCP 多线程并发，只需要将 Process 替换为 Thread 即可。

## 互斥锁


