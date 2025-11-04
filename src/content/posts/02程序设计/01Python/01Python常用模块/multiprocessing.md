---
title: "multiprocessing"
date: 2025-08-21
tags:
  - Others
categories:
  - Others
description: None
---
```python
import multiprocessing
```

```python
p = multiprocessing.Process()

def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, *, daemon=None):
	# group : 参数表示一个组，但是我们不用
	# target: 表示调用的对象 要让子进程完成的任务
	# name : 子进程的名称
	# args : 元组类型，子进程完成的任务的函数的参数
	# kwargs: 调用对象的字典

# 方法
p.start()	# 启动进程，会调用进程中的run()方法
p.run()		# 进程运行时的方法
p.terminate()	# 强制终止进程p
p.is_alive()	# p仍运行，返回True
p.join([timeout])	# 主进程等待所有子进程结束后结束主进程

# 属性
p.daemon	# 守护进程（主进程结束，会自动结束子进程）
    # 在进程启动(start)之前为当前子线程添加额外的参数和限制
    # p.daemon = True
p.name		# 进程名
p.pid		# ...
p.exitcode	# 进程在运行时为None...
p.authkey	# 进程的身份验证键
```

```python
from multiprocessing import current_process
current_process().pid	# 查看进程pid
```

## 不同方式创建子进程

```python
# 制作多进程的启动入口  
# (1)方式一：通过multiprocessing的对象启动 

# 创建子进程程序  
def work(name):  
    print(f"{name} is starting \n")  
    sleep_time = random.randint(1, 6)  
    print(f"{name} is sleeping {sleep_time} s \n")  
    time.sleep(sleep_time)  
    print(f"{name} is ending \n")  
 
def main_object():  
    # （1）实例化得到子进程对象  
    task_1 = multiprocessing.Process(  
        # target 就是需要启动的子进程的函数名  
        target=work,  
        # args 传入的位置参数，位置参数必须带 , 元组类型  
        args=("work_1",)  
    )  
    task_2 = multiprocessing.Process(  
        target=work,  
        kwargs={'name': 'work_2'}  
    )  
    # （2）启动子进程  
    task_1.start()  
    task_2.start()

=====

# 方式二，继承multiprocessing.Process，重写run方法
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
    task_1 = MyProcess(name='work_1')  
    task_2 = MyProcess(name='work_2')  

    task_1.start()  
    task_2.start()
```

## 示例：

```python
import multiprocessing  
import random  
import time  

# 创建子进程程序  
def work(name):  
    print(f"{name} is starting \n")  
    sleep_time = random.randint(1, 6)  
    print(f"{name} is sleeping {sleep_time} s \n")  
    time.sleep(sleep_time)  
    print(f"{name} is ending \n")  
  
# 通过multiprocessing的对象启动子进程
def main_object():  
    task_list = []  
    # 这个生成式在创建多个子进程  
    for i in range(5):  
        task = multiprocessing.Process(  
            # target 就是需要启动的子进程的函数名  
            target=work,  
            # args 传入的位置参数，位置参数必须带 , 元组类型  
            args=(f"work_{i}",)  
        )
        '''
        task = multiprocessing.Process(  
    		target=work,  
    		kwargs={'name': 'work_2'}  
		)
		'''
        task.start()  
        task_list.append(task)  
    # 启动子进程  
    for task in task_list:  
        task.join()  
  
  
if __name__ == '__main__':  
    start_time = time.time()  
    print(f"这是主进程 __main__ 开始 :>>>> \n")  
    main_object()  
    print(f"这是主进程 __main__ 结束 :>>>> \n")  
    end_time = time.time()  
    print(f'总耗时 :>>>> {end_time - start_time}s')  
  
# 这是主进程 __main__ 开始 :>>>>    
# 这是主进程 __main__ 结束 :>>>>    
# 总耗时 :>>>> 5.176285266876221s  
  
# 并行 且主进程等待所有子进程结束后再结束 耗时是最长的子进程的耗时
```
