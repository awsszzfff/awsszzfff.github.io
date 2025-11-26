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
# (1)方式一：直接使用Process类创建 子进程对象然后启动

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

PS：

> 由于Windows没有fork，多处理模块启动一个新的Python进程并导入调用模块。如果在导入时调用Process（），那么这将启动无限继承的新进程（或直到机器耗尽资源）。这是隐藏对Process（）内部调用的原，使用`if __name__ == "__main__"`，这个if语句中的语句将不会在导入时被调用。