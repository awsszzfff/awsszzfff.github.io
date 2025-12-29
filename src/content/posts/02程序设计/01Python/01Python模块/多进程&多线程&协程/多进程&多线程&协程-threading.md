---
title: 多进程&多线程&协程-threading
date: 2025-11-30
updated: 2025-11-30
tags:
  - Python模块
categories:
  - 程序设计
  - Python
description: threading 多线程
---
和多进程的操作基本相同[[多进程&多线程&协程-multiprocessing]]

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

## 示例 TCP 多线程并发

TCP 多线程并发，只需要将 multiprocessing/Process 替换为 threading/Thread 即可。

[[多进程&多线程&协程-multiprocessing#示例1 模拟 TCP 服务|TCP 多进程并发]]

## 互斥锁

解决子线程之间对共享资源的访问冲突问题，保证在同一时刻只有一个线程在访问共享资源，但多进程之间也存在这种问题（多个进程共享同一块内存）

```python
import threading  
import time  
import random  
  
# 共享资源  
counter = 0  
# 创建互斥锁  
lock = threading.Lock()  
  
  
def task(thread_name):  
    global counter  
    for i in range(3):  
        # 模拟线程在准备期间的耗时  
        time.sleep(random.uniform(0.1, 0.3))  
  
        print(f"--- [{thread_name}] 尝试获取锁...")  
  
        # 1. 手动加锁  
        # 如果锁已经被其他线程占用，代码会阻塞在这里，直到锁被释放  
        lock.acquire()  
        try:  
            print(f"[{thread_name}] 成功进入临界区！当前值: {counter}")  
            # 模拟业务逻辑处理  
            temp = counter  
            time.sleep(0.2)  
            counter = temp + 1  
            print(f"[{thread_name}] 修改完毕，新值: {counter}")  
        except Exception as e:  
            print(f"[{thread_name}] 运行出错: {e}")  
        finally:  
            # 2. 手动释放锁  
            # 放在 finally 块中是为了保证即使上面代码报错，锁也能被释放  
            # 否则会发生死锁，其他等待的线程将永远无法运行  
            lock.release()  
            print(f"[{thread_name}] 已手动释放锁。\n")  
  
        """  
        # 使用 with lock 替代 acquire/release，能自动处理异常释放锁  
        with lock:            print(f"[{thread_name}] 已获得锁。当前 counter 值: {counter}")  
  
            # 模拟临界区内的操作耗时  
            temp = counter            time.sleep(0.1)            counter = temp + 1  
            print(f"[{thread_name}] 修改完成。新 counter 值: {counter}")  
  
        # 退出 with 代码块后，锁会自动释放  
        print(f"[{thread_name}] 释放了锁。")  
        """  
  
if __name__ == "__main__":  
    threads = []  
    for i in range(3):  
        t = threading.Thread(target=task, args=(f"Thread-{i + 1}",))  
        threads.append(t)  
        t.start()  
  
    for t in threads:  
        t.join()  
  
    print(f"所有任务完成，最终计数: {counter}")
```

## 递归锁

在处理复杂的系统架构（尤其是包含大量函数嵌套调用）时，你可能会遇到“同一个线程多次请求同一把锁”的情况。这时，普通的 `Lock` 会导致程序卡死（死锁），而 **递归锁（RLock, Reentrant Lock）** 就是专门为此设计的。

一种特殊的互斥锁，它允许**同一个线程**多次获得（acquire）同一把锁，而不会产生死锁。

- **计数器机制**：在递归锁内部维护着一个 `owner`（当前持有锁的线程 ID）和一个 `counter`（嵌套层数）。
- **规则**：
    1. 如果一个线程已经持有了锁，它可以再次调用 `acquire()`，计数器随之加 1。
    2. 每次 `acquire()` 必须对应一个 `release()`。
    3. 只有当计数器归零时，锁才会被真正释放，其他线程才能获取。

```python
# 死锁
import threading

lock = threading.Lock() # 使用普通锁

def function_A():
    lock.acquire()
    print("Function A 拿到锁了")
    function_B()  # 调用 B，B 也要拿这把锁
    lock.release()

def function_B():
    lock.acquire() # 这里会卡死！因为 A 还没释放，B 永远拿不到
    print("Function B 拿到锁了")
    lock.release()

# 运行 function_A() 会导致死锁，程序永久挂起
```

```python
import threading  
import time  
  
# 创建递归锁  
rlock = threading.RLock()  
  
  
class SecurityScanner:  
    def __init__(self):  
        self.vuln_count = 0  
  
    def scan_port(self):  
        """子模块：扫描端口"""  
        # with的方式：with rlock:  
        rlock.acquire()  # 手动加锁：计数器从 1 变为 2        
        try:  
            print(f"[{threading.current_thread().name}] 正在扫描端口... (递归计数: 2)")  
            self.vuln_count += 1  
            # 模拟耗时操作  
            time.sleep(0.1)  
        finally:  
            rlock.release()  # 手动释放：计数器从 2 降回 1            
            print(f"[{threading.current_thread().name}] 子模块释放锁")  
  
    def full_scan(self):  
        """主模块：执行全项扫描，内部调用子模块"""  
        print(f"\n--- [{threading.current_thread().name}] 启动全项扫描 ---")  
  
        # with的方式：with rlock:  
        rlock.acquire()  # 手动加锁：计数器从 0 变为 1        
        try:  
            print(f"[{threading.current_thread().name}] 进入主扫描逻辑 (递归计数: 1)")  
  
            # 这里调用了同样需要锁的方法（发生递归/重入）  
            self.scan_port()  
  
            print(f"[{threading.current_thread().name}] 完成子项扫描，准备退出主逻辑")  
        finally:  
            rlock.release()  # 手动释放：计数器从 1 降回 0，此时锁才真正释放  
            print(f"[{threading.current_thread().name}] 主逻辑释放锁，其他线程现在可以进场了")  
  
  
if __name__ == "__main__":  
    scanner = SecurityScanner()  
  
    # 模拟两个并发执行的扫描任务  
    # Scanner-1 获取锁期间，Scanner-2 会在 full_scan 的第一个 acquire 处阻塞等待  
    t1 = threading.Thread(target=scanner.full_scan, name="Scanner-1")  
    t2 = threading.Thread(target=scanner.full_scan, name="Scanner-2")  
  
    t1.start()  
    t2.start()  
  
    t1.join()  
    t2.join()  
  
    print(f"最终扫描发现漏洞总数: {scanner.vuln_count}")  
```

## 信号量

与递归锁不同的是递归锁允许同时访问的任务数为 1 （但允许同线程重入），信号量可以自定义允许同时访问的任务数。[[多进程&多线程&协程-multiprocessing#信号量|多进程也有信号量]] 

```python
import threading
import time
import random

# 1. 创建信号量，设置最大并发数为 3
# 只有 3 个“停车位”
semaphore = threading.Semaphore(3)

def scan_vulnerability(thread_name):
    print(f"[*] [{thread_name}] 正在排队等待进入扫描通道...")
    
    # 2. 尝试获取信号量 (P操作)
    # 如果计数器 > 0，则减1并进入；如果为0，则在此阻塞
    semaphore.acquire()
    
    try:
        print(f"[{thread_name}] 获得许可，开始扫描目标任务！")
        # 模拟扫描耗时
        duration = random.uniform(1, 3)
        time.sleep(duration)
        print(f"[{thread_name}] 扫描完成，用时 {duration:.2f}s")
        
    finally:
        # 3. 释放信号量 (V操作)
        # 计数器加1，唤醒排队中的其他线程
        print(f"[{thread_name}] 离开通道，释放许可。")
        semaphore.release()

if __name__ == "__main__":
    threads = []
    
    # 创建 8 个线程同时去抢 3 个位置
    for i in range(8):
        t = threading.Thread(target=scan_vulnerability, args=(f"Thread-{i+1}",))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\n--- 所有扫描任务已结束 ---")
```

## 事件

“锁”是为了争夺资源，那么“事件”就是为了同步节奏。像一个“发令枪”：多个线程可以同时停下来等待一个信号，一旦信号发出，所有等待的线程都会同时开始运行。

`Event` 拥有一个**全局标志位（Flag）**，初始值为 `False`。

四个核心方法：
- **`wait()`**: 线程进入阻塞状态，等待标志位变为 `True`。如果标志位已经是 `True`，则直接通过。
- **`set()`**: 将标志位设置为 `True`，并**唤醒所有**正在等待的线程。
- **`clear()`**: 将标志位重置为 `False`。 
- **`is_set()`**: 查询当前标志位的状态。

```python
import threading
import time

# 1. 创建一个事件对象
loading_event = threading.Event()

def scan_task(node_id):
    print(f"[*] 扫描节点-{node_id} 已就绪，等待特征库加载...")
    # 2. 线程在此阻塞，直到 loading_event.set() 被调用
    loading_event.wait() 
    print(f"[Event Triggered] 节点-{node_id} 收到信号，开始扫描目标！")

def prepare_data():
    print("\n[Admin] 正在从服务器下载最新的漏洞特征库...")
    time.sleep(3) # 模拟加载时间
    print("[Admin] 特征库加载完毕！")
    # 3. 发射信号，唤醒所有等待的线程
    loading_event.set()

if __name__ == "__main__":
    # 开启 3 个等待线程
    for i in range(3):
        threading.Thread(target=scan_task, args=(i,)).start()

    # 主线程执行准备工作
    prepare_data()
```

## 线程池

频繁地创建和销毁进程/线程会带来巨大的系统开销（上下文切换、内存分配等）。为此引入了池化技术（Pooling）。

**池化技术**的核心思想是：**空间换时间，循环利用。**

- **预创建**：程序启动时先创建好固定数量的进程/线程。
- **任务队列**：将任务丢进池子的队列里。
- **自动调度**：池子里的“工人”谁空闲了，谁就去领任务做，做完后不销毁，直接等下一个任务。

适用场景：IO 密集型任务，如爬虫、端口扫描、API 请求、数据库读写。

```python
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# 模拟一个网络安全扫描任务：探测端口
def scan_port(ip, port):
    print(f"[+] 正在扫描 {ip}:{port}...")
    # 模拟网络延迟
    time.sleep(1)
    return f"结果: {ip}:{port} 开放"


def thread_pool_demo():
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    ports = [80, 443, 8080]

    # 1. 初始化线程池
    # max_workers: 线程池中工作的线程上限。通常设为 CPU 核心数的 5 倍或更多（对于 I/O 任务）
    with ThreadPoolExecutor(max_workers=4) as executor:

        # 2. 提交任务的两种方式：

        # 方式 A: map (简单，按顺序返回)
        # 类似于内置 map，将函数映射到列表的每个元素
        print("--- 使用 map 批量提交 ---")
        results = executor.map(lambda p: scan_port("127.0.0.1", p), ports)
        for res in results:
            print(res)

        # 方式 B: submit (灵活，非阻塞)
        # submit 返回一个 Future 对象，代表“未来”的结果
        print("\n--- 使用 submit 提交 ---")
        future_tasks = [executor.submit(scan_port, host, 80) for host in hosts]

        # 3. 获取结果
        # as_completed 会在任务完成时立刻返回，不保证提交顺序
        for future in as_completed(future_tasks):
            try:
                data = future.result()  # 获取函数返回值
                print(f"任务完成: {data}")
            except Exception as e:
                print(f"异常: {e}")


if __name__ == "__main__":
    thread_pool_demo()
```

> - **混合模式**：在某些复杂的安全系统中，可以结合进程池和线程池使用。例如：使用进程池分配不同的流量包文件，在每个进程内部使用线程池并行处理该文件中的不同流。
> 
> - **Future 对象的作用**：`future` 允许查询任务状态（`running()`, `done()`）以及取消尚未开始的任务（`cancel()`）。在编写具有交互功能的扫描器时，对于随时停止扫描非常有用。
> 
> - **内存安全性**：在进程池中，由于数据是**深拷贝**到子进程的，修改全局变量不会影响主进程，这在处理敏感数据时是一种天然的隔离保护。
