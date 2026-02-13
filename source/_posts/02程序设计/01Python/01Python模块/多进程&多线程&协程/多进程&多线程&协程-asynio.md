---
title: 多进程&多线程&协程-asynio
date: 2025-12-14
updated: 2025-12-14
tags:
  - Python模块
categories:
  - Python
  - 程序设计
description: asynio 协程
---
协程，单线程的，**事件循环 (Event Loop)**：`asyncio` 内部有一个死循环。它不断检查任务列表

- “煮饭协程还在等吗？” —— 是的，还在等。
- “洗菜协程准备好了吗？” —— 准备好了。
- “OK，那我现在把 CPU 给洗菜协程。”

`async`、`await` 关键字
- `async def`：定义一个“协程函数”。调用它不会立即执行，而是返回一个“协程对象”。
- `await`：告诉程序：“这里有 IO 等待，你可以先去忙别的，等这里有结果了再切回来”。
- `asyncio.run()`：启动指挥中心（事件循环），运行最外层的协程。

```python
import asyncio
import time

# 1. 定义协程
async def task(name, duration):
    print(f"任务 {name} 开始...")
    # 2. 异步等待：告诉 CPU 去忙别的，duration 秒后再回来
    await asyncio.sleep(duration) 
    print(f"任务 {name} 完成！")

async def main():
    # 3. 同时封装多个任务
    # asyncio.gather 会让这些任务“并发”运行
    await asyncio.gather(
        task("煮饭", 2),
        task("洗菜", 1)
    )

if __name__ == "__main__":
    start = time.time()
    # 4. 运行主协程
    asyncio.run(main())
    print(f"总耗时: {time.time() - start:.2f}s") # 结果：2.00s
```

示例：异步实现高性能扫描器 `aiohttp`

```python
import asyncio
import aiohttp
import time

async def check_site_async(session, url):
    """
    具体的异步请求逻辑
    """
    print(f"[*] 正在异步请求: {url}")
    try:
        # await 会挂起当前协程，让出 CPU 去处理其他请求
        async with session.get(url, timeout=5) as response:
            status = response.status
            print(f"[+] {url} 状态码: {status}")
            return status
    except Exception as e:
        return f"Error: {e}"

async def main():
    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.baidu.com"
    ]

    # aiohttp 推荐使用 ClientSession 来管理连接池（复用 TCP 连接）
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            # 创建任务但不立即执行
            tasks.append(check_site_async(session, url))
        
        # 并发执行所有任务
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    start = time.time()
    asyncio.run(main())
    print(f"\n[异步模式] 总耗时: {time.time() - start:.2f}秒")
```