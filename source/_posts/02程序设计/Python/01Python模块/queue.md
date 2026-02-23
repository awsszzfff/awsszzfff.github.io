---
title: queue
date: 2025-11-30
updated: 2025-11-30
tags:
  - Python模块
categories:
  - 程序设计
  - Python
description: Python 中的队列
---
```python
import queue
```

```python
# 创建队列对象  
q = queue.Queue(maxsize)  
# maxsize : 当前队列中的最大容量，不写则默认容量，写了就是按照自己的容量定

# 放入和获取数据
q.put()
q.get()
# 若设置了最大容量，当放入的数据超出最大容量之后就会导致阻塞

# timeout ： 超时时间，一旦当前 put 发生意外 2 秒之后就会抛出异常  
q.put(1, timeout=2)
q.get(timeout=2)

q.empty()  	# 判断当前队列是否为空  
q.full()  	# 判断当前队列是否满了

# 获取数据一旦为空抛出异常  
q.get_nowait()
```