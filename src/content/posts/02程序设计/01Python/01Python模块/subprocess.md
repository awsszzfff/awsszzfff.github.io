---
title: subprocess
date: 2025-07-26
tags:
  - Python模块
categories:
  - 程序设计
  - Python
---
可以允许启动一个新的进程，并连接到它们的输入/输出/作物管道，从而获取返回值

```python
import subprocess
```

```python
# run 最常用，运行命令并等待其完成， 0 表示成功

# 运行 ping 命令 
result = subprocess.run(['ping', 'www.baidu.com'], capture_output=True, text=True) 

# - `capture_output=True` 表示捕获输出
# - `text=True` 表示以字符串形式处理输出（而不是字节）

# 输出命令执行结果 
print("返回码:", result.returncode) 
print("输出内容:\n", result.stdout)
```

```python
# call 运行命令并返回状态码
subprocess.call(['ping', 'www.baidu.com'])

print("返回码:", return_code)
```

```python
# 运行命令并返回输出内容（若出错会抛出异常）

# 获取命令输出 
output = subprocess.check_output(['ping', 'www.baidu.com'], text=True) 

print("输出内容:\n", output)
```

```python
# Popen 更高级的用法，适用于需要更细粒度控制输入输出的情况

# 启动一个子进程 
process = subprocess.Popen(['ping', 'www.baidu.com'], stdout=subprocess.PIPE, text=True) 

# 逐行读取输出 
for line in process.stdout: 
	print(line.strip())
```

```python
res = subprocess.Popen('dir', shell=True,	# 执行shell命令
	stdout=subprocess.PIPE,	# 管道，负责存储正确信息
	stderr=subprocess.PIPE	# 管道，负责存储错误信息
	)

print(res)  # <subprocess.Popen object at 0x000001ABB1970310>

print(res.stdout.read().decode('gbk'))  # dir命令执行之后的正确结果返回

print(res.stderr.read().decode('gbk'))
```
