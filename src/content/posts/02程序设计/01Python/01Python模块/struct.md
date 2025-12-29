---
title: struct
date: 2025-08-14
tags:
  - Python模块
categories:
  - 程序设计
  - Python
description: 将当前字节数据的结果打包成四个字节的二进制数据
---
将当前字节数据的结果打包成四个字节的二进制数据

```python
import struct

result = run_cmd(cmd="ifconfig").encode()
# print(len(result))  # 4315

# 将当前字节数据的结果打包成四个字节的二进制数据
res = struct.pack("i", len(result))
print(res)  # b'\xdb\x10\x00\x00'

# print(res.decode()) # UnicodeDecodeError: 'utf-8' codec can't decode byte 0xdb in position 0: invalid continuation byte

res = struct.unpack("i", res)
print(res)

#   ○ x --- 填充字节
#   ○ c --- char类型，占1字节
#   ○ b --- signed char类型，占1字节
#   ○ B --- unsigned char类型，占1字节
#   ○ h --- short类型，占2字节
#   ○ H --- unsigned short类型，占2字节
#   ○ i --- int类型，占4字节
#   ○ I --- unsigned int类型，占4字节
#   ○ l --- long类型，占4字节（32位机器上）或者8字节（64位机器上）
#   ○ L --- unsigned long类型，占4字节（32位机器上）或者8字节（64位机器上）
#   ○ q --- long long类型，占8字节
#   ○ Q --- unsigned long long类型，占8字节
#   ○ f --- float类型，占4字节
#   ○ d --- double类型，占8字节
#   ○ s --- char[]类型，占指定字节个数，需要用数字指定长度
#   ○ p --- char[]类型，跟s一样，但通常用来表示字符串
#   ○ ? --- bool类型，占1字节
```