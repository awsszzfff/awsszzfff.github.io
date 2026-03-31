---
title: Python的几种输出方式
date: 2024-06-22
updated: 2024-06-22
tags:
  - 杂记
categories:
  - 程序设计杂记
  - Python
description: Python的几种输出方式
published: true
---
```python
# 多行输入，每行两个整数
import sys  
  
for line in sys.stdin:  
    a, b = line.split(' ')  
    print(int(a) + int(b))  
    print()

3 4
11 40	

7
51
```

```python
# 多组数据，每组第一行为n，之后输入n行两个整数
while 1:  
    try:  
        N = int(input())  
        for i in range(N):  
            l = list(map(int, input().split()))  
            print(sum(l))  
    except:  
        break

2
2 4
9 21

6
30
```

```python
# 若干行输入，每行输入两个整数，遇到特定条件终止
while True:  
    s = input().split()  
    a, b = int(s[0]), int(s[1])  
    if not a or not b:  
        break  
    print(a + b)

2 4
11 19
0 0

6
30
```

```python
# 若⼲⾏输⼊，遇到0终⽌，每⾏第⼀个数为N，表示本⾏后⾯有N个数
import sys  
  
for line in sys.stdin:  
    nums = line.split()  
    nums = list(map(int, nums))  
    n = nums[0]  
    if not n:  
        break  
    print(sum(nums[-n:]))
    
4 1 2 3 4
5 1 2 3 4 5
0 

10
15
```

```python
print("%d %d"%(a,b))
print("{0} {1}".format(a,b))
print(f"{a = }，{b = }")
print(f"{a} {b}")
print(f"{a:.1f} {b:.1f}")
```

| 变量值         | 占位符        | 格式化结果           | 说明            |
| ----------- | ---------- | --------------- | ------------- |
| `3.1415926` | `{:.2f}`   | `'3.14'`        | 保留小数点后两位      |
| `3.1415926` | `{:+.2f}`  | `'+3.14'`       | 带符号保留小数点后两位   |
| `-1`        | `{:+.2f}`  | `'-1.00'`       | 带符号保留小数点后两位   |
| `3.1415926` | `{:.0f}`   | `'3'`           | 不带小数          |
| `123`       | `{:0>10d}` | `'0000000123'`  | 左边补`0`，补够10位  |
| `123`       | `{:x<10d}` | `'123xxxxxxx'`  | 右边补`x` ，补够10位 |
| `123`       | `{:>10d}`  | `'       123'`  | 左边补空格，补够10位   |
| `123`       | `{:<10d}`  | `'123       '`  | 右边补空格，补够10位   |
| `123456789` | `{:,}`     | `'123,456,789'` | 逗号分隔格式        |
| `0.123`     | `{:.2%}`   | `'12.30%'`      | 百分比格式         |
| `123456789` | `{:.2e}`   | `'1.23e+08'`    | 科学计数法格式       |