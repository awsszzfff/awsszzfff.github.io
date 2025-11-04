---
title: "Datetime"
date: 2025-07-17
tags:
  - Others
categories:
  - Others
---
> 官方文档： https://docs.python.org/zh-cn/3.12/library/datetime.html

```python
import datetime
```

```python
time_ = datetime.date(2024,1,1)	# 根据时间日期生成指定的格式

# 获取本地时间
datetime.date.today()
datetime.datetime.date.today().year
datetime.datetime.date.today().month
datetime.datetime.date.today().day
datetime.datetime.date.today().hour
datetime.datetime.date.today().minute
datetime.datetime.date.today().second
datetime.datetime.date.today().weekday

# 时间推迟和提前
now_day = datetime.date.today()
time_change = datetime.timedelta(days=n)	# n 任意整数
print(now_day + time_change)
print(now_day - time_change)
```