---
title: "Time"
date: 2025-07-15
tags:
  - Others
categories:
  - Others
---
> 官方文档： https://docs.python.org/zh-cn/3.12/library/time.html

```python
import time
```

```python
time.sleep()	# 睡眠

time_ = time.time()	# 生成时间戳

time_ = time.gmtime(time.time())	# 国际时间
time_ = time.localtime(time.time())	# 本地时间

time_ = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())	# 转换格式

# 取出年月日时分秒
time_year = time_.tm_year
time_mon = time_.tm_mon
time_mday = time_.tm_mday
time_wday = time_.tm_wday
time_yday = time_.tm_yday

time_ = time.strptime("2024-1-1", "%Y-%m-%d")
# time.struct_time(tm_year=2024, tm_mon=1, tm_mday=1, tm_hour=0, tm_min=0, tm_sec=0, tm_wday=0, tm_yday=1, tm_isdst=-1)

# 转国际时间格式
time_ = time.asctime(time.localtime(time.time()))
time_ = time.ctime(time.time())
```