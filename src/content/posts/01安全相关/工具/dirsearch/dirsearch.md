---
title: "dirsearch"
date: 2025-06-24
tags:
  - 工具
categories:
  - 安全相关
---
```shell
python dirsearch.py -u https://example.com -w /path/mydict.txt	# -w 字典
python3 dirsearch.py -u https://example.com -t 100 --delay 0.1	# -t 并发线程数	--delay 每个请求间隔
```