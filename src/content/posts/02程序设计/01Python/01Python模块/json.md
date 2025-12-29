---
title: "json"
date: 2025-07-15
tags:
  - Others
categories:
  - Others
---
> 官方文档 https://docs.python.org/zh-cn/3/library/json.html

```python
import json
```

```python
dict_ = {
   'username': "admin",
   "password": "123"
}

json.dump(obj=dict_, fp=fp)		# Python对象转json直接写入文件
json.load(fp=fp)		# json转Python对象读取文件

json.dumps()	# Python对象转json直接写入文件
json.loads()	# json转Python对象读取文件
```

