---
title: "hashlib"
date: 2025-07-26
tags:
  - Others
categories:
  - Others
---
```python
import hashlib

# 创建一个md5对象
md5 = hashlib.md5()
md5.update(data)	# 原始数据md5加密
md5.hexdigest()	# 加密后的16进制的32长度的字符串
md5.digest()	# 二进制数据
```

加盐：对原始口令加一个复杂字符串来实现

