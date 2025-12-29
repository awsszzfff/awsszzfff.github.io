---
title: "pickle"
date: 2025-07-26
tags:
  - Others
categories:
  - Others
---
```python
import pickle

# 和json模块差不多
# 将python对象转换为二进制数据
pickle.dumps(obj=user_data)

# 将二进制python数据转换为python对象
pickle.loads(user_data_pickle_str)

# 读写数据
with open('data', 'wb') as fp:
	pickle.dump(obj=data, file=fp)

with open('data', 'rb') as fp:
	data = pickle.load(file=fp)
```