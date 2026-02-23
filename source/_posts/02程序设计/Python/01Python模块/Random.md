---
title: "Random"
date: 2025-07-26
tags:
  - Others
categories:
  - Others
---
```python
import random

# 随机生成小数
random.random()	# 0-1的小数
random.uniform(1, 3)	# 指定区间小数

# 整数
random.randint(1, 5)	# 指定区间
random.randrange(1, 10, 2)	# 给定区间及步长

# 随机返回给定内容中的值
random.choice(num_list)	# 返回一个元素
random.choices(num_list) 	# 返回多个元素，默认返回一个元素列表
random.choices(num_list, k)	# 指定的k个元素数，有放回
random.sample(num_list, k)	# 指定的k个元素数，无放回

random.shuffle(num_list)	# 打乱顺序

```
