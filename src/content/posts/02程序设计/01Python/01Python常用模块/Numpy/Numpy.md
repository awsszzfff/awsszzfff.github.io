---
title: "Numpy"
date: 2025-02-11
tags:
  - Others
categories:
  - Others
---
科学运算基础库，主要是数组矩阵的运算

```python
pip install numpy
import numpy as np
```

numpy.ndarray 特有类型（类似于列表）

```python
# 属性
.ndim	# 维度
.shape	# 形状
.size	# 个数
.dtype	# 类型
.itemsize	# 元素大小
```

## 创建

```python
# 创建数组 可指定类型，可指定维度，可指定范围等
np.array()
np.arange()	# 0 - n-1的数组
np.zeros()	# 全0
np.zeros_like()
np.ones()	# 全1
np.ones_like()
np.empty()	# 未初始化，随机值
np.empty_like()
np.full(shape, value)	# 全为value
np.full_like()
np.identity()	# 对角线
np.eye()	# 对角线，更多参数
np.linspace()	# 一维数组
np.logspace()	# 对数值，默认log以10为底
```

```python
# np.random	生成随机数 可指定范围，维度等
np.random.seed()	# 随机种子
np.random.random()	# (0.0, 1.0)
np.random.randint()	# 随机整数
np.random.randn()	# 正态分布
np.random.normal()	# 正态分布，可指定期望、方差，维度
np.random.rand()	# 均匀分布
np.random.shuffle()	# 就地随机排列
np.random.permutation()	# 随机排列，不改变原数组
```

## 索引&切片

基本和列表差不多

```python
# 二维为例
nd_[:,:]	# 逗号前后分别是对行和列的操作

```

## 修改形状相关操作

### 修改维度

```python
nd_.reshape()	# 重构指定维度 -1 多维变一维
nd_.ravel()		# 改1维
nd_.flatten()	# 改1维
nd_.size = (n1, n2)	# 改形状
nd_.resize()	# 改形状
```

### 转置

```python
np.transpose()
nd_.T
```

### 拼接

```python
np.concatenate()	# 连接现有轴的数组序列，可指定
np.hastack()	# 水平方向
np.vstack()		# 垂直
np.dstack()		# 相当于三维时，np.concatenate() axis=2
nd1_.extend(nd2_)
```

### 分割

```python
np.split()	# 可指定轴
np.hsplit()	# 水平
np.vsplit()	# 垂直
```

## 运算

```python
np.abs() np.fabs()	# 计算整数、浮点数的绝对值
np.sqrt()			# 计算各元素的平方根
np.reciprocal()		# 计算各元素的倒数
np.square()		# 计算各元素的平方
np.exp()		# 计算各元素的指数ex
np.log() np.log10() np.log2()	# 计算各元素的自然对数、底数为10的对数、底数为2的对数
np.sign()		# 计算各元素的符号，1（整数）、0（零）、-1（负数）
np.ceil() np.floor() # 对各元素分别向上取整、向下取整、
np.rint() np.around()	# 四舍五入 到最近的整数、到指定小数位
np.modf()	# 将各元素的小数部分和整数部分以两个独立的数组返回
np.cos() np.sin() np.tan()	# 对各元素求对应的三角函数
np.add() np.subtract() np.multiply() np.divide()	# 对两个数组的各元素执行加法、减法、乘法、除法
np.mod() np.remainder()	# 一样，都是取模
```

## 统计

```python
np.sum()	# 求和
np.prod()	# 所有元素相乘
np.mean()	# 平均值
np.std()	# 标准差
np.var()	# 方差
np.median()	# 中数
np.power()	# 幂运算
np.sqrt()	# 开方
np.min()	# 最小值
np.max()	# 最大值
np.argmin()	# 最小值的下标
np.argmax() # 最大值的下标
np.cumsum()	# 对数组中元素累积求和，可指定轴
np.cumprod()	# 对数组中元素累积求积，可指定轴
np.ptp()	# 计算一组数中最大值与最小值的差，可指定轴
np.unique()	# 删除数组中的重复数据，并对数据进行排序
np.nonzero()	# 返回数组中非零元素的索引
```

## 其他

```python
np.tile() 		# 按照行列复制扩展
np.repeat() 	# 每个元素重复若干次
np.roll() 		# 沿指定轴对数组元素进行移位
np.place() np.put() 	# 满足条件的元素/指定的元素 替换为指定的值
np.savetxt() 	# 将数据保存到txt文件中
np.loadtxt() 	# 从文件中加载数据
np.genfromtxt() # 根据文件内容中生成数据，可以指定缺失值的处理等
np.any() 	# 如果数组中只要有一个元素为True，则结果返回True
np.all() 	# 如果数组中只有所有元素都为True，则结果返回True
np.where(条件,x,y) 	# 如果条件为True，对应值为x，否则对应值为y
np.dot()	# 点积
np.sort() # 对数组进行排序，返回一个新的排好序的数组，原数组不变
np.argsort() # 返回的是数组值从小到大排序后元素对应的索引值
```

## 广播机制

相加时，维度不匹配，小维度尽量匹配大维度，小维度自动补 1

## 比较掩码

```python
a = np.array([[1, 2, 30], [45, 67, 89]])  
print(a < 60)

[[ True  True  True]
 [ True False False]]
```

> 参考学习
> https://www.runoob.com/numpy/numpy-tutorial.html
> 
> https://numpy123.com/