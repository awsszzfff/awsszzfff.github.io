---
title: "Pandas"
date: 2025-02-10
tags:
  - Others
categories:
  - Others
---
数据读入、清洗、准备、图表呈现等

```python
pip install pandas
import pandas as pd

pd.options.display.max_rows = 10	# 设置输出最多的行
pd.options.display.max_columns = 20	# 设置输出最多的列
```

Series 一维数组与索引名称捆绑

DataFrame 二维数组，行列索引的捆绑

## 创建

```python
# 属性
se_.values
se_.index

df_.index	# 行索引
df_.values
df_.columns	# 列索引
df_.dtypes	
# df_.astype(...) 可用来修改到指定的数据类型

in_.ndim
in_.shape
in_.dtype
in_.size
```

```python
# 可指定 行/列 索引名
pd.Series()	# 创建Series对象

pd.DataFrame()	# 创建DataFrame对象
# eg：
df_ = pd.DataFrame({'se1_': se1_, 'se2_': se2_})

pd.Index()	# Index对象（不可变的一维数组）
```

## 导入文件

```python
# 可指定导入的Sheet、列，行列索引，分隔符等
pd.read_excel()	# 导入excel文件，还需安装openpyxl库
pd.read_csv()	# 导入csv文件
pd.read_table()	# （通用）可导入txt、csv文件

pd.read_sql(sql, con, ...)	# 读sql数据
```

## 保存数据

```python
# 可指定行列索引，分隔符，编码，写模式等
df_.to_csv(...)
df_.to_excel(...)
df_.to_sql(...)
```

## 查看数据

```python
df_.head() df.tail()	# 前/后 几行
df_.info()		# 数据类型
df_.shape()		# 形状（不算索引）
df_.describe()	# 数据分布（均值、方差等）
pd.value_counts()	# 分类变量的频数统计
```

## 基本操作

```python
# 修改列
df_.columns = 新列名
df_.rename(新旧名称字典, ...)

# 筛选列
df_.列名 df_[列名]	# 得到的是Series对象
df_.[[列名1, 列名2]]	# 得到的是DataFrame对象

# 删除列
df_.drop()
del df_[]

# 添加列
df_[new_column] = pd.Series()
df_[new_column] = df_[column1] + df_[column2]

df_.assign(...)	# 向DataFrame中添加新的列，或修改现有列
df_.insert(...)	# 插入新变量列
df_.replace(...)	# 替换
```

## 索引&切片

```python
# 指定某列为索引列
df_.set_index(...)

# 将索引还原变量列
df_.reset_index(...)

# 修改索引
df_.index.name = ''

# 更新索引
df_.reindex(...)	# 可使用数据框中不存在的数据建立索引，NaN自动填充
```

```python
# 切片时可根据默认索引切片，也可以根据指定索引切片
# eg:
se_ = pd.Series(...)
se_['a', 'b']
se_[data > 3]

se_[]	# 索引获取依据指定的索引
se_.loc()	# 同上
se_.iloc()	# 索引获取依据默认索引（0,1,2...）

df_[col_]
df_[[col1_, col2_]]
df_.loc[]
df_.iloc[]
```

```python
df.isin()	# is in? True/False
# 可用来筛选数据
# eg：
df_[df_.isin({  
    'height': [1.83, 1.81],  
    'weight': [83.0, 81.0]  
})]

df_.query(...)	# 类似于对当前表的一个查询语句
# 用来筛选数据
# eg:
df_.query("height < 1.82 and weight > 82.0")	# 如果是变量需添加@符号，eg：h=1.82 写进去就是height < @h
```

## 排序

```python
df_.sort_values(...)
df_.sort_index(...)
```

## 运算

```python
df_.apply(...)	# 指定函数来运算
# eg:
df_.体重.apply(math.sqrt)	# 可用自定义的函数
```

## 其他操作

```python
pd.get_dummies(...)	# 虚拟变量，类似于自动生成one-hot编码，可指定字段


pd.cut(...)			# 数值分段
pd.qcut(...)


df_.groupby(...)	# 数组分组
# eg:
dfg_ = df_.groupby("年龄")
dfg_.groups			# 分组基本数据
dfg_.describe()		# 分组具体描述 
dfg_.get_group("指定分的组").mean() ...[一些计算函数]	# 基于分组进行筛选
dfg_.agg(mean...[一些计算函数])		# 分组汇总
# 之后的版本可以直接调用计算函数，不需要agg，也可用自定义函数

df_.pivot_table()	# 交叉统计，分组、聚合、汇总
pd.crosstab()	# 交叉统计


df_.stack(...)		# 转换为最简格式（简单理解为索引的压缩）
df_.unstack(...)	# 转换，可还原上面
df_.T	# 转置

df1_.append(df2_)	# 纵向合并
pd.merge(...)		# 横向合并
pd.concat(...)		# 支持横向和纵向

df_.shift()			# 数据平移
```

## 处理缺失值

```python
# None NaN
# 查看缺值
df_.isnull() df_.isna()
df_.notnull() df_.notna()
df_.any() df_.all()	# 只要有真，就为真 全为真，才为真

df_.fillna(...)		# 填充缺值
df_.dropna(...)		# 删除缺值（整行/整列）
```

## 数据查重

```python
df_.duplicated()	# 标识出重复的行
df_.drop_duplicates()	# 直接删除重复的行
df_[~df_.duplicated()]	# 利用取反符号来删除重复行
```

## 日期时间

```python
pd.Timestamp()
pd.Peroid()	# 上面的简化说是~
# eg:
pd.Timestamp("2030-1-1")

pd.to_datatime(...)	# 日期转换（和上面那个感觉一样）

pd.Datatimeindex()	# 时间索引
pd.data_range()	# 时间索引
pd.date_range()	pd.bdate_range()	# 后者跳过假期

df_.resample()	# 时间分组
# 对于时间，有许多属性，eg：.year .month .day ...
```

## 数据图形展示

```python
df_.plot(...)

.plot.line  .bar  .pie  .barh  .hist  .box  .kde  .density  .area  .scatter  .hexbin
```

```python
# 加速外挂Linux上为主
numba 和 swifter
```

> 参考学习
> 
> https://www.runoob.com/pandas/pandas-tutorial.html
> 
> https://pandas.liuzaoqi.com/intro.html