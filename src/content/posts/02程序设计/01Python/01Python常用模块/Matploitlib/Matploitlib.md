---
title: "Matploitlib"
date: 2025-02-11
tags:
  - Others
categories:
  - Others
---
```python
pip install matplotlib
import matplotlib.pyplot as plt
```

```python
matplotlib.rcParams['font.sans-serif'] = ['SimHei']	# 设置字体为SimHei，支持中文显示
matplotlib.rcParams['axes.unicode_minus'] = False	# 坐标轴负号显示为正常字符，避免乱码问题
```

## 基本方法

```python
# plt.
title()		# 设置图表的名称
xlabel()	# 设置x轴名称
ylabel()	# 设置y轴名称
xticks(x, ticks, rotation)	# 设置x轴的刻度,rotation旋转角度
yticks()	# 设置y轴的刻度
ylim()		# y轴范围
plot()		# 绘制线性图表
show()		# 显示图表
legend()	# 显示图例
text(x, y, text)		# 显示每条数据的值 x,y值的位置
figure(name, figsize=(w, h), dpi=n)	# 设置图片大小
savefig()	# 保存图片
subplot()	# 画布分区
fig_, ax_ = plt.subplots(neows, ncols)
# eg: ax_[0][0].plot(...)
fill_between(x, y1, y2, color='')	# 填充两条线之间的内容
```

```python
# 图形绘制，可以指定线的粗细，标签文字，图例，字体大小等
fontsize	# 字体大小
label	# 标签
loc		# 图示位置 还可修改边框和样式

# 风格
plt.style.available	# 显示已有风格
plt.style.use('指定风格')

```

```python
# 绘制直线
plt.plot(x, y, ...)
plt.show()

# linewidth	# 线粗细

# 不同种类的线
- -- -. : , o v ^ + 1 2 3 a b c * h ...
# 颜色（首字母）
b g r c m y k w

# eg:
plt.plot(x, y, '-r')
```

```python
# 散点图
plt.scatter()
plt.plot( x, y, 'o')	# 也可绘制散点图

# c颜色，s大小，alpha透明度
```

```python
# 条形图
plt.bar()	# 纵向
plt.barh()	# 横向

# width宽 color
# eg: 负和正用不同的颜色
x=range(5) 
y=[1, -3, 4, -5, 6]
v_bar = plt.bar(x, y, color='lightblue')
for bar, height in zip(v_bar, y):
	if height < 0:
		bar.set(color='lightgreen', linewidth='3')

# 其他一些参数（上面for循环中zip出来的bar）
# 当前柱的宽，高等
bar.get_width()
bar.get_y()
bar.get_height()

# 带方差条形图
plt.bar( , , yerr=variance_)	# 对条形图添加参数
```

```python
# 饼状图
plt.pie()

# autopct百分比 explode裂开
```

```python
# 直方图
plt.hist()
# bins 分组方式和精确程度
```

```python
# 盒图
plt.boxplot()
```

```python
# 三维图
plt.contourf()
# plt.colorbar()	# 添加颜色条以显示等高线图的数值范围

# 需要用到 np.meshgrid(x, y)
# 生成网格数据  
X, Y = np.meshgrid(x, y)

# 需要3d包
from mpl_toolkits.mplot3d import Axes3D
figure=plt.figure()
ax=Axes3D(figure)
ax.plot_surface(X,Y,Z)
```














> 参考学习
> 
> https://www.runoob.com/matplotlib/matplotlib-tutorial.html


