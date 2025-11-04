---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "PythonReview"
---
## 提升代码能力 --- 大量的编程练习和阅读优质的代码
## 运算符

### 例子1：华氏温度转摄氏温度

要求：输入华氏温度将其转换为摄氏温度，华氏温度到摄氏温度的转换公式为：$\small{C = (F - 32) / 1.8}$。

```python
"""
摄氏温度转换为华氏温度
"""

f = float(input("请输入摄氏温度："))
c = (f-32)/1.8
print("%.1f摄氏温度=%.1f华氏温度"%(f,c))
// print(f"{f:.1f}摄氏温度={c:.1f}华氏温度")
```

### 例子2：计算圆的周长和面积

要求：输入一个圆的半径，计算出它的周长$（\small{2 \pi r}）$和面积$（\small{\pi r^{2}}）$。

```python
"""
计算圆的周长和面积
"""

import math
radius = float(input("输入圆的半径："))
perimeter = 2*radius*math.pi
area= math.pi*radius**2
print("半径为%.2f的圆，周长为%.2f，面积为%.2f"%(radius,perimeter,area))
print(f"{perimeter = :.2f}，{area = :.2f}")
```

### 例子3：判断闰年

要求：输入一个1582年以后的年份，判断该年份是不是闰年。

```python
"""
判断闰年
"""

year = int(input("输入年份："))
is_leap_year = year % 4 == 0 and year % 100 != 0 and year % 400 == 0
print(f"{is_leap_year = }")
```

## 分支

### 例子1：分段函数求值

有如下所示的分段函数，要求输入`x`，计算出`y`。

$$  
y = \begin{cases} 3x - 5, & (x \gt 1) \\ x + 2, & (-1 \le x \le 1) \\ 5x + 3, & (x \lt -1) \end{cases}  
$$

```python
"""
分段函数求值
        3x - 5  (x > 1)
f(x) =  x + 2   (-1 <= x <= 1)
        5x + 3  (x < -1)
"""
 
x = int(input("输入x值："))
if x > 1:
    y = 3 * x - 5
elif -1 <= x <= 1:
    y = x + 2
else:
    y = 5 * x + 3
print(f"{y = }")
```

### 例子2：计算三角形的周长和面积。

要求：输入三条边的长度，如果能构成三角形就计算周长和面积；否则给出“不能构成三角形”的提示。

三角形面积的公式叫做海伦公式，假设有一个三角形，边长分别为$\small{a}、\small{b}、\small{c}$，那么三角的面积$\small{A}$可以由下面的公式得到，其中，$\small{s=\frac{a+b+c}{2}}$。

$$  
A = \sqrt{s(s-a)(s-b)(s-c)}  
$$

```python
"""
判断输入的边长能否构成三角形
如果能则计算出三角形的周长和面积
"""

a = float(input("a = "))
b = float(input("b = "))
c = float(input("c = "))

if a + b > c and a + c > b and b + c > a:
    perimeter = a + b + c
    s = perimeter / 2
    area = (s * (s - a) * (s - b) * (s - c)) ** 0.5
	print(f"{perimeter = }，{area = }")
else:
    print("不能构成三角形")
```

## 循环

### 例子1：判断素数

要求：输入一个大于1的正整数，判断它是不是素数。

> **提示**：素数指的是只能被1和自身整除的大于1的整数。例如对于正整数`n`，我们可以通过在`2`到`n-1`之间寻找有没有`n`的因子，来判断它到底是不是一个素数。当然，循环不用从`2`开始到`n-1`结束，因为对于大于1的正整数，因子应该都是成对出现的，所以循环到$\small{\sqrt{n}}$就可以结束了。

```python
"""
输入一个大于1的正整数判断它是不是素数
"""

number = int(input("输入一个整数："))
flag = True
for i in range(2, int(number**0.5) + 1):
    if number % i == 0:
        flag = False
        break
if flag:
    print("%d是素数" % (number))
else:
    print("%d不是素数" % (number))
```

### 例子2：最大公约数

要求：输入两个大于`0`的正整数，求两个数的最大公约数和最小公倍数。

> **提示**：两个数的最大公约数是两个数的公共因子中最大的那个数。

```python
"""
求两个数的最大公约数和最小公倍数。
"""

a = x = int(input("a = "))
b = y = int(input("b = "))
  
while a % b != 0:
    a, b = b, a % b
print(f"{x}和{y}的最大公约数是 {b}")
print(f"{x}和{y}的最小公倍数是 {x*y//b}")
```

### 例子3：猜数字小游戏

要求：计算机出一个`1`到`100`之间的随机数，玩家输入自己猜的数字，计算机给出对应的提示信息“大一点”、“小一点”或“猜对了”，如果玩家猜中了数字，计算机提示用户一共猜了多少次，游戏结束，否则游戏继续。

```python
"""
猜数字小游戏
"""

import random

number = random.randrange(1, 101)
count = 0
while True:
    count += 1
    is_number = int(input("请输入数字："))
    if is_number > number:
        print("小一点")
    elif is_number < number:
        print("大一点")
    else:
        print(f"猜对了，一共猜了{count}次")
        break
```

## 分支+循环

### 例子1：100以内的素数

> **说明**：素数指的是只能被1和自身整除的正整数（不包括1），之前我们写过判断素数的代码，这里相当于是一个升级版本。

```python
"""
输出100以内的素数
"""

print("100以内的素数有：")
for number in range(2, 101):
    flag = True
    for j in range(2, int(number**0.5) + 1):
        if number % j == 0:
            flag = False
            break
    if flag == True:
        print(f"{i}", end=" ")
```

### 例子2：斐波那契数列

要求：输出斐波那契数列中的前20个数。

> **说明**：斐波那契数列（Fibonacci sequence），通常也被称作黄金分割数列，数列的前两个数都是1，从第三个数开始，每个数都是它前面两个数的和。按照这个规律，斐波那契数列的前10个数是：`1, 1, 2, 3, 5, 8, 13, 21, 34, 55`。斐波那契数列在现代物理、准晶体结构、化学等领域都有直接的应用。

```python
"""
输出斐波那契数列的前20个数
1 1 2 3 5 8 13 21 ...
"""

a = 0
b = 1
for _ in range(20):
    a, b = b, a + b
    print(a, end=" ")

```

### 例子3：寻找水仙花数

要求：找出`100`到`999`范围内的所有水仙花数。

> **提示**：在数论中，水仙花数（narcissistic number）也被称为超完全数字不变数、自恋数、自幂数、阿姆斯特朗数，它是一个$\small{N}$位非负整数，其各位数字的$\small{N}$次方和刚好等于该数本身，例如：$\small{153=1^3+5^3+3^3}$，所以`153` 是一个水仙花数；$\small{1634=1^4+6^4+3^4+4^4}$，所以`1634`也是一个水仙花数。对于三位数，解题的关键是将它拆分为个位、十位、百位，再判断是否满足水仙花数的要求，这一点利用Python中的`//`和`%`运算符其实很容易做到。

```python
"""
找出100到999范围内的水仙花数
"""

for number in range(100, 1000):
    high = number // 100
    mid = number % 100 // 10
    low = number % 10
    if number == high**3 + mid**3 + low**3:
        print(number, end=" ")

```

【`%`取余，得到的是后面几位；`//`模除，得到的是前面几位】

正整数进行反转，例如将`12389`变成`98321`

```python
"""
正整数的反转
"""
num = int(input('num = '))
reversed_num = 0
while num > 0:
    reversed_num = reversed_num * 10 + num % 10
    num //= 10
print(reversed_num)
```

### 例子4：百钱百鸡问题

> **说明**：百钱百鸡是我国古代数学家张丘建在《算经》一书中提出的数学问题：鸡翁一值钱五，鸡母一值钱三，鸡雏三值钱一。百钱买百鸡，问鸡翁、鸡母、鸡雏各几何？翻译成现代文是：公鸡5元一只，母鸡3元一只，小鸡1元三只，用100块钱买一百只鸡，问公鸡、母鸡、小鸡各有多少只？

```python
"""
百钱百鸡问题
"""

for x in range(0, 21):
    for y in range(0, 34):
        for z in range(0, 100, 3):
            if x + y + z == 100 and 5 * x + 3 * y + z // 3 == 100:
                print(f'公鸡: {x}只, 母鸡: {y}只, 小鸡: {z}只')

# 优化
for x in range(0, 21):
    for y in range(0, 34):
        z = 100 - x - y
        if z % 3 == 0 and 5 * x + 3 * y + z // 3 == 100:
            print(f'公鸡: {x}只, 母鸡: {y}只, 小鸡: {z}只')         
```

### 例子5：CRAPS赌博游戏

> **说明**：CRAPS又称花旗骰，是美国拉斯维加斯非常受欢迎的一种的桌上赌博游戏。该游戏使用两粒骰子，玩家通过摇两粒骰子获得点数进行游戏。简化后的规则是：玩家第一次摇骰子如果摇出了`7`点或`11`点，玩家胜；玩家第一次如果摇出`2`点、`3`点或`12`点，庄家胜；玩家如果摇出其他点数则游戏继续，玩家重新摇骰子，如果玩家摇出了`7`点，庄家胜；如果玩家摇出了第一次摇的点数，玩家胜；其他点数玩家继续摇骰子，直到分出胜负。为了增加代码的趣味性，我们设定游戏开始时玩家有`1000`元的赌注，每局游戏开始之前，玩家先下注，如果玩家获胜就可以获得对应下注金额的奖励，如果庄家获胜，玩家就会输掉自己下注的金额。游戏结束的条件是玩家破产（输光所有的赌注）。

```python
"""
Craps赌博游戏
"""

import random

money = 1000
while money > 0:
    print(f'你的总资产为: {money}元')
    # 下注金额必须大于0且小于等于玩家的总资产
    while True:
        debt = int(input('请下注: '))
        if 0 < debt <= money:
            break
    # 用两个1到6均匀分布的随机数相加模拟摇两颗色子得到的点数
    first_point = random.randrange(1, 7) + random.randrange(1, 7)
    print(f'\n玩家摇出了{first_point}点')
    if first_point == 7 or first_point == 11:
        print('玩家胜!\n')
        money += debt
    elif first_point == 2 or first_point == 3 or first_point == 12:
        print('庄家胜!\n')
        money -= debt
    else:
        # 如果第一次摇色子没有分出胜负，玩家需要重新摇色子
        while True:
            current_point = random.randrange(1, 7) + random.randrange(1, 7)
            print(f'玩家摇出了{current_point}点')
            if current_point == 7:
                print('庄家胜!\n')
                money -= debt
                break
            elif current_point == first_point:
                print('玩家胜!\n')
                money += debt
                break
print('你破产了, 游戏结束!')
```

## 列表

> **说明**：列表（list）中可以有重复元素，例如`items1`中的`35`；列表中可以有不同类型的元素，但是通常不建议将不同类型的元素放在同一个列表中，主要是操作起来极为不方便。列表式一种可变容器，可变容器指的是我们可以向容器中添加元素、可以从容器移除元素，也可以修改现有容器中的元素。

### 生成及索引等基础操作

`list()`将其他系列变成列表
`+`实现两个列表的拼接
`*`实现列表元素的重复
`in`或`not in`判断一个元素是否在列表中
列表元素可以正向索引和反向索引`[0->N-1]`或`[-1->-N]`，列表切片访问列表中多个元素`[start:end:stride]`
`等于==,!=,<=,>=`

```python
items0 = list(range(1, 10))
items1 = list('hello')
items2 = [35, 12, 99, 45, 66]
items3 = [45, 58, 29]
items4 = ['Python', 'Java', 'JavaScript']

print(items0)  # [1, 2, 3, 4, 5, 6, 7, 8, 9]
print(items1)  # ['h', 'e', 'l', 'l', 'o']
print(items2 + items3)  # [35, 12, 99, 45, 66, 45, 58, 29]
print(items3 + items4)  # [45, 58, 29, 'Python', 'Java', 'JavaScript']
items2 += items3
print(items2)  # [35, 12, 99, 45, 66, 45, 58, 29]
print(items3 * 3)  # [45, 58, 29, 45, 58, 29, 45, 58, 29]
```

### 增删改查
`append()`向列表追加元素
`insert()`向列表插入元素
`remove()`从列表中删除指定元素，若要删除的元素不在列表中，会引发`ValueError`错误导致程序崩溃
`pop()`默认弹出（删除）列表中的最后一个元素，也可弹出指定位置的元素，弹出元素可用变量接收。若索引的值超出了范围，会引发`IndexError`异常，导致程序崩溃
`del`删除指定元素
`clear()`清空列表中的元素
`index()`查找某个元素在列表中的索引位置，若找不到指定的元素，会引发`ValueError`错误
`count（）`统计一个元素在列表中出现的次数
`sort()`实现列表元素的排序
`reverse()`实现元素的反转

```python
# append,insert
languages = ['Python', 'Java', 'C++']
languages.append('JavaScript')
print(languages)  # ['Python', 'Java', 'C++', 'JavaScript']
languages.insert(1, 'SQL')
print(languages)  # ['Python', 'SQL', 'Java', 'C++', 'JavaScript']

# remove,pop,clear
if 'Java' in languages:
    languages.remove('Java')
if 'Swift' in languages:
    languages.remove('Swift')
print(languages)  # ['Python', 'SQL', C++', 'JavaScript']
languages.pop()
temp = languages.pop(1)
print(temp)       # SQL
languages.append(temp)
print(languages)  # ['Python', C++', 'SQL']
languages.clear()
print(languages)  # []
# del
items = ['Python', 'Java', 'C++']
del items[1]
print(items)  # ['Python', 'C++']

# index,count
items = ['Python', 'Java', 'Java', 'C++', 'Kotlin', 'Python']
print(items.index('Python'))     # 0
# 从索引位置1开始查找'Python'
print(items.index('Python', 1))  # 5
print(items.count('Python'))     # 2

# sort,reverse
items = ['Python', 'Java', 'C++', 'Kotlin', 'Swift']
items.sort()
print(items)  # ['C++', 'Java', 'Kotlin', 'Python', 'Swift']
items.reverse()
print(items)  # ['Swift', 'Python', 'Kotlin', 'Java', 'C++']
```

### 列表生成式

```python
# 创建一个取值范围在1到99且能被3或者5整除的数字构成的列表。
items = [i for i in range(1, 100) if i % 3 == 0 or i % 5 == 0]

# 有一个整数列表nums1，创建一个新的列表nums2，nums2中的元素是nums1中对应元素的平方。
nums1 = [35, 12, 97, 64, 55]
nums2 = [num ** 2 for num in nums1]

# 有一个整数列表nums1，创建一个新的列表nums2，将nums1中大于`50`的元素放到nums2中。
nums1 = [35, 12, 97, 64, 55]
nums2 = [num for num in nums1 if num > 50]

#  生成5个学生3门课程的成绩并保存在列表中
import random

scores = [[random.randrange(60, 101) for _ in range(3)] for _ in range(5)]
print(scores)
```

### 例子：双色球随机选号

> **说明**：双色球是由中国福利彩票发行管理中心发售的乐透型彩票，每注投注号码由`6`个红色球和`1`个蓝色球组成。红色球号码从`1`到`33`中选择，蓝色球号码从`1`到`16`中选择。每注需要选择`6`个红色球号码和`1`个蓝色球号码。

```python
"""
双色球随机选号程序
"""
import random

n = int(input('生成几注号码: '))
red_balls = [i for i in range(1, 34)]
blue_balls = [i for i in range(1, 17)]
#  实现随机生成N注号码
for _ in range(n):
    # 从红色球列表中随机抽出6个红色球（无放回抽样）
    selected_balls = random.sample(red_balls, 6)
    # 对选中的红色球排序
    selected_balls.sort()
    # 输出选中的红色球
    for ball in selected_balls:
        print(f'\033[031m{ball:0>2d}\033[0m', end=' ')
    # 从蓝色球列表中随机抽出1个蓝色球
    blue_ball = random.choice(blue_balls)
    # 输出选中的蓝色球
    print(f'\033[034m{blue_ball:0>2d}\033[0m')
```

> **说明**：上面代码中`print(f'\033[0m...\033[0m')`是为了控制输出内容的颜色，红色球输出成红色，蓝色球输出成蓝色。其中省略号代表我们要输出的内容，`\033[0m`是一个控制码，表示关闭所有属性，也就是说之前的控制码将会失效，你也可以将其简单的理解为一个定界符，`m`前面的`0`表示控制台的显示方式为默认值，`0`可以省略，`1`表示高亮，`5`表示闪烁，`7`表示反显等。在`0`和`m`的中间，我们可以写上代表颜色的数字，比如`30`代表黑色，`31`代表红色，`32`代表绿色，`33`代表黄色，`34`代表蓝色等。【不重要，引用别人的，我也没怎么看懂，之后闲了可以学习一下】

## 元组

> **说明**：元组（tuple）是不可变类型，元组类型的变量一旦定义，其中的元素不能再添加或删除，而且元素的值也不能修改。如果试图修改元组中的元素，将引发`TypeError`错误，导致程序崩溃。定义元组通常使用形如`(x, y, z)`的字面量语法，元组类型支持的运算符跟列表是一样的。

### 定义等基础操作

元组同列表均有索引，切片，拼接，成员判断，比较等
元组定义，`()`表示空元组，但是如果元组中只有一个元素，需要加上一个逗号，列如`('hello', )`和`(100, )`才是一元组

```python
# 定义
a = ()
t1 = (35, 12, 98)
```

### 打包和解包

把多个用逗号分隔的值赋给一个变量时，多个值会打包成一个元组类型；把一个元组赋值给多个变量时，元组会解包成多个值然后分别赋给对应的变量。
使用星号表达式可解决变量个数少于元素的个数，星号修饰的变量会变成一个列表，列表中有0个或多个元素；在解包语法中，星号表达式只能出现一次。
【解包语法对列表、range、字符串等所有序列都成立】

```python
# 打包操作
a = 1, 10, 100
print(type(a))  # <class 'tuple'>
print(a)        # (1, 10, 100)
# 解包操作
i, j, k = a
print(i, j, k)  # 1 10 100

# *
a = 1, 10, 100, 1000
i, j, *k = a
print(i, j, k)        # 1 10 [100, 1000]
i, *j, k = a
print(i, j, k)        # 1 [10, 100] 1000

a, b, *c = range(1, 10)
print(a, b, c)        # 1 2 [3, 4, 5, 6, 7, 8, 9]
a, b, c = [1, 10, 100]
print(a, b, c)        # 1 10 100
a, *b, c = "hello"
print(a, b, c)        # h ['e', 'l', 'l'] o
```

## 字符串

> 字符串是不可变类型

### 基础操作

同列表一样都有拼接、切片等操作
字符串中使用`\`可用来转义，若引号外由`r`或`R`开头则为原始字符串，取消转义效果。`\`后可跟八进制、十六进制、Unicode字符编码等

### 大小写

`capitalize()`字符串首字母大写
`title()`字符串每个单词首字母大写
`upper()`字符串变大写
`lower()`字符串变小写
**注**：变换后原字符串值并不发生变化

```python
s1 = 'hello, world!'
# 字符串首字母大写
print(s1.capitalize())  # Hello, world!
# 字符串每个单词首字母大写
print(s1.title())       # Hello, World!
# 字符串变大写
print(s1.upper())       # HELLO, WORLD!
s2 = 'GOODBYE'
# 字符串变小写
print(s2.lower())       # goodbye
# 检查s1和s2的值
print(s1)               # hello, world
print(s2)               # GOODBYE
```

### 查找

`find(),index()`从前往后查找子串，可通过参数指定查找范围，即查找不必从索引为`0`的位置开始。`find`方法找不到指定的字符串会返回`-1`，`index`方法找不到指定的字符串会引发`ValueError`错误。`rfind(),rindex()`逆向查找

```python
s = 'hello, world!'
print(s.find('or'))      # 8
print(s.find('or', 9))   # -1
print(s.find('of'))      # -1
print(s.index('or'))     # 8
print(s.index('or', 9))  # ValueError: substring not found
print(s.rfind('o'))      # 7
print(s.rindex('o'))     # 7
# print(s.rindex('o', 8))  # ValueError: substring not found
```

### 性质判断

`startswith(),endswith()`判断字符串是否以某个字符串开头
`isdigit()`判断是否完全由数字构成
`isalpha()`判断是否完全由字母构成
`isalnum()`判断是否由字母和数字构成

```python
s1 = 'hello, world!'
print(s1.startswith('He'))   # False
print(s1.startswith('hel'))  # True
print(s1.endswith('!'))      # True
s2 = 'abc123456'
print(s2.isdigit())  # False
print(s2.isalpha())  # False
print(s2.isalnum())  # True
```

### 格式化字符串

`center(),ljust(),rjust()`居中，左对齐，右对齐
`zfill()`字符串左侧补零

```python
s = 'hello, world'
print(s.center(20, '*'))  # ****hello, world****
print(s.rjust(20))        #         hello, world
print(s.ljust(20, '~'))   # hello, world~~~~~~~~
print('33'.zfill(5))      # 00033
print('-33'.zfill(5))     # -0033
```

### 修剪替换拆分合并操作

`strip(),lstrip(),rstrip()`修剪左右两端指定字符，修剪左侧，右侧
`replace()`替换，第一个参数是被替换的内容，第二个参数是替换后的内容，还可以通过第三个参数指定替换的次数。
`split()`将一个字符串拆分为多个字符串（放在一个列表中），默认使用空格进行拆分，我们也可以指定其他的字符来拆分字符串，而且还可以指定最大拆分次数来控制拆分的效果。
`join()`将列表中的多个字符串连接成一个字符串

```python
# 修剪
s1 = '   jackfrued@126.com  '
print(s1.strip())      # jackfrued@126.com
s2 = '~你好，世界~'
print(s2.lstrip('~'))  # 你好，世界~
print(s2.rstrip('~'))  # ~你好，世界

# 替换
s = 'hello, good world'
print(s.replace('o', '@'))     # hell@, g@@d w@rld
print(s.replace('o', '@', 1))  # hell@, good world

# 拆分合并
s = 'I love you'
words = s.split()
print(words)            # ['I', 'love', 'you']
print('~'.join(words))  # I~love~you

s = 'I#love#you#so#much'
words = s.split('#')
print(words)  # ['I', 'love', 'you', 'so', 'much']
words = s.split('#', 2)
print(words)  # ['I', 'love', 'you#so#much']
```

### 编码和解码

`encode`按照某种编码方式将字符串编码为字节串
`decode`将字节串解码为字符串

```python
 a = '骆昊'  
 b = a.encode('utf-8')  
 c = a.encode('gbk')  
 print(b)                  # b'\xe9\xaa\x86\xe6\x98\x8a'  
 print(c)                  # b'\xc2\xe6\xea\xbb'  
 print(b.decode('utf-8'))  # 骆昊  
 print(c.decode('gbk'))    # 骆昊
```

注意，如果编码和解码的方式不一致，会导致乱码问题（无法再现原始的内容）或引发`UnicodeDecodeError`错误，导致程序崩溃。

## 集合

> 可变类型，无序不支持索引，不能有重复元素
> 集合中的元素必须是`hashable`类型，使用哈希存储的容器都会对元素提出这一要求。所谓`hashable`类型指的是能够计算出哈希码的数据类型，通常不可变类型都是`hashable`类型，如整数（`int`）、浮点小数（`float`）、布尔值（`bool`）、字符串（`str`）、元组（`tuple`）等。可变类型都不是`hashable`类型，因为可变类型无法计算出确定的哈希码，所以它们不能放到集合中。例如：不能将列表作为集合中的元素；同理，由于集合本身也是可变类型，所以集合也不能作为集合中的元素。我们可以创建出嵌套的列表，但是我们不能创建出嵌套的集合，

### 创建等基础操作

`{},set()`创建集合，`{}`中至少一个元素
也有`in`和`not in`操作
`add()`添加元素
`discard()`删除元素，`remove()`元素不存在会报错，`pop`
`clear()`清空集合
`isdisjoint()`判断两集合是否有相同的元素

```python
# 创建
set1 = {1, 2, 3, 3, 3, 2}
print(set1) # {1, 2, 3}
set5 = {num for num in range(1, 20) if num % 3 == 0 or num % 7 == 0}
print(set5) # {3, 6, 7, 9, 12, 14, 15, 18}

set1 = {1, 10, 100}

# 添加元素
set1.add(1000)
set1.add(10000)
print(set1)  # {1, 100, 1000, 10, 10000}

# 删除元素
set1.discard(10)
if 100 in set1:
    set1.remove(100)
print(set1)  # {1, 1000, 10000}

# 清空元素
set1.clear()
print(set1)  # set()

set1 = {'Java', 'Python', 'C++', 'Kotlin'}
set2 = {'Kotlin', 'Swift', 'Java', 'Dart'}
set3 = {'HTML', 'CSS', 'JavaScript'}
print(set1.isdisjoint(set2))  # False
print(set1.isdisjoint(set3))  # True
```

### 集合的运算

`&`交集运算、`|`并集运算、`-`差集运算、`^`对称差

```python
set1 = {1, 2, 3, 4, 5, 6, 7}
set2 = {2, 4, 6, 8, 10}

# 交集
print(set1 & set2)                      # {2, 4, 6}
print(set1.intersection(set2))          # {2, 4, 6}

# 并集
print(set1 | set2)                      # {1, 2, 3, 4, 5, 6, 7, 8, 10}
print(set1.union(set2))                 # {1, 2, 3, 4, 5, 6, 7, 8, 10}

# 差集
print(set1 - set2)                      # {1, 3, 5, 7}
print(set1.difference(set2))            # {1, 3, 5, 7}

# 对称差
print(set1 ^ set2)                      # {1, 3, 5, 7, 8, 10}
print(set1.symmetric_difference(set2))  # {1, 3, 5, 7, 8, 10}
```

集合的二元运算还可以跟赋值运算一起构成复合赋值运算，例如：`set1 |= set2`相当于`set1 = set1 | set2`，跟`|=`作用相同的方法是`update`；`set1 &= set2`相当于`set1 = set1 & set2`，跟`&=`作用相同的方法是`intersection_update`
比较运算（相等性、子集、超集）

```python
set1 = {1, 3, 5, 7}
set2 = {2, 4, 6}
set3 = {3, 6, 9}
set1 |= set2
# set1.update(set2)
print(set1)  # {1, 2, 3, 4, 5, 6, 7}
set1 &= set3
# set1.intersection_update(set3)
print(set1)  # {3, 6}
set2 -= set1
# set2.difference_update(set1)
print(set2)  # {2, 4}

# 比较运算
set1 = {1, 3, 5}
set2 = {1, 2, 3, 4, 5}
set3 = {5, 4, 3, 2, 1}

print(set1 < set2)   # True 真子集
print(set1 <= set2)  # True 子集
print(set2 < set3)   # False
print(set2 <= set3)  # True
print(set2 > set1)   # True
print(set2 == set3)  # True

print(set1.issubset(set2))    # True 子集
print(set2.issuperset(set1))  # True 超集
```

### 不可变集合

`frozenset`。`set`跟`frozenset`的区别就如同`list`跟`tuple`的区别，`frozenset`由于是不可变类型，能够计算出哈希码，因此它可以作为`set`中的元素。除了不能添加和删除元素，`frozenset`在其他方面跟`set`是一样的，下面的代码简单的展示了`frozenset`的用法。

```python
 fset1 = frozenset({1, 3, 5, 7})  
 fset2 = frozenset(range(1, 6))  
 print(fset1)          # frozenset({1, 3, 5, 7})  
 print(fset2)          # frozenset({1, 2, 3, 4, 5})  
 print(fset1 & fset2)  # frozenset({1, 3, 5})  
 print(fset1 | fset2)  # frozenset({1, 2, 3, 4, 5, 7})  
 print(fset1 - fset2)  # frozenset({7})  
 print(fset1 < fset2)  # False
```

## 字典

> 可变类型

### 创建
`{},dict()`创建字典
`zip()`压缩两个序列并创建字典
也有`in`和`not int`

```python
# dict函数(构造器)中的每一组参数就是字典中的一组键值对
person = dict(name='王大锤', age=55, height=168, weight=60, addr='成都市武侯区科华北路62号1栋101')
print(person)  # {'name': '王大锤', 'age': 55, 'height': 168, 'weight': 60, 'addr': '成都市武侯区科华北路62号1栋101'}

# 可以通过Python内置函数zip压缩两个序列并创建字典
items1 = dict(zip('ABCDE', '12345'))
print(items1)  # {'A': '1', 'B': '2', 'C': '3', 'D': '4', 'E': '5'}
items2 = dict(zip('ABCDE', range(1, 10)))
print(items2)  # {'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5}

# 用字典生成式语法创建字典
items3 = {x: x ** 3 for x in range(1, 6)}
print(items3)  # {1: 1, 2: 8, 3: 27, 4: 64, 5: 125}
```

**字典中的键必须是不可变类型**，例如整数（`int`）、浮点数（`float`）、字符串（`str`）、元组（`tuple`）等类型，这一点跟集合类型对元素的要求是一样的；很显然，之前我们讲的列表（`list`）和集合（`set`）不能作为字典中的键，字典类型本身也不能再作为字典中的键，因为字典也是可变类型，但是字典可以作为字典中的值。

`get()`通过键来获取对应的值，当字典中没有指定的键时不会产生异常，而是返回None或指定的默认值
`keys()`获取字典中所有的键
`values()`获取字典所有的值
`items()`将键和值组装成二元组，通过该方法遍历字典中的元素较为方便
`update()`用一个字典更新另一个字典中的键值
`pop(),popitem()`删除元素，前者会返回键对应的值，但是如果字典中不存在指定的键，会引发`KeyError`错误；后者在删除元素时，会返回键和值组成的二元组。
`clear()`清空字典中所有的键值对
`del`删除指定元素，不存在会报错

```python
person = {'name': '王大锤', 'age': 25, 'height': 178, 'addr': '成都市武侯区科华北路62号1栋101'}
print(person.get('name'))       # 王大锤
print(person.get('sex'))        # None
print(person.get('sex', True))  # True

person = {'name': '王大锤', 'age': 25, 'height': 178}
print(person.keys())    # dict_keys(['name', 'age', 'height'])
print(person.values())  # dict_values(['王大锤', 25, 178])
print(person.items())   # dict_items([('name', '王大锤'), ('age', 25), ('height', 178)])
for key, value in person.items():
    print(f'{key}:\t{value}')

person1 = {'name': '王大锤', 'age': 55, 'height': 178}
person2 = {'age': 25, 'addr': '成都市武侯区科华北路62号1栋101'}
person1.update(person2)
print(person1)  # {'name': '王大锤', 'age': 25, 'height': 178, 'addr': '成都市武侯区科华北路62号1栋101'}

person = {'name': '王大锤', 'age': 25, 'height': 178, 'addr': '成都市武侯区科华北路62号1栋101'}
print(person.pop('age'))  # 25
print(person)             # {'name': '王大锤', 'height': 178, 'addr': '成都市武侯区科华北路62号1栋101'}
print(person.popitem())   # ('addr', '成都市武侯区科华北路62号1栋101')
print(person)             # {'name': '王大锤', 'height': 178}
person.clear()
print(person)             # {}
```

### 例子：统计字母数

要求：输入一段话，统计每个英文字母出现的次数，按出现次数从高到低输出。

```python
"""
统计字母数
"""

sentence = input('请输入一段话: ')
counter = {}
for ch in sentence:
    if 'A' <= ch <= 'Z' or 'a' <= ch <= 'z':
        counter[ch] = counter.get(ch, 0) + 1
sorted_keys = sorted(counter, key=counter.get, reverse=True)
for key in sorted_keys:
    print(f'{key} 出现了 {counter[key]} 次.')
```

## 函数和模块

### 参数

在定义函数时，可以在参数列表中用`/`设置**强制位置参数**（只在3.8版本后被引入），即调用函数时只能按照参数位置来接收参数值的参数；用`*`设置**命名关键字参数**，只能通过“参数名=参数值”的方式来传递和接收参数

```python
# /前面的参数是强制位置参数
def make_judgement(a, b, c, /):
    """判断三条边的长度能否构成三角形"""
    return a + b > c and b + c > a and a + c > b

# 下面的代码会产生TypeError错误，错误信息提示“强制位置参数是不允许给出参数名的”
# TypeError: make_judgement() got some positional-only arguments passed as keyword arguments
# print(make_judgement(b=2, c=3, a=1))

# *后面的参数是命名关键字参数
def make_judgement(*, a, b, c):
    """判断三条边的长度能否构成三角形"""
    return a + b > c and b + c > a and a + c > b


# 下面的代码会产生TypeError错误，错误信息提示“函数没有位置参数但却给了3个位置参数”
# TypeError: make_judgement() takes 0 positional arguments but 3 were given
# print(make_judgement(1, 2, 3))
```

### 默认参数

带默认值的参数必须放在不带默认值参数之后

```python
def add(a=0, b=0, c=0):
    """三个数相加求和"""
    return a + b + c

# 调用add函数，没有传入参数，那么a、b、c都使用默认值0
print(add())         # 0
# 调用add函数，传入一个参数，该参数赋值给变量a, 变量b和c使用默认值0
print(add(1))        # 1
# 调用add函数，传入两个参数，分别赋值给变量a和b，变量c使用默认值0
print(add(1, 2))     # 3
# 调用add函数，传入三个参数，分别赋值给a、b、c三个变量
print(add(1, 2, 3))  # 6
```

### 可变参数

在调用函数时，可以向函数传入`0`个或任意多个参数
`*parameter`接受`0`个或多个普通参数
`**parameter`接收`0`个或多个关键字参数

```python
# 用星号表达式来表示args可以接收0个或任意多个参数
# 调用函数时传入的n个参数会组装成一个n元组赋给args
# 如果一个参数都没有传入，那么args会是一个空元组
def add(*args):
    total = 0
    # 对保存可变参数的元组进行循环遍历
    for val in args:
        # 对参数进行了类型检查（数值型的才能求和）
        if type(val) in (int, float):
            total += val
    return total


# 在调用add函数时可以传入0个或任意多个参数
print(add())         # 0
print(add(1))        # 1
print(add(1, 2, 3))  # 6
print(add(1, 2, 'hello', 3.45, 6))  # 12.45

# 参数列表中的**kwargs可以接收0个或任意多个关键字参数
# 调用函数时传入的关键字参数会组装成一个字典（参数名是字典中的键，参数值是字典中的值）
# 如果一个关键字参数都没有传入，那么kwargs会是一个空字典
def foo(*args, **kwargs):
    print(args)
    print(kwargs)


foo(3, 2.1, True, name='骆昊', age=43, gpa=4.95)
```

### 模块

`import`关键字导入指定的模块再使用**完全限定名**（`模块名.函数名`）的调用方式，就可以区分到底要使用的是哪个模块中的`foo`函数，代码如下所示。

`module1.py`

```python
 def foo():  
     print('hello, world!')
```

`module2.py`
```python
 def foo():  
     print('goodbye, world!')
```

`test.py`
```python
 import module1  
 import module2  
 ​  
 # 用“模块名.函数名”的方式（完全限定名）调用函数，  
 module1.foo()  # hello, world!  
 module2.foo()  # goodbye, world!
```

```python
# 导入模块
impor math
math.factorial(n)

# 另一种方法
from math import factorial as f # 直接导入math中的factorial
factorial(n)

# as起别名
import math as m
m.factorial(n)

from math import factorial as f # 直接导入math中的factorial并起别名为f
f(n)
```

函数参数处加`:`和参数类型，后面加`->`和返回值类型

> **说明**：如下`is_prime`函数的参数`num`后面的`: int`用来标注参数的类型，虽然它对代码的执行结果不产生任何影响，但是很好的增强了代码的可读性。同理，参数列表后面的`-> bool`用来标注函数返回值的类型，它也不会对代码的执行结果产生影响，但是却让我们清楚的知道，调用函数会得到一个布尔值，要么是`True`，要么是`False`。

```python
def is_prime(num: int) -> bool:
	...
```

### 案例：生成随机验证码

设计一个生成随机验证码的函数，验证码由数字和英文大小写字母构成，长度可以通过参数设置。

```python
import random
import string

ALL_CHARS = string.digits + string.ascii_letters


def generate_code(*, code_len=4):
    """
    生成指定长度的验证码
    :param code_len: 验证码的长度(默认4个字符)
    :return: 由大小写英文字母和数字构成的随机验证码字符串
    """
    return "".join(random.choices(ALL_CHARS, k=code_len))

for _ in range(5):
    print(generate_code())

for _ in range(5):
    print(generate_code(code_len=6))
```

### 高阶函数：函数的参数是一个函数

```python
def is_even(num):
    """判断num是不是偶数"""
    return num % 2 == 0


def square(num):
    """求平方"""
    return num ** 2

# map实现对序列中元素的映射，filter实现对序列中元素的过滤
old_nums = [35, 12, 8, 99, 60, 52]
new_nums = list(map(square, filter(is_even, old_nums)))
print(new_nums)  # [144, 64, 3600, 2704]
```

### Lambda匿名函数

用 lambda 替换上面的`is_even`和`square`函数
定义 lambda 函数的关键字是`lambda`，后面跟函数的参数，如果有多个参数用逗号进行分隔；冒号后面的部分就是函数的执行体，通常是一个表达式，表达式的运算结果就是 lambda 函数的返回值，不需要写`return` 关键字

```python
old_nums = [35, 12, 8, 99, 60, 52]
new_nums = list(map(lambda x: x ** 2, filter(lambda x: x % 2 == 0, old_nums)))
print(new_nums)  # [144, 64, 3600, 2704]
```

### 偏函数

**偏函数是指固定函数的某些参数，生成一个新的函数**，这样就无需在每次调用函数时都传递相同的参数。使用`functools`模块的`partial`函数来创建偏函数。
例如，`int`函数在默认情况下可以将字符串视为十进制整数进行类型转换，如果我们修修改它的`base`参数，就可以定义出三个新函数，分别用于将二进制、八进制、十六进制字符串转换为整数。

```python
import functools  
 ​  
int2 = functools.partial(int, base=2)  
int8 = functools.partial(int, base=8)  
int16 = functools.partial(int, base=16)  
 
print(int('1001'))    # 1001  
 ​  
print(int2('1001'))   # 9  
print(int8('1001'))   # 513  
print(int16('1001'))  # 4097
```

`partial`函数的第一个参数和返回值都是函数，它将传入的函数**处理成一个新的函数返回**。通过构造偏函数，可以结合实际的使用场景将原函数变成使用起来更为便捷的新函数

### 装饰器

函数的参数和返回值都是一个函数

`record_time`函数的参数`func`代表了一个被装饰的函数，函数里面定义的`wrapper`函数是带有装饰功能的函数，它会执行被装饰的函数`func`，它还需要返回在最后产生函数执行的返回值。`record_time`函数最终会返回这个带有装饰功能的函数`wrapper`并通过它替代原函数`func`，**当原函数`func`被`record_time`函数装饰后，我们调用它时其实调用的是`wrapper`函数，所以才获得了额外的能力。**`wrapper`函数的参数比较特殊，由于我们要用`wrapper`替代原函数`func`，但是我们又不清楚原函数`func`会接受哪些参数，所以我们就通过可变参数和关键字参数照单全收，然后在调用`func`的时候，原封不动的全部给它。
【这里还要强调一下，Python 语言支持函数的嵌套定义，就像上面，我们可以在`record_time`函数中定义`wrapper`函数，这个操作在很多编程语言中并不被支持。】

```python
# 构造计算一个函数执行时间的装饰器
import time

def record_time(func):

    def wrapper(*args, **kwargs):
        # 在执行被装饰的函数之前记录开始时间
        start = time.time()
        # 执行被装饰的函数并获取返回值
        result = func(*args, **kwargs)
        # 在执行被装饰的函数之后记录结束时间
        end = time.time()
        # 计算和显示被装饰函数的执行时间
        print(f'{func.__name__}执行时间: {end - start:.2f}秒')
        # 返回被装饰函数的返回值
        return result
    
    return wrapper
```

使用装饰器很有更为便捷的**语法糖**（编程语言中添加的某种语法，这种语法对语言的功能没有影响，但是使用更加方法，代码的可读性也更强，我们将其称之为“语法糖”或“糖衣语法”），可以用`@装饰器函数`将装饰器函数直接放在被装饰的函数上，效果跟上面的代码相同。

```python
# 模拟计算文件操作时间的程序
import random
import time

def record_time(func):

    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f'{func.__name__}执行时间: {end - start:.2f}秒')
        return result

    return wrapper

@record_time
def download(filename):
    print(f'开始下载{filename}.')
    time.sleep(random.random() * 6)
    print(f'{filename}下载完成.')

@record_time
def upload(filename):
    print(f'开始上传{filename}.')
    time.sleep(random.random() * 8)
    print(f'{filename}上传完成.')

download('MySQL从删库到跑路.avi')
upload('Python从入门到住院.pdf')
```

当想去掉装饰器的作用执行原函数，则在定义装饰器函数的时，可使用Python 标准库`functools`模块的`wraps`函数也是一个装饰器，将它放在`wrapper`函数上，该装饰器可以帮我们保留被装饰之前的函数，这样在需要取消装饰器时，可以通过被装饰函数的`__wrapped__`属性获得被装饰之前的函数。

```python
import random
import time

from functools import wraps


def record_time(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f'{func.__name__}执行时间: {end - start:.2f}秒')
        return result

    return wrapper


@record_time
def download(filename):
    print(f'开始下载{filename}.')
    time.sleep(random.random() * 6)
    print(f'{filename}下载完成.')


@record_time
def upload(filename):
    print(f'开始上传{filename}.')
    time.sleep(random.random() * 8)
    print(f'{filename}上传完成.')


# 调用装饰后的函数会记录执行时间
download('MySQL从删库到跑路.avi')
upload('Python从入门到住院.pdf')
# 取消装饰器的作用不记录执行时间
download.__wrapped__('MySQL必知必会.pdf')
upload.__wrapped__('Python从新手到大师.pdf')
```

### 递归调用

Python默认递归层数1000层，可以使用`sys`模块的`setrecursionlimit`函数来改变递归调用的最大深度，但不建议。

```python
# 斐波那契数的递归
from functools import lru_cache

@lru_cache()
def fib1(n):
    if n in (1, 2):
        return 1
    return fib1(n - 1) + fib1(n - 2)

for i in range(1, 51):
    print(i, fib1(i))
```

可使用`functools`模块的`lru_cache`函数来优化递归代码。`lru_cache`函数是一个装饰器函数，将其置于上面的函数`fib1`之上，它可以缓存该函数的执行结果从而避免在递归调用的过程中产生大量的重复运算，这样代码的执行性能就有“飞一般”的提升。

> **提示**：`lru_cache`函数是一个带参数的装饰器，所以上面第4行代码使用装饰器语法糖时，`lru_cache`后面要跟上圆括号。`lru_cache`函数有一个非常重要的参数叫`maxsize`，它可以用来定义缓存空间的大小，默认值是128。

## 面向对象

> **面向对象编程**：把一组数据和处理数据的方法组成**对象**，把行为相同的对象归纳为**类**，通过**封装**隐藏对象的内部细节，通过**继承**实现类的特化和泛化，通过**多态**实现基于对象类型的动态分派。
> **类是对象的蓝图和模板，对象是类的实例，是可以接受消息的实体**。

### 类和对象的基本操作

#### 定义和调用

`class`定义类，在类里面的函数称为方法，方法即对象的行为，也就是对象可以接收的消息。方法的第一个参数通常都是`self`，它代表了接收这个消息的对象本身。

```python
class Student:

    def study(self, course_name):
        print(f'学生正在学习{course_name}.')

    def play(self):
        print(f'学生正在玩游戏.')

stu1 = Student() # 创建学生对象
stu2 = Student()
print(stu1)    # <__main__.Student object at 0x10ad5ac50>
print(stu2)    # <__main__.Student object at 0x10ad5acd0> 
print(hex(id(stu1)), hex(id(stu2)))    # 0x10ad5ac50 0x10ad5acd0
```

类名后加括号即构造器语法。用`id`函数查看对象标识获得的值是相同的，这是因为定义的变量保存的是一个对象的逻辑地址，`stu3 = stu2`这样的赋值语句并未创建新的对象，只是用新的变量保存了已有对象的地址。

```python
# 通过“类.方法”调用方法
# 第一个参数是接收消息的对象
# 第二个参数是学习的课程名称
Student.study(stu1, 'Python程序设计')    # 学生正在学习Python程序设计.

# 通过“对象.方法”调用方法
# 点前面的对象就是接收消息的对象
# 只需要传入第二个参数课程名称
stu1.study('Python程序设计')             # 学生正在学习Python程序设计.

Student.play(stu2)                      # 学生正在玩游戏.
stu2.play()                             # 学生正在玩游戏. 
```

#### 初始化方法

上面创建的学生对象只有行为没有属性，可添加`__init__`方法，调用`Student`类的构造器创建对象时，首先会在内存中获得保存学生对象所需的内存空间，然后通过自动执行`__init__`方法，完成对内存的初始化操作，即把数据放到内存空间中。

```python
class Student:
    """学生"""

    def __init__(self, name, age):
        """初始化方法"""
        self.name = name
        self.age = age

    def study(self, course_name):
        """学习"""
        print(f'{self.name}正在学习{course_name}.')

    def play(self):
        """玩耍"""
        print(f'{self.name}正在玩游戏.')

# 调用Student类的构造器创建对象并传入初始化参数
stu1 = Student('骆昊', 44)
stu2 = Student('王大锤', 25)
stu1.study('Python程序设计')    # 骆昊正在学习Python程序设计.
stu2.play()                    # 王大锤正在玩游戏.
```

### 案例1：定义一个类描述数字时钟

```python
import time


# 定义时钟类
class Clock:
    """数字时钟"""

    def __init__(self, hour=0, minute=0, second=0):
        """初始化方法
        :param hour: 时
        :param minute: 分
        :param second: 秒
        """
        self.hour = hour
        self.min = minute
        self.sec = second

    def run(self):
        """走字"""
        self.sec += 1
        if self.sec == 60:
            self.sec = 0
            self.min += 1
            if self.min == 60:
                self.min = 0
                self.hour += 1
                if self.hour == 24:
                    self.hour = 0

    def show(self):
        """显示时间"""
        return f'{self.hour:0>2d}:{self.min:0>2d}:{self.sec:0>2d}'


# 创建时钟对象
clock = Clock(23, 59, 58)
while True:
    # 给时钟对象发消息读取时间
    print(clock.show())
    # 休眠1秒钟
    time.sleep(1)
    # 给时钟对象发消息使其走字
    clock.run()
```

### 案例2：定义一个类描述平面上的点，要求提供计算到另一个点距离的方法

```python
class Point:
    """平面上的点"""

    def __init__(self, x=0, y=0):
        """初始化方法
        :param x: 横坐标
        :param y: 纵坐标
        """
        self.x, self.y = x, y

    def distance_to(self, other):
        """计算与另一个点的距离
        :param other: 另一个点
        """
        dx = self.x - other.x
        dy = self.y - other.y
        return (dx * dx + dy * dy) ** 0.5

    def __str__(self):
        return f'({self.x}, {self.y})'


p1 = Point(3, 5)
p2 = Point(6, 9)
print(p1)  # 调用对象的__str__魔法方法
print(p2)
print(p1.distance_to(p2))
```

### 面向对象进阶操作

封装：**隐藏一切可以隐藏的实现细节，只向外界暴露简单的调用接口**。

#### 可见性属性装饰器

对象的属性通常会被设置为私有（private）或受保护（protected）的成员，简单的说就是不允许直接访问这些属性。Python 中，可以通过给对象属性名添加前缀下划线的方式来说明属性的访问可见性，例如，可以用`__name`表示一个私有属性，`_name`表示一个受保护属性。

```python
class Student:

    def __init__(self, name, age):
        self.__name = name
        self.__age = age

    def study(self, course_name):
        print(f'{self.__name}正在学习{course_name}.')


stu = Student('王大锤', 20)
stu.study('Python程序设计')
print(stu.__name)  # AttributeError: 'Student' object has no attribute '__name'
```

虽然是私有属性但依旧可以通过`stu._Student__name`的方式来访问私有属性`__name`，Python并未作出严格的限定。

#### 动态属性

Python 可以动态添加属性，也可用`__slots__`魔术方法来限制动态添加属性。对于`Student`类来说，可以在类中指定`__slots__ = ('name', 'age')`，这样`Student`类的对象只能有`name`和`age`属性，如果想动态添加其他属性将会引发异常

```python
# 允许动态添加属性
class Student:

    def __init__(self, name, age):
        self.name = name
        self.age = age


stu = Student('王大锤', 20)
stu.sex = '男'  # 给学生对象动态添加sex属性

# 不允许动态添加属性
class Student:
    __slots__ = ('name', 'age')

    def __init__(self, name, age):
        self.name = name
        self.age = age


stu = Student('王大锤', 20)
# AttributeError: 'Student' object has no attribute 'sex'
stu.sex = '男'
```

#### 静态方法和类方法

两个没有实质区别，静态方法和类方法就是发送给类的消息。而以上定义的方法是发送给对象的消息。

`staticmethod`装饰器声明类的静态方法
`classmethod`装饰器声明类方法
可以直接使用`类名.方法名`的方式来调用静态方法和类方法，二者的区别在于，类方法的第一个参数是类对象本身，而静态方法则没有这个参数。
简单的总结一下，**对象方法、类方法、静态方法都可以通过“类名.方法名”的方式来调用，区别在于方法的第一个参数到底是普通对象还是类对象，还是没有接受消息的对象**。

```python
# 当进行三角形周长和面积时，需要先判断是否是三角形，这一判断显然不是对象方法，因为在调用这个方法时三角形对象还没有创建出来。因此设为静态或类方法
class Triangle(object):
    """三角形"""

    def __init__(self, a, b, c):
        """初始化方法"""
        self.a = a
        self.b = b
        self.c = c

    @staticmethod
    def is_valid(a, b, c):
        """判断三条边长能否构成三角形(静态方法)"""
        return a + b > c and b + c > a and a + c > b

    # @classmethod
    # def is_valid(cls, a, b, c):
    #     """判断三条边长能否构成三角形(类方法)"""
    #     return a + b > c and b + c > a and a + c > b

    def perimeter(self):
        """计算周长"""
        return self.a + self.b + self.c

    def area(self):
        """计算面积"""
        p = self.perimeter() / 2
        return (p * (p - self.a) * (p - self.b) * (p - self.c)) ** 0.5
```

补充，可添加一个`property`装饰器，这样三角形类的`perimeter`和`area`就变成了两个属性，不再通过调用方法的方式来访问，而是用对象访问属性的方式直接获得。

```python
class Triangle(object):
    """三角形"""

    def __init__(self, a, b, c):
        """初始化方法"""
        self.a = a
        self.b = b
        self.c = c

    @staticmethod
    def is_valid(a, b, c):
        """判断三条边长能否构成三角形(静态方法)"""
        return a + b > c and b + c > a and a + c > b

    @property
    def perimeter(self):
        """计算周长"""
        return self.a + self.b + self.c

    @property
    def area(self):
        """计算面积"""
        p = self.perimeter / 2
        return (p * (p - self.a) * (p - self.b) * (p - self.c)) ** 0.5


t = Triangle(3, 4, 5)
print(f'周长: {t.perimeter}')
print(f'面积: {t.area}')
```

#### 继承和多态

在已有类基础上创建新类。

继承的语法是在定义类的时候，在类名后的圆括号中指定当前类的父类。如果定义一个类的时候没有指定它的父类是谁，那么默认的父类是`object`类（Python的顶级类）。

```python
# 先定义人类，再通过继承，从人类的基础上派生出学生类和老师类
class Person:
    """人"""

    def __init__(self, name, age):
        self.name = name
        self.age = age
    
    def eat(self):
        print(f'{self.name}正在吃饭.')
    
    def sleep(self):
        print(f'{self.name}正在睡觉.')


class Student(Person):
    """学生"""
    
    def __init__(self, name, age):
        super().__init__(name, age)
    
    def study(self, course_name):
        print(f'{self.name}正在学习{course_name}.')


class Teacher(Person):
    """老师"""

    def __init__(self, name, age, title):
        super().__init__(name, age)
        self.title = title
    
    def teach(self, course_name):
        print(f'{self.name}{self.title}正在讲授{course_name}.')



stu1 = Student('白元芳', 21)
stu2 = Student('狄仁杰', 22)
tea1 = Teacher('武则天', 35, '副教授')
stu1.eat()
stu2.sleep()
tea1.eat()
stu1.study('Python程序设计')
tea1.teach('Python程序设计')
stu2.study('数据科学导论')
```

Python可多重继承，一个类继承多个类。子类初始化方法可通过`super().__init__()`来调用父类初始化方法。`super`函数是 Python 内置函数中专门为获取当前对象的父类对象而设计的。

子类继承父类的方法后，还可以对方法进行重写（重新实现该方法），不同的子类可以对父类的同一个方法给出不同的实现版本，

### 案例1：扑克游戏。

> **说明**：简单起见，我们的扑克只有52张牌（没有大小王），游戏需要将52张牌发到4个玩家的手上，每个玩家手上有13张牌，按照黑桃、红心、草花、方块的顺序和点数从小到大排列，暂时不实现其他的功能。

使用面向对象编程方法，首先需要从问题的需求中找到对象并抽象出对应的类，此外还要找到对象的属性和行为。当然，这件事情并不是特别困难，我们可以从需求的描述中找出名词和动词，名词通常就是对象或者是对象的属性，而动词通常是对象的行为。扑克游戏中至少应该有三类对象，分别是牌、扑克和玩家，牌、扑克、玩家三个类也并不是孤立的。类和类之间的关系可以粗略的分为**is-a关系（继承）**、**has-a关系（关联）**和**use-a关系（依赖）**。很显然扑克和牌是has-a关系，因为一副扑克有（has-a）52张牌；玩家和牌之间不仅有关联关系还有依赖关系，因为玩家手上有（has-a）牌而且玩家使用了（use-a）牌。

牌的属性显而易见，有花色和点数。我们可以用0到3的四个数字来代表四种不同的花色，但是这样的代码可读性会非常糟糕，因为我们并不知道黑桃、红心、草花、方块跟0到3的数字的对应关系。如果一个变量的取值只有有限多个选项，我们可以使用枚举。与 C、Java 等语言不同的是，Python 中没有声明枚举类型的关键字，但是可以通过继承`enum`模块的`Enum`类来创建枚举类型，代码如下所示。

```Python
from enum import Enum


class Suite(Enum):
    """花色(枚举)"""
    SPADE, HEART, CLUB, DIAMOND = range(4)
```

通过上面的代码可以看出，定义枚举类型其实就是定义符号常量，如`SPADE`、`HEART`等。每个符号常量都有与之对应的值，这样表示黑桃就可以不用数字`0`，而是用`Suite.SPADE`；同理，表示方块可以不用数字`3`， 而是用`Suite.DIAMOND`。注意，使用符号常量肯定是优于使用字面常量的，因为能够读懂英文就能理解符号常量的含义，代码的可读性会提升很多。Python 中的枚举类型是可迭代类型，简单的说就是可以将枚举类型放到`for-in`循环中，依次取出每一个符号常量及其对应的值，如下所示。

```Python
for suite in Suite:
    print(f'{suite}: {suite.value}')
```

接下来我们可以定义牌类。

```Python
class Card:
    """牌"""

    def __init__(self, suite, face):
        self.suite = suite
        self.face = face

    def __repr__(self):
        suites = '♠♥♣♦'
        faces = ['', 'A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']
        return f'{suites[self.suite.value]}{faces[self.face]}'  # 返回牌的花色和点数
```

可以通过下面的代码来测试下`Card`类。

```Python
card1 = Card(Suite.SPADE, 5)
card2 = Card(Suite.HEART, 13)
print(card1)  # ♠5 
print(card2)  # ♥K
```

接下来我们定义扑克类。

```Python
import random


class Poker:
    """扑克"""

    def __init__(self):
        self.cards = [Card(suite, face) 
                      for suite in Suite
                      for face in range(1, 14)]  # 52张牌构成的列表
        self.current = 0  # 记录发牌位置的属性

    def shuffle(self):
        """洗牌"""
        self.current = 0
        random.shuffle(self.cards)  # 通过random模块的shuffle函数实现随机乱序

    def deal(self):
        """发牌"""
        card = self.cards[self.current]
        self.current += 1
        return card

    @property
    def has_next(self):
        """还有没有牌可以发"""
        return self.current < len(self.cards)
```

可以通过下面的代码来测试下`Poker`类。

```Python
poker = Poker()
print(poker.cards)  # 洗牌前的牌
poker.shuffle()
print(poker.cards)  # 洗牌后的牌
```

定义玩家类。

```Python
class Player:
    """玩家"""

    def __init__(self, name):
        self.name = name
        self.cards = []  # 玩家手上的牌

    def get_one(self, card):
        """摸牌"""
        self.cards.append(card)

    def arrange(self):
        """整理手上的牌"""
        self.cards.sort()
```

创建四个玩家并将牌发到玩家的手上。

```Python
poker = Poker()
poker.shuffle()
players = [Player('东邪'), Player('西毒'), Player('南帝'), Player('北丐')]
# 将牌轮流发到每个玩家手上每人13张牌
for _ in range(13):
    for player in players:
        player.get_one(poker.deal())
# 玩家整理手上的牌输出名字和手牌
for player in players:
    player.arrange()
    print(f'{player.name}: ', end='')
    print(player.cards)
```

执行上面的代码会在`player.arrange()`那里出现异常，因为`Player`的`arrange`方法使用了列表的`sort`对玩家手上的牌进行排序，排序需要比较两个`Card`对象的大小，而`<`运算符又不能直接作用于`Card`类型，所以就出现了`TypeError`异常，异常消息为：`'<' not supported between instances of 'Card' and 'Card'`。

为了解决这个问题，我们可以对`Card`类的代码稍作修改，使得两个`Card`对象可以直接用`<`进行大小的比较。这里用到技术叫**运算符重载**，Python 中要实现对`<`运算符的重载，需要在类中添加一个名为`__lt__`的魔术方法。很显然，魔术方法`__lt__`中的`lt`是英文单词“less than”的缩写，以此类推，魔术方法`__gt__`对应`>`运算符，魔术方法`__le__`对应`<=`运算符，`__ge__`对应`>=`运算符，`__eq__`对应`等于==`运算符，`__ne__`对应`!=`运算符。

修改后的`Card`类代码如下所示。

```Python
class Card:
    """牌"""

    def __init__(self, suite, face):
        self.suite = suite
        self.face = face

    def __repr__(self):
        suites = '♠♥♣♦'
        faces = ['', 'A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']
        return f'{suites[self.suite.value]}{faces[self.face]}'
    
    def __lt__(self, other):
        if self.suite == other.suite:
            return self.face < other.face   # 花色相同比较点数的大小
        return self.suite.value < other.suite.value   # 花色不同比较花色对应的值
```

完整代码

```python
from enum import Enum
import random

class Suite(Enum):
    """花色（枚举）"""

    SPADE, HEART, CLUB, DIAMOND = range(4)

# 对枚举类型的遍历
# for suite in Suite:
#     print(f"{suite}:{suite.value}")

class Card:
    """牌"""

    def __init__(self, suite, face):
        self.suite = suite
        self.face = face

    def __repr__(self):
        suites = "♠♥♣♦"
        faces = ["", "A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"]
        return f"{suites[self.suite.value]}{faces[self.face]}"

    def __lt__(self, other):
        if self.suite == other.suite:
            return self.face < other.face  # 花色相同比较点数的大小
        return self.suite.value < other.suite.value  # 花色不同比较对应的值

# 测试牌类
# card1 = Card(Suite.SPADE, 5)
# card2 = Card(Suite.HEART, 13)
# print(card1)
# print(card2)

class Poker:
    """扑克"""

    def __init__(self):
        self.cards = [
            Card(suite, face) for suite in Suite for face in range(1, 14)
        ]  # 52张牌构成的列表
        self.current = 0  # 记录发牌位置的属性

    def shuffle(self):
        """洗牌"""
        self.current = 0
        random.shuffle(self.cards)  # 通过random中的shuffle函数实现随机乱序

    def deal(self):
        """发牌"""
        card = self.cards[self.current]
        self.current += 1
        return card

    @property
    def has_next(self):
        """还有没有牌可发"""
        return self.current < len(self.cards)

# poker = Poker()
# print(poker.cards)  # 洗牌前的牌
# poker.shuffle()
# print(poker.cards)  #  洗牌后的牌

class Player:
    """玩家"""

    def __init__(self, name):
        self.name = name
        self.cards = []  # 玩家的手牌

    def get_one(self, card):
        """摸牌"""
        self.cards.append(card)

    def arrange(self):
        """整理手上的牌"""
        self.cards.sort()

poker = Poker()
poker.shuffle()
players = [Player("东邪"), Player("西毒"), Player("南帝"), Player("北丐")]
# 将牌轮流发到每个玩家的手中
for _ in range(13):
    for player in players:
        player.get_one(poker.deal())
# 玩家整理手上的牌输出名字和手牌
for player in players:
    player.arrange()
    print(f"{player.name}:", end="")
    print(player.cards)
```


### 案例2：工资结算系统

> **要求**：某公司有三种类型的员工，分别是部门经理、程序员和销售员。需要设计一个工资结算系统，根据提供的员工信息来计算员工的月薪。其中，部门经理的月薪是固定15000元；程序员按工作时间（以小时为单位）支付月薪，每小时200元；销售员的月薪由1800元底薪加上销售额5%的提成两部分构成。

通过对上述需求的分析，可以看出部门经理、程序员、销售员都是员工，有相同的属性和行为，那么我们可以先设计一个名为`Employee`的父类，再通过继承的方式从这个父类派生出部门经理、程序员和销售员三个子类。很显然，后续的代码不会创建`Employee` 类的对象，因为我们需要的是具体的员工对象，所以这个类可以设计成专门用于继承的抽象类。Python 语言中没有定义抽象类的关键字，但是可以通过`abc`模块中名为`ABCMeta` 的元类来定义抽象类。关于元类的概念此处不展开讲解，当然大家不用纠结，照做即可。

```Python
from abc import ABCMeta, abstractmethod


class Employee(metaclass=ABCMeta):
    """员工"""

    def __init__(self, name):
        self.name = name

    @abstractmethod
    def get_salary(self):
        """结算月薪"""
        pass
```

在上面的员工类中，有一个名为`get_salary`的方法用于结算月薪，但是由于还没有确定是哪一类员工，所以结算月薪虽然是员工的公共行为但这里却没有办法实现。对于暂时无法实现的方法，我们可以使用`abstractmethod`装饰器将其声明为抽象方法，所谓**抽象方法就是只有声明没有实现的方法**，**声明这个方法是为了让子类去重写这个方法**。接下来的代码展示了如何从员工类派生出部门经理、程序员、销售员这三个子类以及子类如何重写父类的抽象方法。

```Python
class Manager(Employee):
    """部门经理"""

    def get_salary(self):
        return 15000.0


class Programmer(Employee):
    """程序员"""

    def __init__(self, name, working_hour=0):
        super().__init__(name)
        self.working_hour = working_hour

    def get_salary(self):
        return 200 * self.working_hour


class Salesman(Employee):
    """销售员"""

    def __init__(self, name, sales=0):
        super().__init__(name)
        self.sales = sales

    def get_salary(self):
        return 1800 + self.sales * 0.05
```

上面的`Manager`、`Programmer`、`Salesman`三个类都继承自`Employee`，三个类都分别重写了`get_salary`方法。**重写就是子类对父类已有的方法重新做出实现**。相信大家已经注意到了，三个子类中的`get_salary`各不相同，所以这个方法在程序运行时会产生**多态行为**，多态简单的说就是**调用相同的方法**，**不同的子类对象做不同的事情**。

我们通过下面的代码来完成这个工资结算系统，由于程序员和销售员需要分别录入本月的工作时间和销售额，所以在下面的代码中我们使用了 Python 内置的`isinstance`函数来判断员工对象的类型。我们之前讲过的`type`函数也能识别对象的类型，但是`isinstance`函数更加强大，因为它可以判断出一个对象是不是某个继承结构下的子类型，你可以简单的理解为`type`函数是对对象类型的精准匹配，而`isinstance`函数是对对象类型的模糊匹配。

```Python
emps = [Manager('刘备'), Programmer('诸葛亮'), Manager('曹操'), Programmer('荀彧'), Salesman('张辽')]
for emp in emps:
    if isinstance(emp, Programmer):
        emp.working_hour = int(input(f'请输入{emp.name}本月工作时间: '))
    elif isinstance(emp, Salesman):
        emp.sales = float(input(f'请输入{emp.name}本月销售额: '))
    print(f'{emp.name}本月工资为: ￥{emp.get_salary():.2f}元')
```

---

> 参考链接：
> https://github.com/jackfrued/Python-for-Freshmen-2023
> https://github.com/jackfrued/Python-Core-50-Courses
> https://github.com/jackfrued/Python-100-Days

【注：仅供自己学习复习使用，上文部分内容粘贴原项目方便理解，若有侵权请联系删除】