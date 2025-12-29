---
title: Python基础
date: 2025-06-15
tags:
  - Python基础
categories:
  - 程序设计
---
> 官方文档 https://docs.python.org/zh-cn/3/index.html

## 基本数据类型及其基本操作

```txt
1. 按照访问方式分
	- 直接访问：数字 布尔
	- 按照索引：列表、集合、元组
	- 按照关键字：字典 映射类型
2. 按照可变和不可变区分
	- 不可变：字符串、数字、布尔、元组，集合
	- 可变：列表，字典
3. 可迭代与不可迭代
	- 可迭代即可以被 for 遍历： 元组、集合 、列表，字典，字符串、
	- 不可迭代：数字、布尔
```

### 数字 num_

|        基本操作        |    含义     |
| :----------------: | :-------: |
|    `int(num_)`     |   强转整数    |
|    `oct(num_)`     |   转八进制    |
|    `hex(num_)`     |   转十六进制   |
|    `bin(num_)`     |   转二进制    |
|   `float(num_)`    |   强转浮点数   |
|  `num_.isdigit()`  | 判断是否为数字类型 |
| `num_.isdecimal()` | 判断是否为浮点类型 |

### 字符串 str_

|               基本操作               |           含义           |
| :------------------------------: | :--------------------: |
|         `str_1 + str_2`          |   拼接`str_1`,`str_2`    |
|         `''.join(str_`)          |      用`c`拼接`str_`      |
|      `str_[start:end:step]`      |      索引，支持正负索引/切片      |
|           `len(str_)`            |          计算长度          |
|           `'' in str_`           |          成员判断          |
|         `str_.strip('')`         |        去除两侧指定字符        |
|        `str_.rstrip('')`         |        去除右侧指定字符        |
|        `str_.lstrip('')`         |        去除左侧指定字符        |
|         `str_.split('')`         |        根据指定字符切分        |
|          `str_.upper()`          |          转大写           |
|          `str_.lower()`          |          转小写           |
|            `str_ * n`            |          重复n次          |
|         `str_.islower()`         |          判断小写          |
|         `str_isupper()`          |          判断大写          |
|      `str_.startswith('')`       |      判断开头是否为指定字符       |
|       `str_.endswith('')`        |      判断结尾是否为指定字符       |
|   `str_.find('',[start,end])`    |        查找（从左往右）        |
|         `str_.rfind('')`         |        查找（从右往左）        |
|         `str_.index('')`         |       查找，不存在则报错        |
|        `str_.rindex('')`         |    查找（从右往左），不存在则报错     |
|         `str_.count('')`         |        统计指定字符个数        |
| `str_.center(len(str_) + n,'c')` | 用c填充原字符至`len(str_)+n`长 |
| `str_.ljust(len(str_) + n,'c')`  |         只填充右侧          |
| `str_.rjust(len(str_) + n,'c')`  |         只填充左侧          |
|   `str_.zfill(len(name)) + n`    |        填充，不足补0         |
|       `str_.capitalize()`        |         句首字母大写         |
|          `str_.title()`          |       每个单词首字母大写        |
|        `str_.swapcase()`         |         大小写翻转          |
|         `str_.isalnum()`         |     是否字符串中包含数字和字母      |
|         `str_.isalpha()`         |        是否仅包含字母         |
|      `str_.isidentifier()`       |       是否包含合法标识符        |
|         `str_.islower()`         |         是否纯小写          |
|         `str_.isupper()`         |         是否纯大写          |
|         `str_.isspace()`         |         是否纯空格          |
|         `str_.istitle()`         |        是否首字母大写         |

### 列表 list_

`list(<可迭代类型>)`

|             基本操作              |      含义      |
| :---------------------------: | :----------: |
|    `list_[start:end:step]`    |      切片      |
|         `'' in list_`         |     成员判断     |
|      `list_.append('')`       | 追加元素到最后，无返回值 |
|    `list_.extend(<可迭代对象>)`    |   可追加多个元素    |
|     `list_.insert(n, '')`     |   索引n处添加元素   |
|        `del list_[n]`         |      删除      |
|        `list_.pop(n)`         | 弹出（可选指定索引n）  |
|      `list_.remove('')`       |    删除指定值     |
|       `list_.reverse()`       |      翻转      |
| `sorted(list_, reverse=True)` |   翻转，有返回值    |
| `list_.sort([reverse=True])`  |   排序，可选翻转    |


### 字典 dict_[k:v]


|               基本操作               |      含义      |
| :------------------------------: | :----------: |
|            `dict_[k]`            |  获取v，不存在则报错  |
|          `dict_.get[k]`          |   获取v，不报错    |
|           `dict_[k]=v`           |      增       |
|     `dict_.setdefault(k,v)`      |  增，有返回值，返回v  |
|     `dict_1.update(dict_2)`      |   更新dict_1   |
|       `dict_.update(k=v)`        |      更新      |
|         `del dict_p[k]`          |   删除k<=>v    |
|          `dict_.pop(k)`          |      弹出      |
|         `dict_.clear()`          |      清空      |
|        `dict_.popitem()`         | 弹出键值对，默认弹最后的 |
|           `len(dict_)`           |     计算个数     |
|          `dict_.keys()`          |      键       |
|         `dict_.values()`         |      值       |
|         `dict_.items()`          |     键值对      |
| `c in dict_.keys/values/items()` |     成员运算     |
|   `for k, v in dict_.items()`    |      遍历      |

### 元组 tuple_


|        基本操作         |     含义      |
| :-----------------: | :---------: |
|     `tuple_[n]`     |     索引      |
|     `tuple_[:]`     |     切片      |
|  ~~`tuple_[n]=v`~~  |   不支持索引改值   |
|    `len(tuple_)`    |    计算个数     |
|    `c in tuple_`    |    成员运算     |
| `tuple_1 + tuple_2` |     拼接      |
|    `tuple_ * n`     | \*运算，会得到新元组 |

### 集合 set_


|            基本操作             |      含义      |
| :-------------------------: | :----------: |
|        `set_.add()`         |      增       |
|     `set_.update(...)`      |      更新      |
|     `set_.remove(...)`      |  删除，不存在则报错   |
|     `set_.discard(...)`     |   删除，不会报错    |
|        `set_.pop()`         | 弹出，随机，不能指定元素 |
|       `set_.clear()`        |      清空      |
| `set_1.intersection(set_2)` |      交集      |
|    `set_1.union(set_2)`     |      并集      |
|  `set_1.difference(set_2)`  |      差集      |
|         `len(set_)`         |     计算长度     |

集合内部不可放可变数据类型，每个元素是单独的，无序，数字类型的 hash 值是死的

## 深浅拷贝

```python
import copy
old_list = [1,2,3]
new_list = copy().copy(old_list) # 浅拷贝，修改新的旧的变
new_list = copy().deepcopy(old_list) # 深拷贝，修改新的旧的不变
```

## 字符编码

```python
data_.decode('utf-8')	# gbk...
data_.encode('utf-8')	# gbk...
```

## 文件操作

|  模式  | 主要用途  |      关键特点      |
| :--: | :---: | :------------: |
| `r`  |  只读   |     文件必须存在     |
| `w`  | 覆盖写入  |    清空或创建文件     |
| `a`  | 追加写入  |  追加到末尾，自动创建文件  |
| `r+` | 读写混合  |   从当前位置覆盖写入    |
| `w+` | 创建并读写 |  先清空文件，适合临时文件  |
| `a+` | 追加并读取 | 追加到末尾，但可读取全量内容 |

```python
# eg:
fp = open('demo.txt', 'r', encoding='utf-8')
data = fp.read()	# 读所有数据
fp.close()

with open('demo.txt', 'r', encoding='utf-8') as fp:
	data = fp.read()
```


|            模式             |                  主要用途                   |
| :-----------------------: | :-------------------------------------: |
|       `fp_.read()`        |                  读所有内容                  |
|       `fp_.write()`       |                   写入                    |
|     `fp_.readline()`      |                   读单行                   |
|     `fp_.readlines()`     |             读多行，读出的数据存放在列表中             |
|     `fp_.readable()`      |                  是否可读                   |
|  `fp_.writelines(list_)`  |                 逐个元素写入                  |
|       `fp_.flush()`       |                 刷新到磁盘中                  |
| `fp_.seek(指针移动字节数, 模式控制)` | 0以文件开头为参照；<br>1以当前所在位置为参照；<br>2以文件末尾为参照 |
|       `fp_.tell()`        |                指针当前所在位置                 |

## 异常捕获

```python
try:
	...
except [Error_type]:
	...

# 多异常捕获
try:
	...
except (Error_type_1, Error_type_2):
	...

# 多分支异常补货
try:
	...
except [f_Error_type]:
	...
except [s_Error_type]:
	...

# 不区分异常类型
try:
	...
except [Error_type] as e:
	print(e)
```

```python
# 主动报错
raise Error_type

# eg：
for i in range(10):
	if i == 6:
		raise ValueError("不能为6")

# 断言
for i in range(10):
	assert i == 6, "不能为6"
```

## 函数多参数&类型注解

### 多参传递

```python
def student_(name, age, *args, gender='male', **kwargs):
	...
# *args 多普通参数
# **kwargs 多键值参数
```

```python
# 解包传参
def student_(name, age)
	...
student(*stu_list)
student(**stu_dict)
```

### 类型注解

```python
# 不可变类型
def student_(name: str, age: int, score: float, is_male: bool):
	...

# 可变类型
from typing import Dict, List, Tuple, Set
def student_(user_data: Dict[str, int], id_list: List[int], num_tuple: Tuple[str], num_set: Set[int]):
	...

# 约定返回值
def add_(x: int, y: int) -> int:
	...

# 允许返回多类型
from typing import Union
def add_(x: int, y: int) -> Union[str, int]:
	...

# 可以是None
from typing import Optional
def add_(x: int, y: int) -> Optional[，int, None]:
	...
```

## 装饰器&语法糖

在不改变原函数代码和调用方式的基础上额外增加的新功能。基本原理：闭包函数 + 函数对象的组合使用。

### 无参装饰器

```python
# 无参装饰器模版
def outer(func):
	'''
	:param func: 每一次需要调用传递的函数
	:return: 返回值是内嵌函数 inner 的函数内存地址
	'''
  	def inner():
  		# 可以加逻辑校验
		# 当符合指定条件后，可以允许执行传递进来的函数
		# 不符合条件的时候不执行函数
		func()
		# 做逻辑校验，func 函数执行后的逻辑
	return inner
```

示例：

```python
def outer(func):
	def inner():
		username = input("username :>>>> ")
		password = input("password :>>>> ")
		# 否则打印失败
		if username == user_data_dict.get('username') and password ==
	user_data_dict.get('password'):
			print(f"登录成功")
			func()
		else:
			print("登录失败")
	return inner
	
def transform():
	print(f"这是在转账功能")
	
transform = outer(transform)
transform()
# transform = outer(transform) # transform = inner = outer(transform)
# transform() # transform() = inner() = outer(transform)()
def withdral():
	print(f"这是取款功能")
	
withdral = outer(withdral)
# withdral()
```

### 有参装饰器

```python
# 有参装饰器模版
def outer_yes(func):
	def inner(*args, **kwargs):
		func(*args, **kwargs)
	return inner
```

示例：

```python
# 用可变长位置参数和可变长关键字参数接收到函数所需要的所有参数
def outer(func):
	def inner(*args, **kwargs):
		func(*args, **kwargs)
	return inner
	
def transform(username, money):
	print(f"向 {username} 转账 {money}")
	
username = 'opp'
money= 10000
transform = outer(transform)
transform(username, money)
```

### 语法糖

示例：在不改变原 transform 函数的基础上，添加 timer 功能。

```python
# 无语法糖
import time

def timer(func):
	def inner():
		start = time.time()
		func()
		end = time.time()
		print(f"总耗时 :>>>> {end - start} s")
	 return inner
	 
def transform():
	time.sleep(1)
	
transform = timer(transform)
transform()

# 有语法糖
def timer(func):
	def inner():
		start = time.time()
		func()
		end = time.time()
		print(f"总耗时 :>>>> {end - start} s")
	return inner
	
@timer
def transform():
	time.sleep(1)
	
# transform = timer(transform)
# transform()
transform()
```

### 多层代参语法糖

```python
def check_user_pwd(tag):
    if tag == 'username':
        def check_username(func):
            def inner(*args, **kwargs):
                username = input("username :>>>> ").strip()
                username_dict = user_data_dict.get('username')
                if not username_dict == username:
                    print(f"当前 {username} 不存在不允许使用")
                else:
                    func(*args, **kwargs)
            return inner
        return check_username
    elif tag == 'password':
        def check_password(func):
            def inner(*args, **kwargs):
                password = input("password :>>>> ").strip()
                user_password = user_data_dict.get("password")
                if user_password != password:
                    print(f"密码错误")
                else:
                    func(*args, **kwargs)

            return inner
        return check_password


# 一个负责校验密码是否正确
# 【语法糖的执行会从下往上执行，具体流程浏览器搜一下吧~】
@check_user_pwd(tag="username")
@check_user_pwd(tag="password")
def transform(username, money):
    print(f"{username} 转账 {money}")


transform(username='dream', money=6666)
```

## 迭代器&生成器

### 迭代器

```python
# eg：str_
str_ = "abc"
# iter(str_)
str_.__iter__()	# <str_iterator object at 0x0000027750011340> 返回可迭代对象
str_.__next__()	#  a
str_.__next__()	#  b
str_.__next__()	#  c
```

### 生成器

在需要的时候给你数据，不需要的时候不给数据

```python
# eg：range(10) 就是一个生成器
```

yield 关键字

https://blog.csdn.net/mieleizhi0522/article/details/82142856

```python
def foo():
    print("starting...")
    while True:
        res = yield 4
        print("res:",res)
g = foo()
print(next(g))
print("*"*20)
print(next(g))
print(g.send(7))
# starting...
# 4
# ********************
# res: None
# res: 7
# 4
```

简单理解就是一个 return ，return 出 4 后并没有赋值给 res ，send 后才真正赋值给 res 。

作为一种节省内存的生成器来使用，eg：

```python
def foo(num):
    print("starting...")
    while num<10:
        num=num+1
        yield num
for n in foo(0):
    print(n)
# strting... 1 2 3 4 5...
```

## 模块和包

### 模块

一个 py 文件即一个模块，一般里面有多个 def 

### 包

文件夹有 `__init__.py` 文件

示例：

calculator 包

```python file:add.py
def add(x, y):
	print("加法功能")
	if not x.isdigit() or not y.isdigit():
		return False, f'当前数字格式错误'
	return True, int(x) + int(y)
```

```python file:__init__.py
from .add import add
```

包外部调用

```python file:main.py
from calculator import add
add(x, y)
# 若不用__init__.py那样写则使用方式：
add.add(x, y)
```

## 匿名函数

```python
# 示例：filter 过滤后面的参数

temp = filter(lambda x: x % 2 == 0, range(1, 10))  
print(list(temp))	# [2, 4, 6, 8]
```

## 内置函数

### 强转

|    函数名     | 含义  |
| :--------: | :-: |
|  `str()`   | ... |
|  `int()`   | ... |
| `floadt()` | ... |
|  `list()`  | ... |
| `tuple()`  | ... |
|  `bool()`  | ... |
|  `set()`   | ... |
|  `dict()`  | ... |

### 进制转换

|   函数名   |   含义   |
| :-----: | :----: |
| `bin()` | 10->2  |
| `oct()` | 10->8  |
| `hex()` | 10->16 |

### 数学运算

|             函数名              |     含义     |
| :--------------------------: | :--------: |
|           `abs()`            |    绝对值     |
|       `divmod(被除数，除数)`       |    商和余数    |
|       `round( ,小数点位数)`       |    四舍五入    |
| `pow(base, exponent[, mod])` | 幂次方, mod模数 |
|           `sum()`            |    ...     |
|           `min()`            |    ...     |
|           `max()`            |    ...     |
|         `complex()`          |    复数转换    |
### 数据结构相关

|      函数名      |  含义  |
| :-----------: | :--: |
| `reversed()`  |  翻转  |
|   `slice()`   |  切片  |
|    `len()`    | 计算长度 |
|  `sorted()`   |  排序  |
| `enumerate()` |  枚举  |

### 字符串相关

|            函数名             |          含义          |
| :------------------------: | :------------------: |
|    `format(str_, '^n')`    |       n位中居中对齐        |
|    `format(str_, '<n')`    |         左对齐          |
|    `format(str_, '>n')`    |         右对齐          |
|     `format(num, 'b')`     |       进制转换，二进制       |
|     `format(num, 'd')`     |         十进制          |
|     `format(num, 'o')`     |         八进制          |
|     `format(num, 'x')`     |       十六进制（小写）       |
|     `format(num, 'X')`     |       十六进制（大写）       |
|     `format(num, 'c')`     |       转unicode       |
|   `format(num, '0.2e')`    |     科学计数小写，保留后两位     |
|   `format(num, '0.2E')`    |     科学计数大写，保留后两位     |
|   `format(num, '0.2f')`    |     小数点计数，保留后两位      |
|     `format(num, 'F')`     | 小数点计数，很大的时候输出INF:... |
|   `bytes(str_, 'utf-8')`   |        指定编码方式        |
| `bytearray(str_, 'utf-8')` |        获取字节数组        |
|        `repr(str_)`        |      得到字符串的原始样式      |

### 字符编码相关

|     函数名     |         含义          |
| :---------: | :-----------------: |
|  `ord(c_)`  |      得到ASCII值       |
| `chr(num_)` |         相反          |
|  `ascii()`  | 类似repr，不过会自动转义\x等字符 |

### 输入输出

|    函数名    | 含义  |
| :-------: | :-: |
| `input()` | ... |
| `print()` |     |
### hash算法

|   函数名    |      含义       |
| :------: | :-----------: |
| `hash()` | 计算不可变数据类型的哈希值 |

### 文件操作

|   函数名    | 含义  |
| :------: | :-: |
| `open()` | ... |

### 其他

|        函数名         |            含义             |
| :----------------: | :-----------------------: |
|      `help()`      |            ...            |
|    `callable()`    |        判断是否可被用()调用        |
|      `dir()`       |     列出当前作用域中的所有变量和函数名     |
|       `id()`       |        获取当前变量的内存地址        |
|   `breakpoint()`   |            调试器            |
|    `compile()`     |       编译字符串为可执行的代码        |
|    `getattr()`     |      从对象中获取变量名对应的属性值      |
|   `isinstance()`   |       判断当前变量是否是指定类型       |
|   `issubclass()`   |      判断当前类是否是另一个累的子类      |
|    `globals()`     |         查看全局名称空间          |
|     `locals()`     |         查看局部名称空间          |
| `map(def_, list_)` | 将可迭代类型中的每一个元素作为参数传递给前面的函数 |
|      `iter()`      |          生成迭代器对象          |
|      `next()`      |        生成器或迭代器向下取值        |
|   `memoryview()`   |           查看内存            |
|    `delattr()`     |         从对象中删除属性          |
|  `classmethod()`   |          类的静态方法           |
|    `hasatter()`    |       从对象中判断是否具有该属性       |
|      `zip()`       |     将两个或三个及以上的数据进行打包      |
|     `anext()`      |       获取异步迭代器的下一个元素       |
|     `aiter()`      |         获取异步迭代器对象         |
|      `any()`       |     判断是否有任意一个元素为 True     |
|      `all()`       |      判断是否所有元素都为 True      |
|     `filter()`     |            过滤             |
|      `exec()`      |       执行字符串形式的代码，指令       |
|      `eval()`      |        执行字符串形式的代码         |
|   `frozenset()`    |       冻结集合，不能往里面加东西       |

## 面向对象

### 封装&继承&多态&

#### 封装

私有方法&私有属性，方法和属性前加`__`

`property` 一个特殊的属性，将函数的返回值作为数据属性返回

```python
# eg：
class Student:
	def __init__(self, name):
		self.name = name
	   
	@property
	def vip_name(self):
		return self.name

student = Student(name='dream')
print(student.vip_name)	# 可这样直接调用
```

应用示例：（主要目的还是对私有属性的操作）

```python
class Person(object):
	def __init__(self, name):
		self.__name = name
		
	# 给当前函数名添加装饰器 property
	# 将当前 函数名作为一个数据属性返回
	@property
	def vip_name(self):
		# 返回值可以是字符串也可以是其他内容
		return self.__name
		
	# 修改 和 property 包装的函数名一致 并且加 .setter
	# 修改当前变量民的时候会触发
	@vip_name.setter
	def vip_name(self, value):
		print(value)
		self.__name = value
	
	# 删除 和 property 包装的函数名一致 并且加 .deleter
	# 删除当前变量民的时候会触发
	@vip_name.deleter
	def vip_name(self):
		del self.__name

	# 可以不添加property装饰器，直接用该方法来操作，可以达到同样的效果
	# vip_name = property(get_vip_name, set_vip_name, del_vip_name)
	
person = Person(name='dream')

# 查看
print(person.vip_name)
# <bound method Person.name of <__main__.Person object at 0x000001EE86C22340>>

# 修改
person.vip_name = 'opp'
print(person.vip_name)

# 删除
del person.vip_name
print(person.vip_name)
```

#### 继承

```python
class son(father):
	...

# 不过子类想要继承到父类__init__初始化的属性，需要下面这种方式：
class son(father):
	def __init__(self, name, sex, age, title):
		# 若是多继承，super只会继承第一个类的init，可以用这种指定的方式来分别指定继承
		# father.__init__(self, name, age, sex)	
		super().__init__(name, sex, age)
		self.title = title
```

```python
# 查看调用顺序
class A:
	def hello(self):
		print("Hello from A")
class B(A):
	def hello(self):
		print("Hello from B")
class C(B):
	def hello(self):
		print("Hello from C")
		
print(C.mro())
# [<class '__main__.C'>, <class '__main__.B'>, <class '__main__.A'>, <class 'object'>] 。
```

##### 抽象类

类创建添加 `metaclass=abc.ABCMeta` ，对应方法添加装饰器 `@abc.abstractmethod`

示例：

```python
# 所有继承父类的子类必须重写父类的某些方法，这个父类就叫抽象类
import abc
import json

class Animal(metaclass=abc.ABCMeta):
	def __init__(self, color, foot, hand):
		self.color = color
		self.foot = foot
		self.hand = hand
		
	def speak(self):
		print(f'任何动物都能叫')
		
	# 在子类中必须重写父类的当前方法
	@abc.abstractmethod
	def walk(self):
		...
		
	class BlackBear(Animal):
		def __init__(self, color, foot, hand):
			super().__init__(color, foot, hand)
			
		# 如果不重写父类的方法就会报错
		# Can't instantiate abstract class BlackBear with abstract methods walk
		def walk(self):
			...
		
bear = BlackBear('black', 2, 2)
print(bear.color)
bear.speak()
```

#### 多态

父类被多个子类继承，并重写父类对应的方法

### 绑定方法&非绑定方法

#### 绑定方法

- 绑定给对象的方法

即正常方法，特征是会自动补全 self （类的实例对象本身），类调用时需主动传入对象`Student.talk(s)`

示例：

```python
# 对象可以任意调用的方法  
class Student(object):  
    def __init__(self, name):  
        self.name = name  
  
    def talk(self):  
        print(f'{self.name} is talking')  
  
  
# （1）对象可以直接调用绑定给对象的方法  
s = Student('dream')  
s.talk()  # 默认将 s 作为 self 自动传入  
# （2）类调用绑定给对象的方法,需要主动传入一个生成的对象  
Student.talk(s)
```

- 绑定给类的方法

对应的方法添加 `@classmethod` 装饰器，特征是自动补全 cls （类本身），类可直接调用该方法。

示例：

```python
# 对象和类都可以任意调用的方法  
class Student(object):  
    def __init__(self, name):  
        self.name = name  
  
    # 绑定给类的方法  
    @classmethod  
    def read(cls, *args, **kwargs):  
        '''  
       :return: 调用当前方法的类  
       '''        # print(cls) # <class '__main__.Student'>  
        obj = cls(*args, **kwargs)  # Student(*args,**kwargs)  
        print(f'{obj.name} is reading')  
  
  
stu = Student('dream')  
# print(Student) # <class '__main__.Student'>  
# （1）对象调用绑定给类的方法, 默认将实例化得到当前对象的类自动传入  
stu.read('dream')  
# （2）类调用绑定给类的方法,类可以直接调用，默认将调用当前方法的类自动传入  
Student.read('dream')
```

#### 非绑定方法

对应的方法添加 `@staticmethod` 装饰器，特征是不会自动补全任何参数，类和对象可直接调用

```python
# 对象和类都可以任意调用的方法  
class Student(object):  
    def __init__(self, name):  
        self.name = name  
  
    # 非绑定方法  
    # 对象调用非绑定方法，直接调用  
    # 类调用非绑定方法，直接调用  
    @staticmethod  
    def write():  
        print("is writing")  
  
  
stu = Student('dream')  
# print(Student) # <class '__main__.Student'>  
# （1）对象调用非绑定方法, 不用传任何参数，和普通函数一样  
stu.write()  
# （2）类调用非绑定方法, 不用传任何参数，和普通函数一样  
Student.write()
```

## 面向对象的其他相关操作


|             函数             |       含义        |
| :------------------------: | :-------------: |
|    `getattr(obj, key)`     |      获取属性       |
|    `hasattr(obj, key)`     |   判断当前属性是否存在    |
| `setattr(obj, key, value)` | 向当前对象中设置属性值和属性名 |
|    `delattr(obj, key)`     |   删除对象中指定的属性    |

不光是属性，类中的方法也可以进行这些操作，getattr 获取到该函数后还可以调用。

## 部分魔术方法

> 部分引用： https://blog.csdn.net/qq_37085158/article/details/124986720

### `__init__`

实例化类得到对象时自动触发

### `__getitem__`

允许其实例使用`[]`运算符来获取属性

```python
class GetTest(object):  
    def __init__(self):  
        self.info = {  
            'name': 'Bob',  
            'country': 'UUU',   
        }  
  
    def __getitem__(self, i):  
        return self.info[i]  
  
  
foo = GetTest()  
print(foo['name'])	# Bob
```

### `__del__`

对象关闭销毁时自动触发

### `__call__`

让类的实例具有类似于函数的行为，把对象当做函数调用的时候自动触发

```python
class A(object):
    def __call__(self, *args, **kwargs):
        pass


a = A()
a()  # 自动调用__call__()
```

### `__slots__`

限制当前类只能有指定的属性

```python
class WithSlots:
    __slots__ = ['name', 'age']  # 限制只能有 name 和 age 属性
    
    def __init__(self, name, age):
        self.name = name
        self.age = age

# 创建实例
with_slots = WithSlots("Bob", 25)
with_slots.new_attr = "I am a new attribute"  # 抛出 AttributeError 错误
# 若没有指定__slots__则这里可以正确的指定新的属性
```

### `__str__`

打印当前对象的时候可指定改变对象的字符串现实，打印当前对象时会触发，打印该方法的返回值

```python
class Cat:
    def __init__(self, name, sex):
        self.name = name
        self.sex = sex

    def __str__(self):
        return f"我是一只可爱的小{self.sex}猫咪，我的名字是{self.name}"


>>> cat = Cat("小白", "公")
>>> print(cat)
# 我是一只可爱的小公猫咪，我的名字是小白
```

### `__repr__`

改变对象的字符串现实，表述某个对象在内存中的展示形式。如果在终端直接输入一个对象，然后按回车，那么将会执行这个对象的`__repr__`方法。

- 此方法是`__str__()`的“备胎”，如果找不到`__str__()`就会找`__repr__()`方法
- `%r`默认调用的是`__repr__()`方法，`%s`调用`__str__()`方法
- `repr()`方法默认调用`__repr__()`方法

```python
class A(object):  
    def __init__(self, name, age):  
        self.name = name  
        self.age = age  
  
    def __str__(self):  
        msg = 'name:{},age:{}'.format(self.name, self.age)  
        return msg  
  
    def __repr__(self):  
        msg = 'name--->{},age--->{}'.format(self.name, self.age)  
        return msg  
  
  
a = A('za', 34)  
  
print('%s' % a)  # name:za, age:34  
# 用 %r,默认调用__repr__()方法  
print('%r' % a)  # name-->za, age-->34  
# 有__str__()方法就会调用__str__()方法，没有就调用__repr__()方法  
print(a)  # name:za, age:34 # repr()方法默认调用__repr__()方法  
print(repr(a))  # name-->za, age-->34
```

### `__new__`

对象实例化时被调用，先触发`__new__`才会触发`__init__`。

- 接受的第一个参数是 cls ，代表实例化的类。
- 至少需要返回一个该类的新实例（通常是调用超类的 `__new__` 方法来完成。
- 该方法执行后，新创建的对象会作为第一个参数传递给`__init__`方法来进行初始化

```python
class Person(object):
    def __init__(self):
        print('__init__(): 我也被调用啦~')

    def __new__(cls, *args, **kwargs):  # 重写后,不再创建对象
        print('__new__(): 哈哈我被调用啦~')


per = Person()	# __new__(): 哈哈我被调用啦~
print(per)	# None
```

`None`说明没有创建对象，因为我们重写了`__new__`方法，`__new__`方法不再具有创建对象的功能，只有打印的功能。

调用父类的`__new__`方法，创建当前对象

```python
class Person(object):
    def __init__(self):
        print('__init__(): 我也被调用啦~')

    def __new__(cls, *args, **kwargs): 
        print('__new__(): 哈哈我被调用啦~')
        ret = super().__new__(cls)  # 调用父类object的__new__方法创建对象
        return ret

per = Person()
# __new__(): 哈哈我被调用啦~
# __init__(): 我也被调用啦~
print(per)
# <__main__.Person object at 0x0000020FA3892848>

```

### `__dict__`

获取类或对象的内部成员结构，主要用来获取用户自定义的属性，以及这些属性对应的值，返回的是一个字典。

### `__doc__`

获取类或对象内部文档

### `__name__`

获取类名或函数名

### `__class__`

获取当前对象获取的类

### `__bases__`

获取一个类直接继承的所有父类，返回元组

### `__getattr__`

获取当前对象不存在的属性时触发。

仅当属性在实例的 `__dict__`、类的 `__dict__` 或其父类中都找不到时才会调用。

```python
class Student(object):  
    def __init__(self, name):  
        self.name = name  
  
    def __getattr__(self, item):  
        return item  
  
  
s = Student("hello")  
print(s.name)  # hello  
print(s.age)  # age
```

### `__getattribute__`

每次访问任何实例属性（无论是否存在），会自动调用。

### `__setattr__`

设置对象的属性值的时候触发（无论该属性是否已存在）

```python
class MyClass:  
    def __setattr__(self, name, value):  
        print(f"Setting attribute '{name}' to '{value}'")  
        # 使用父类的 __setattr__ 避免递归  
        object.__setattr__(self, name, value)  
        # 或者: self.__dict__[name] = value  
  
  
obj = MyClass()  
obj.x = 10  # Setting attribute 'x' to '10'  
print(obj.x)  # 10
```

### `__delattr__`

当尝试删除一个实例属性时（使用`del`语句），会自动调用

```python
class MyClass:  
    def __init__(self):  
        self.attr_to_delete = "I will be deleted"  
  
    def __delattr__(self, name):  
        print(f"Deleting attribute '{name}'")  
        object.__delattr__(self, name)  
  
  
obj = MyClass()  
del obj.attr_to_delete  # Deleting attribute 'attr_to_delete'  
# del obj.non_existent   # 这会引发 AttributeError，但也会先调用 __delattr__
```

## 元类

`class MyClass: ...` 是创建一个类，那么`Myclass`类是由谁创建的？`MyClass`是由`type`创建的，它不仅可以检查对象的类型，它本身也是一个类，并且是创建其他类的“工厂”。

实际创建类的两种方式：

```python
# 方式一
class MyClass: 
	x = 10 
	def hello(self): 
		print("Hello")

# 方式二
# type(name, bases, dict)  
# name: 类名  
# bases: 父类的元组（用于继承）  
# dict: 类的属性和方法的字典  
  
MyClass = type('MyClass', (), {'x': 10, 'hello': lambda self: print("Hello")})
```

> 元类就是用来创建类的东西
> 
> 可以理解为：
> 
> - 类是用来创建实例的
> - 元类是用来创建类的

### 作用

为了在类被创建时，自动做一些事情。

eg：想要每个类在创建时：

- 自动给所有方法加上日志记录。
- 自动验证某些属性。
- 强制类必须包含某个特定的方法。
- 改变类的结构（比如把所有属性名转为大写）。

这些操作都可以在类被创建的那一刻（而不是实例化时）通过自定义元类来实现。

### 示例

所有使用这个元类的类，在创建时自动打印一条消息：“类 XXX 被创建了！”

步骤：

1. 定义一个元类：它必须继承自 `type`。
2. 重写 `__new__` 方法：`__new__` 是在类被创建时调用的，我们可以在这里插入自定义逻辑。
3. 在类定义中使用 `metaclass=` 参数。

```python
# 第一步：定义元类  
class MyMeta(type):  
    def __new__(cls, name, bases, attrs):  
        """  
        cls: 当前元类 (MyMeta)        
        name: 要创建的类的名字 (比如 'MyClass')        
        bases: 父类的元组  
        attrs: 类的属性和方法的字典  
        """        
        print(f"元类 MyMeta: 正在创建类 '{name}'")  
  
        # 可以在这里修改类的属性  
        # 例如，给所有类添加一个版本号  
        attrs['version'] = '1.0'  
  
        # 调用父类 (type) 的 __new__ 来真正创建类  
        new_class = super().__new__(cls, name, bases, attrs)  
  
        return new_class  
  
  
# 第二步：使用元类创建类  
class MyClass(metaclass=MyMeta):  
    def greet(self):  
        print("Hello from MyClass")  
  
# 输出: 元类 MyMeta: 正在创建类 'MyClass'

print(MyClass.version)  # 输出: 1.0  
obj = MyClass()  
obj.greet()  # 输出: Hello from MyClass
```
