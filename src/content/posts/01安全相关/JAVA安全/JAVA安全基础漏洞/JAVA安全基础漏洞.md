---
title: JAVA安全基础漏洞
date: 2025-12-28
updated: 2025-12-28
tags:
  - Java安全
categories:
  - 安全相关
description: None
---
## SQL 注入

- 使用 `Statement` 对象，传入参数拼接到 SQL 语句执行，存在漏洞；
- 若使用 `PreparedStatement` 通过预编译再去执行，但是若依旧使用拼接的方式来构造 SQL 语句还是存在漏洞；
- 使用 Spring 中的 `jdbctemplate` 也一样。

若使用占位符 `?` 、ESAPI 验证、强类型转换限制、编码或严格的白名单过滤也可以避免注入。

### Mybatis

支持两种参数符号 `#`、`$`， `#` 使用预编译 `$` 使用拼接 SQL。

当需要用到 `order by`、`like`、`in` 时也是无法使用预编译

- `#{}` 会将对象转换为字符串，导致 `order by` 时错误；
- `like` 模糊搜索时，直接使用 `%#{}` 会报错；
- `in` 之后多个 id 查询时使用 `#` 同样会报错。

所以很多研发还是会使用 `$`。

### Hibernate&JPA

接收参数使用 `:` 进行预编译可防止注入。

> 白盒审计：确定数据库通讯技术、确定类型找调用方法、再查看写法是否安全。

## XXE

```java
// 审计函数
XMLReader
SAXReader
DocumentBuilder
XMLStreamReader
SAXBuilder
SAXParser
SAXSource
TransformerFactory
SAXTransformerFactory
SchemaFactory
Unmarshaller
XPathExpression
```

对于以上类函数实现，`parse` 执行后续的变量可控

> - 禁用 dtd 实体引用、外部参数实体解析
> - 过滤关键词 `<!DOCTYPE>` 和 `<!ENTITY>`，或者 `SYSTEM` 和 `PUBLIC`
> - 使用安全的 XML 解析器或库：考虑使用像 Jackson XML、JAXB 等现代库，通常默认禁用不安全的功能，或者提供更好的安全性控制

## SSRF

可能造成 SSRF 的 API

```java
HttpClient
HttpAsyncClient
java.net.URLConnection/HttpURLConnection
java.net.URL
java.net.Socket
OkHttp
ImageIO
Hutool
Jsoup
RestTemplate
```

> 代码审计 SINK 点：
> 
> URL、HttpClient、OkHttpURLConnection、Socket、ImageIO、DriverManager.getConnection、SimpleDriverDataSource.getConnection、HttpURLConnection、RestTemplate、URLConnection、WebClient、JNDI
> Linux：file:///etc/hosts Windows：file:///C:\windows\win.ini

## URL 跳转

可能存在跳转的参数

```java
sendRedirect
setHeader
```

> 代码审计SINK点：
> 
> redirect、url、redirectUrl、callback、return_url、toUrl、ReturnUrl、fromUrl、redUrl、request、redirect_to、redirect_url、jump、jump_to、target、to、goto、link、linkto、domain、oauth_callback

## 任意文件上传



```txt

```
