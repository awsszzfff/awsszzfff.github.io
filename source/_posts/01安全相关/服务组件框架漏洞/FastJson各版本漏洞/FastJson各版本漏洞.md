---
title: FastJson
date: 2026-01-13
updated: 2026-01-13
tags:
  - 服务组件框架漏洞
categories:
  - 安全相关
description: FastJson各版本漏洞
published: true
---
> 历史漏洞 https://avd.aliyun.com/search?q=fastjson

> https://xz.aliyun.com/news/14309
> https://mp.weixin.qq.com/s/t8sjv0Zg8_KMjuW4t-bE-w

使用 AutoType，序列化时用 `@type` 显示指定反序列化的 Java 类，支持多态类型（接口、抽象类、父类引用指向子类对象等）

- 1.2.24
	- 没有任何过滤器
	- 典型攻击类 `TemplatesImpl`、`JdbcRowSetImpl`
- 1.2.25
	- 引入 `checkAutoType` 机制，加入黑名单和白名单
	- `AutoType` 机制开启
		- 先检查白名单，白名单中的类直接加载
		- 若不在白名单，继续检查黑名单，若不在黑名单，正常加载
	- `AutoType` 机制关闭
		- 先检查黑名单，若类在黑名单则抛出异常
		- 再检查白名单，若不在白名单则抛出异常
- 1.2.42
	- 假如对 `L;` 的加测，发现 `L;` 去除
	- 黑名单和白名单类名隐去，使用 hash 比对
- 1.2.43
	- 假如对 `LL;;` 的检测，发现则去除
	- 通过引入对 `[` 字符的检测进行进一步防护
- 1.2.45
	- 黑名单机制问题：黑名单无法穷尽所有恶意类
- 1.2.47
	- 开启 `AutoType` 且版本在 33 到 47 之间
		- 若类不在白名单，则继续检查黑名单
		- 若类不在黑名单且不在 mappings 中，则正常加载
		- 关键问题在于如何往 mappings 中添加恶意类
	- 未开启 `AutoType` 且版本在 24 到 32 之间，也存在漏洞
- 1.2.68
	- 引入 `expectedClass` 机制，增加了防护，但仍存在逻辑漏洞
		- 特别针对 `Throwable` 类的防护不足

## 序列化与反序列化

> 序列化与反序列化方法：
> 
> - 序列化方法：
> 	- `JSON.toJSONString()`，返回字符串；
> 	- `JSON.toJSONBytes()`，返回 byte 数组；
> - 反序列化方法：
> 	- `JSON.parseObject()`，返回 `JsonObject`；
> 	- `JSON.parse()`，返回 `Object`；
> 	- `JSON.parseArray()`，返回 `JSONArray`；
> 	- 将 JSON 对象转换为 java 对象：`JSON.toJavaObject()`；
> 	- 将 JSON 对象写入 write 流：`JSON.writeJSONString()`；
> - 常用：
> 	- `JSON.toJSONString()`、 `JSON.parse()`、 `JSON.parseObject()`
> - 在通过 `parse`、`parseObject` 进行反序列化时，会调用类的 `set`、`get` 方法
> - 在通过 `parse` 或 `parseObject` 指定类型进行反序列化时，会利用序列化数据中的 `@type` 值创建对应类的实例。

## 常用 Gadget 链

- `JdbcRowSetImpl`，JNDI 引用，RMI/LDAP 远程加载恶意类执行；
- `TemplatesImpl`，加载恶意字节码，本地不出网执行；
- `CC`，链子；
- `MVEL`，解析表达式，直接执行命令。

`com.sun.rowset.JdbcRowSetlmpl` 该类的 setDataSourceName 方法可以设置一个 JNDI 数据源名，而 setAutoCommit 方法会触发一个初始连接，从而执行 JNDI 查找。

- 攻击流程：构造的恶意 JSON 中，通过@type 指定该类，并将 dataSourceName 设置为一个由攻击者控制的恶意 LDAP/RMI 服务器地址。当 Fastjson 反序列化时，会自动调用 setAutoCommit，向恶意服务器发起 JNDI 请求，服务器返回一个恶意的 java 类，最终在目标服务器上加载并执行，完成 RCE。
- 漏洞关键：AutoType 默认开启且无任何限制

- 绕过原理：当 AutoType 关闭后，Fastjson 会检查@type 指定的类名是否在黑名单内。但如果在解析过程中触发了异常，Fastjson 会尝试使用 java.lang.Class 这个类型去获取一个类，并将其缓存到 mappings 中。攻击者可以利用这个特性，分两步进行攻击：
	1. 先构造一个第一个 JSON 对象，利用异常处理机制，将恶意类名（如 com.sun.rowset.JdbcRowSetlmpl）以 Class 类型提前放入缓存；
	2. 再在第二个 JS0N 对象中直接使用这个恶意类名，此时由于缓存中已存在，Fastjson 会直接使用，从而绕过了 AutoType 的检查；
- 漏洞关键：这是一个逻辑缺陷导致的绕过，而非黑名单不全。它证明了仅仅关闭 AutoType 并依赖黑名单或缓存机制是不安全的。

利用其他库中的类（eg：Tomcat DBCP、Spring、Groovy 等），串联成完整的链~

eg：Tomcat DBCP 链，在反序列化时加入 BCEL 字节码或通过 EL 表达式处理执行命令；

## 不出网问题

> https://xz.aliyun.com/news/11938
> https://github.com/safe6Sec/Fastjson

对一些协议、端口、内外网限制。（JNDI 作为一种服务接口，若目标无法访问，则就无法触发）

可通过延时进行判断是否存在漏洞，加载本地不存在的 JNDI 测试进行延时判断。

> 将要执行命令的文件转换为特定的格式，触发反序列化本地执行。

> 即 RCE 不出网链都是建立在将要执行的命令文件转成 BCEL、BYTE、HEX 等格式用到不同的依赖进行调用执行。

### 利用 BCEL 进行本地类加载

Java 源码通过编译后得到的字节码，JVM 通过解释或编译这些字节码来运行程序

> BCEL 字节码检测器是一个通过 Java 字节码操作库，用来分析、修改和创建 Java 类文件的字节码。通常程序运行后字节码是不动的，但 BCEL 运行在程序运行的过程中，或在文件层面，直接对字节码进行操作：
> 
> - 分析： 查看一个类有哪些方法、字段，逻辑是什么。
> - 修改： 在现有的方法里插入一段你自己的代码（比如监控代码、后门代码等）。
> - 创建： 凭空生成一个新的 `.class` 文件，而不需要写 `.java` 源码。

BCEL 包中一个特殊的类加载器 `com.sun.org.apache.bcel.internal.util.ClassLoader` ，可以识别 `$$BCEL$$` 开头的长字符串，**当尝试加载一个类名以 `$$BCEL$$` 开头的类时，它会自动截取后面的字符串，将其解码并转换回字节码，然后加载这个字节码成为一个 Java 类**。

通过将恶意代码编译为字节码，使用 BCEL 将字节码转换为特殊的字符串，服务器在内存中还原并执行恶意代码，从而导致 RCE。

```json
{
   "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
   "driverClassLoader": {
        "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
   },
   "driverClassName": "$$BCEL$$xxxx"
}

```

### TemplatesImpl 链

触发 `JSON.parseObject(payload, Feature.SupportNonPublicField);`

```json
{
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": ["字节码"],
    '_name': 'a.b',
    '_tfactory': {},
    "_outputProperties": {},
    "_name": "b",
    "_version": "1.0",
    "allowedProtocols": "all"
}
```

### c3p0 链

```json
{
    "@type": "java.lang.Class",
    "val": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"
},
"f": {
    "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
    "userOverridesAsString": "HexAsciiSerializedMap:;HEX值"
}
```

> 版本差异：
> 
> - <= 1.2.47 可利用 JDK 自带的链可实现 RCE；
> - 1.2.47 - 1.2.80 利用链为依赖包或本地代码；（依赖包还需要开启 autoType）

> 常见总结 https://mp.weixin.qq.com/s/yMQPyzYa9YSD-pq2dWEZrA?scene=1

