---
title: Shiro
date: 2025-11-29
updated: 2025-11-29
tags:
  - Java安全
categories:
  - 安全相关
description: Shiro漏洞
---
Shiro 开源安全框架，主要用来解决身份验证、授权、会话管理、数据加解密处理。

> 历史漏洞 https://avd.aliyun.com/search?q=Shiro

漏洞触发 `CookieRememberMeManager`

黑盒特征：数据包 cookie 有 rememberme（并不绝对）

漏洞原理：利用到原生类的 readObject/writeObject 反序列化操作导致漏洞（对数据进行了 aes 加密和 base64 编码）。源码中存在硬编码。

> 常见总结 https://mp.weixin.qq.com/s/wG3xhu2F_tWUihCBLJ-uEQ

Shiro 有 key 无链 https://mp.weixin.qq.com/s/MdCUfyaUCAa2M3P3H1NsGw

JRMP RMI 远程方法调用

让目标成为客户端，ys-all 成为服务端

