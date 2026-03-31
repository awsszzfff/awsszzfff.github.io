---
title: Shiro各版本漏洞
date: 2025-11-29
updated: 2025-11-29
tags:
  - 服务组件框架漏洞
categories:
  - 安全相关
description: Shiro各版本漏洞
published: false
---
Shiro 开源安全框架，主要用来解决身份验证、授权、会话管理、数据加解密处理。

> 历史漏洞 https://avd.aliyun.com/search?q=Shiro

漏洞触发 `CookieRememberMeManager`

黑盒特征：数据包 cookie 有 rememberme（并不绝对）

漏洞原理：利用到原生类的 readObject/writeObject 反序列化操作导致漏洞（对数据进行了 AES 加密和 base64 编码）。源码中存在硬编码。

当获取用户请求时，大致的关键过程：
- 获取 Cookie 中的 rememberMe 值
- 对 rememberMe 进行 Base64 编码
- 使用 AES 进行解密
- 对解密的值进行反序列化

AES 加密的 key 是硬编码的默认 key，可使用默认 key 对恶意构造的序列化数据进行加密，当 CookieRememberMeManager 对恶意的 rememberMe 进行以上过程处理时，最终会对恶意数据进行反序列化，从而导致反序列化漏洞。

> 常见总结 https://mp.weixin.qq.com/s/wG3xhu2F_tWUihCBLJ-uEQ

Shiro 550 利用链

获取 AES 加密属性（AES/CBC/PKCS5Padding），将 Payload 进行加密（AES+Base64）借助 URLDNS、CC/CB 链

Shiro 有 key 无链 https://mp.weixin.qq.com/s/MdCUfyaUCAa2M3P3H1NsGw

JRMP RMI 远程方法调用

让目标成为客户端，ys-all 成为服务端

