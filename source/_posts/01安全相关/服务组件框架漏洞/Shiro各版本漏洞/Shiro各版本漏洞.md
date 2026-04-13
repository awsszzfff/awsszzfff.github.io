---
title: Shiro各版本漏洞
date: 2025-11-29
updated: 2025-11-29
tags:
  - 服务组件框架漏洞
  - Java安全
categories:
  - 安全相关
description: Shiro各版本漏洞
published: true
---
Shiro 开源安全框架，主要用来解决身份验证、授权、会话管理、数据加解密处理。

> 历史漏洞 https://avd.aliyun.com/search?q=Shiro

RememberMe 是 Shiro 中核心功能之一，用于实现用户登录访问，正常业务：

- 用户登录：用户勾选「记住我」，输入账号密码完成认证；
- 序列化用户信息：Shiro 将用户身份信息（如用户名、权限）序列化为字节流；
- AES 加密：使用预设的 AES 密钥对序列化数据进行加密；
- Base64 编码：将加密后的字节流做 Base64 编码，生成最终的 rememberMeCookie；
- 写入浏览器：将 Cookie 下发给用户浏览器，下次访问自动携带；
- 服务端校验：用户再次访问时，Shiro 反向执行：Base64 解码 → AES 解密 → 反序列化，恢复用户对象，实现免登录。

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

### Shiro-550 利用链

<= 1.2.4 

![[attachments/b0d07e93f2f1fad152f11f02529c7a4f_MD5.jpg]]

获取 AES 加密属性（AES/CBC/PKCS5Padding），将 Payload 进行加密（AES+Base64）借助 URLDNS、CC/CB 链

### Shiro-721

1.2.5+

随机动态秘钥（用户自定义），AES-GCM 模式，随机 iv，需要窃取/爆破，或绕过秘钥校验

### 1.2.3 未授权访问

./admin 等畸形路径，可直接绕过权限校验进入后台

### 权限绕过

<= 1.5.2

路径匹配逻辑缺陷，构造特殊 URL（/xxx/..;/admin）绕过权限拦截

### 认证绕过

<= 1.5.3

对 HTTP 请求方法处理不当，通过特殊请求方法绕过认证，直接访问受限资源

### Shiro 有 key 无链 

https://mp.weixin.qq.com/s/MdCUfyaUCAa2M3P3H1NsGw

JRMP 远程方法协议，RMI 远程方法调用机制的底层通信协议，允许一个 JVM 中的对象像调用本地方法一样调用另一个 JVM 中的对象方法。

构造 JRMPClient 对象作为反序列化 Payload，当 Shiro 反序列化这个 JRMPClient 对象时，主动去连接指定的 JRMP 服务端，并加载服务端返回恶意的对象。

让目标成为客户端，ys-all 成为服务端

