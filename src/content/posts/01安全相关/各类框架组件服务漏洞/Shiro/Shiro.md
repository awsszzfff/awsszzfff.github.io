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

## Shiro 反序列化漏洞

Remember Me 功能的设计缺陷

Shiro-550 (CVE-2016-4437)


