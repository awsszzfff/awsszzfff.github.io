---
title: "Tomcat"
date: 2026-01-30
updated: 2026-01-30
tags:
  - Others
categories:
  - Others
description: None
---
管理界面弱口令，部署 war 包 getshell。

## CVE-2020-1938

Apache Tomcat AJP 协议（默认 8009 端口） 协议设计上存在缺陷，攻击者通过 Tomcat AJP Connector 可以读取或包含 Tomcat 上所有 webapp 目录下的任意文件，例如可以读取 webapp 配置文件或源代码。此外在目标应用有文件上传功能的情况下，配合文件包含的利用还可以达到远程代码执行的危害。

> 影响版本：
> 
> Tomcat 6.*
> Tomcat 7.* < 7.0.100
> Tomcat 8.* < 8.5.51
> Tomcat 9.* < 9.0.31

## CVE-2025-24813

远程代码执行

> 影响版本：
> 
> 11.0.0-M1 <= Apache Tomcat <= 11.0.2
> 10.1.0-M1 <= Apache Tomcat <= 10.1.34
> 9.0.0.M1 <= Apache Tomcat <= 9.0.98

> https://www.cnblogs.com/smileleooo/p/18772389

> 满足以下条件，攻击者可以访问或修改安全敏感文件：
> 
> 1. DefaultServlet 启用了写入权限（默认情况下禁用）。
> 2. 服务器启用了 partial PUT（默认启用）。
> 3. 该敏感文件存放在允许上传的目录的子路径（攻击者需要能够在该敏感文件目录上级路径使用 partial PUT 上传文件）
> 4. 攻击者已知目标敏感文件的路径以及文件名。
> 5. 敏感文件是通过 partial PUT 上传的。
> 
> 满足以下条件，攻击者可以远程代码执行（RCE）：
> 
> 6. DefaultServlet 启用了写入权限（默认情况下禁用）。
> 7. 服务器启用了 partial PUT（默认启用）。
> 8. Tomcat 使用了基于文件的 Session 持久化机制（非默认配置，默认为基于内存持久化），且存储位置为默认路径。
> 9. 应用程序包含可利用的反序列化漏洞库（如 Commons-Collections 3.x）。
