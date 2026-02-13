---
title: "SSTI"
date: 2025-05-18
tags:
  - 基础漏洞
categories:
  - 安全相关
---
SSTI（Server Side Template Injection) 服务器模板注入， 服务端接收了用户的输入，将其作为 Web 应用模板内容的一部分，在进行目标编译渲染的过程中，执行了用户插入的恶意内容。

![[attachments/20250518.png]]

测试思路：确认使用的模版引擎；修改参数查看报错/回显等；搜索对应的模版引擎语法格式；构造 Payload ；

构造 Payload 思路：寻找可用对象（如字符串、字典，或已经给出的对象）；通过可用对象寻找原生对象（Object）；利用原生对象实例化目标对象；

> 案例：
> 
> https://forum.butian.net/share/1229

> 漏洞介绍：
> 
> https://www.cnblogs.com/R3col/p/12746485.html