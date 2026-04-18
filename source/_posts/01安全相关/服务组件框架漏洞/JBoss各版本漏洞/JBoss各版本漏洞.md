---
title: JBoss各版本漏洞
date: 2025-04-14
updated: 2025-04-14
tags:
  - 服务组件框架漏洞
  - Java安全
categories:
  - 安全相关
description: JBoss各版本漏洞
published: false
---
| 漏洞类型        | 漏洞名称                                             |
| ----------- | ------------------------------------------------ |
| 访问控制不严导致的漏洞 | JMXConsole未授权访问Getshell                          |
|             | AdministrationConsole弱口令Getshell                 |
|             | CVE-2007-1036 - JMX Console HtmlAdaptor Getshell |
|             | CVE-2010-0738－JMX控制台安全验证绕过漏洞                     |
| 反序列化漏洞      | CVE-2013-4810-JBoss EJBInvokerServlet反序列化漏洞      |
|             | CVE-2015-7501-JBossJMXInvokerServlet反序列化漏洞       |
|             | CVE-2017-7504 - JBoss 4.x JBossMQ JMS 反序列化漏洞     |
|             | CVE-2017-12149 --JBosS AS 6.X 反序列化漏洞             |

fofa

```
title="JBoss" || header="jboss" && port="8080" && country!="CN"
```

JMX Console 未授权访问

http://ip:port/jmx-console （默认密码 admin/admin）

jboss.deployment 部署功能 addURL() 部署 war 包