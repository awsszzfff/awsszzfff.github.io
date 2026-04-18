---
title: Weblogic各版本漏洞
date: 2025-09-27
updated: 2025-09-27
tags:
  - 服务组件框架漏洞
  - Java安全
categories:
  - 安全相关
description: Weblogic各版本漏洞
published: false
---
默认端口：7001

Web 界面：Error 404 -- Not Found

控制后台：http://ip:7001/console

主要影响版本：

- Weblogic 10.3.6.0
- Weblogic 12.1.3.0
- Weblogic 12.2.1.1
- Weblogic 12.2.1.2
- Weblogic 12.2.1.3
- Weblogic 14.1.1.0

| 漏洞类型           | CVE 编号          |
| -------------- | -------------- |
| SSRF           | CVE-2014-4210  |
| 任意文件上传         | CVE-2018-2894  |
| XMLDecoder 反序列化 | CVE-2017-3506  |
|                | CVE-2017-10271 |
|                | CVE-2019-2725  |
|                | CVE-2019-2729  |
| Java 反序列化       | CVE-2015-4852  |
|                | CVE-2016-0638  |
|                | CVE-2016-3510  |
|                | CVE-2017-3248  |
|                | CVE-2018-2628  |
|                | CVE-2018-2893  |
|                | CVE-2020-2890  |
|                | CVE-2020-2555  |
|                | CVE-2020-14645 |
|                | CVE-2020-14756 |
|                | CVE-2021-2109  |
| 弱口令            | Weblogic       |
|                | Oracle@123     |

fofa

```
app="BEA-WebLogic-Server" && port==7001 && country!="CN"
```

弱口令

```
访问路径：/console
账号：weblogic
密码：Oracle@123
```

默认口令

```
system/password
system/Passw0rd
weblogic/weblogic
admin/security
joe/password
mary/password
system/security
wlcsystem/wlcsystem
wlpisystem/wlpisystem
```

## Weblogic SSRF CVE-2014-4210

`/uddiexplorer/SearchPublicRegistries.jsp` 页面

利用 SSRF 攻击内网 Redis

设定工作目录，写定时任务

## 未授权任意文件上传 CVE-2018-2894

受影响版本 10.3.6.0、12.1.3.0、12.2.1.2、12.2.1.3

受影响模块为 web 服务测试页面（默认情况下不启用）

（启用方法：登录控制台 -> base_domain -> 高级 -> 勾选启用 Web 服务测试页 -> 保存）

- /ws_utc/config.do
- /ws_utc/begin.do

设置工作目录（ws_uts 应用的静态文件 css 目录，访问时无需权限）

```
/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css
```

上传文件，响应中有时间戳，它和文件名拼接即为最终文件目录

```
http://your-ip:7001/ws_utc/css/config/keystore/[时间戳]_[文件名]
```

## 反序列化远程代码执行 CVE-2019-2725

影响版本

- Oracle WebLogic Server 10.*
- Oracle WebLogic Server 12.1.3

影响组件

- bea_wls9_async_response.war：`/_async/AsyncResponseService`
- wsat.war：`/wls-wsat/CoordinatorPortType`













PS:

部署 war 包，修改访问路由，访问...

```bash
# 制作 war 包
jar cvf 1.war 1.jsp
```

