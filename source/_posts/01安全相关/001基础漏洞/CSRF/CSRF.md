---
title: "CSRF"
date: 2001-01-01
tags:
  - Others
categories:
  - Others
---
# CSRF

跨站请求伪造

![[attachments/1.png]]

![[attachments/1-1.png]]

## 基本场景

用户 A 通过网上银行给用户 B 支付，同时 A 访问了攻击者 C 的网站，该网站模拟网上银行支付数据操作给 C 进行支付，此时导致 A 以自己的身份触发了支付请求 -> C；

![[attachments/1-2.png]]

![[attachments/1-3.png]]

示例：

用户登录 A 网站更改密码；攻击者获取相同（类似）网站的数据包（或是 URL【最基础的情况下】）；利用 BurpSuite 带有的功能生成 CSRF Poc；（`BurpSuite->Engagement tools->Generate CSRF Poc`）放在攻击者网站诱使用户访问触发；

## 防护与绕过

主要利用一些同源策略；CSRF_token ；或网站自身的一些过滤机制来防护；

- 删除令牌并发送带有空白参数的请求；（置空）（eg：`<meta name="referrer" content="no-referrer">`）
- `http://xxx.xxx.xxhttp://xxx.xxx.xx`；
- 域名；eg：baidu.com -> xxxxxbaidu.com；
- 所创建的文件或文件名包含期望的 IP 或域名；
- 利用文件上传的功能绕过同源策略；

## PS

HTML 部分标签在引用第三方资源时不受同源策略的影响；eg：`<script>、<img>、<iframe>、<link>`等；

> 同源策略：两个网站的域名、端口、协议；三者是否完全相同；

> CSRF + XSS 组合拳；如之前所提到的 XSS 的部分攻击方式；

简单的示例：假设修改密码的 URL 为：

```paylaod
http://127.0.0.1/csrf/?password_new=111&password_conf=111&Change=Change#
```

此时攻击者构造带有 XSS 攻击语句的页面钓鱼：

```html
<html>
<head>
    <title>XSS&CSRF</title>
</head>
<body>
<script src="http://127.0.0.1/csrf/?password_new=222&password_conf=222&Change=Change#"></script>
</body>
</html>
```

用户一旦访问则会触发 script 标签中的内容，从而密码被修改~






