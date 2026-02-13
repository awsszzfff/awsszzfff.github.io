---
title: "身份验证漏洞-OAuth漏洞"
date: 2025-06-13
tags:
  - 基础漏洞
categories:
  - 安全相关
---
# OAuth漏洞

## OAuth

OAuth 一种授权框架，如那些允许通过第三方（QQ、微信等）登录的网站，可能使用该框架来进行身份授权验证。

eg：用微信登录 CSDN ，CSDN 会跳转至微信授权界面，申请访问账户信息（昵称、头像等），若同意授权，微信生成授权码（Code）给网站，网站用授权码向微信换取访问令牌（token），再通过令牌获取授权的信息，随后创建或绑定对应账户。

OAuth 2.0 基本运行流程：

![[attachments/20250614.png]]

OAuth 流程可以通过多种不同的方式来实现，即不同的授权类型。以下为两种最常见的授权类型：

### 授权码授权类型

![[attachments/20250614-1.png]]

1. 授权请求

客户端向授权服务器发送授权请求：

```http
GET /authorize?client_id=123  
              &redirect_uri=http://client-app.com/test  
              &response_type=code  
              &scope=profile  
              &state=abcd1234 HTTP/1.1  
Host: authorization-server.com
```

`client_id`：客户端在授权服务器的 ID（公开）。

`redirect_uri`：授权完成后，授权服务器回调客户端的地址。

`response_type`：声明授权类型，code 是授权码授权。

`scope`：告诉授权服务器，客户端要访问哪些用户数据，profile 是仅请求用户的基本信息（如用户名、头像）。

`state`：随机字符串，防止CSRF。

2. 用户登录与授权
3. 返回授权码
4. 令牌交换
5. 访问资源
6. 返回数据

### 隐式授权类型

隐式授权不需要先获取授权码再换取访问令牌，而是用户允许授权后直接获取访问令牌。

![[attachments/20250614-2.png]]

1. 授权请求

```http
GET /authorize?client_id=123  
              &redirect_uri=https://client-app.com/test  
              &response_type=token  
              &scope=profile  
              &state=abcd1234 HTTP/1.1  
Host: authorization-server.com
```

2. 用户登录与授权
3. 返回访问令牌
4. 前端访问资源
5. 返回用户数据

## 漏洞利用

1. OAuth 隐式认证绕过
2. 注册资源 SSRF 被利用
3. 存在 CSRF 缺陷用户被绑定无 state
4. CSRF 缺陷 redirect_uri 劫持 code 帐户
5. scope 篡改升级范围信息获取

## 测试

测试 OAuth 换绑实现账户接管漏洞

1. 分别在两个浏览器上注册两个账号，分别为账号 A 和账号 B；
2. 在账号A上走完一遍绑定第三方平台的流程，抓住最后绑定的那个数据包，Send to Repeater 然后 Drop 掉；
3. 在登陆了账号 B 的浏览器上，直接去访问账号 A 先前绑定的 URL，观察 B 是否新绑定了第三方平台，如果是，则存在该漏洞，否则就不存在。

> 案例：
> 
> https://mp.weixin.qq.com/s/TSsQ_mWGsFYZiF_RBdfbKg
> 
> https://mp.weixin.qq.com/s/NuNkzax8nb72qb-S1RvTnQ
> 
> https://mp.weixin.qq.com/s/QuhNuVyb2uy2T-br-mxAJw
> 
> https://mp.weixin.qq.com/s/TSsRNZtpttqXBviLwtYT9A

> 参考学习：
> 
> https://blog.csdn.net/weixin_39190897/article/details/139885599
> 
> https://mp.weixin.qq.com/s/TSsRNZtpttqXBviLwtYT9A
> 
> https://mp.weixin.qq.com/s/ATjdIxSOruY-_lCCs2kcGg
