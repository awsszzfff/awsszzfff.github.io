---
title: "身份验证漏洞-JWT漏洞"
date: 2025-06-12
tags:
  - 基础漏洞
categories:
  - 安全相关
---
# JWT 漏洞
## JWT

JSON Web Token （JWT）一种标准化格式，用于在系统之间发送加密签名的 JSON 数据。常用于发送有关用户信息的声明，作为身份验证、会话处理和访问控制机制的一部分。

常用于验证用户身份信息及跨域的身份验证，一旦用户登录，后续每个请求都将包含 JWT ，系统在每次处理用户请求之前，都要进行 JWT 安全校验。

![[attachments/20250613.png]]

JWT 由三部分构成`[[header][pyload][signature]]`：

- header 头部，用来声明此 JWT 的类型和加密算法，通常由 alg 和 typ 两个字段及一些可选参数组成；
	- alg ：当前采用的加密算法；
	- typ ：类型；
- pyload 载荷，各种明文数据，eg：id、用户名、token 生成时间等；
	- iss ：JWT 的签发者；
	- sub ：该 JWT 面向用户；
	- aud ：JWT 的接收方；
	- exp ：过期时间；
	- iat ：签发时间；
	- jti ：唯一表示，通常用于解决请求中的重放攻击；
- signature 签证，对 header 和 payload 进行签名；

一般存储在请求头的 Authorization、Cookie 或请求体里面。

## JWT 攻击

![[attachments/image7.jpg]]

## 攻击检测方法

首先找到需要JWT鉴权后才能访问的页面，如个人资料页面，将请求重放测试：

- 未授权访问：删除 Token 后仍然可以正常响应对应页面；
- 敏感信息泄露：通过 JWt.io 解密出 Payload 后查看其中是否包含敏感信息，如弱加密的密码等；
- 破解密钥+越权访问：通过 JWT.io 解密出 Payload 部分内容，通过空加密算法或密钥爆破等方式实现重新签发 Token 并修改 Payload 部分内容，重放请求包，观察响应包是否能够越权查看其他用户资料；
- 检查 Token 时效性：解密查看 payload 中是否有 exp 字段键值对（Token 过期时间），等待过期时间后再次使用该 Token 发送请求，若正常响应则存在 Token 不过期；
- 通过页面回显进行探测：如修改 Payload 中键值对后页面报错信息是否存在注入， payload 中 kid 字段的目录遍历问题与 sql 注入问题；

> 案例：
> 
> https://mp.weixin.qq.com/s/obiU3BaFoZ7272z2vS0QgQ
> 
> https://mp.weixin.qq.com/s/ITVFuQpA8OCIRj4wW-peAA
> 
> https://mp.weixin.qq.com/s/xuY1oTwFcM1pyiql0U3NPQ
> 
> https://mp.weixin.qq.com/s/AVW8DsnLiviopeJYQYKC3A
> 
> https://mp.weixin.qq.com/s/st0xma6KoRbo1NUp9rtZhw
> 
> https://mp.weixin.qq.com/s/9OL5jZK7S1MiEUb8Q_F1Pw

> 参考学习：
> 
> https://blog.csdn.net/weixin_44288604/article/details/128562796
> 
> https://blog.csdn.net/uuzeray/article/details/142681561

