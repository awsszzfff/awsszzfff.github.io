---
title: "HTTP相关"
date: 2025-02-22
tags:
  - Others
categories:
  - Others
---
请求及返回头的一些字段含义：

![[attachments/Pasted image 20250222193518.png]]

![[attachments/Pasted image 20250222193527.png]]

![[attachments/Pasted image 20250222193541.png]]

请求头

![[attachments/Pasted image 20250222193546.png]]

返回头

![[attachments/Pasted image 20250222193550.png]]

Request 有 8 种不同的请求方法；

根据 Response 状态码来判断：数据是否正常、文件是否存在、地址自动跳转、服务提供错误；

注：容错处理识别

- 1xx：指示信息—表示请求已接收，继续处理。
- 2xx：成功—表示请求已经被成功接收、理解、接受。
	- 200 OK：客户端请求成功
- 3xx：重定向—要完成请求必须进行更进一步的操作。
	- 301 redirect：页面永久性移走，服务器进行重定向跳转；
	- 302 redirect：页面暂时性移走，服务器进行重定向跳转，具有被劫持的安全风险；
- 4xx：客户端错误—请求有语法错误或请求无法实现。
	- 400 BadRequest：由于客户端请求有语法错误，不能被服务器所理解；
	- 401 Unauthonzed：请求未经授权。
	- 403 Forbidden：服务器收到请求，但是拒绝提供服务。
	- 404 NotFound：请求的资源不存在，例如，输入了错误的URL；
- 5xx：服务器端错误—服务器未能实现合法的请求。
	- 500 InternalServerError：服务器发生不可预期的错误，无法完成客户端的请求；
	- 503 ServiceUnavailable：服务器当前不能够处理客户端的请求







