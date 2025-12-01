---
title: "SSRF"
date: 2001-01-01
tags:
  - Others
categories:
  - Others
---
服务器端请求伪造

![[attachments/1.png]]

前端用户可以输出任意 URL 到后端服务器，而服务器没有对其 URL 进行严格的过滤和校验，导致攻击者可以构造一些恶意的 URL 让服务器去访问执行；

![[attachments/1-1.png]]

## 主要影响

- 读取服务器本地文件；
- 探测内网存活主机和开放端口；
- 攻击其他内网服务器及服务；

（绕过 CDN 来查找真实 IP；）

## 探测业务功能点

1. 社交分享功能：获取超链接的标题等内容进行显示；
2. 转码服务：通过 URL 地址把原地址的网页内容调优使其适合手机屏幕浏览；
3. 在线翻译：给网址翻译对应网页的内容；
4. 图片加载/下载：例如富文本编辑器中的点击下载图片到本地；通过URL地址加载或下载图片；
5. 图片/文章收藏功能：主要其会取 URL 地址中 title 以及文本的内容作为显示以求一个好的用具体验；
6. 云服务厂商：它会远程执行一些命令来判断网站是否存活等，所以如果可以捕获相应的信息，就可以进行 ssrf 测试；
7. 网站采集，网站抓取的地方：一些网站会针对你输入的 url 进行一些信息采集工作；
8. 数据库内置功能：数据库的比如 mongodb 的 copyDatabase 函数；
9. 邮件系统：比如接收邮件服务器地址；
10. 编码处理, 属性信息处理，文件处理：比如 ffpmg，ImageMagick，docx，pdf，xml 处理器等；
11. 未公开的 api 实现以及其他扩展调用 URL 的功能：可以利用 google 语法加上这些关键字去寻找 SSRF 漏洞；

视频解析，格式转换，代码执行，在线笔记，数据采集等

## URL 中的关键参数

- `share、wap、url、link、src、source、target、u、display、sourceURl、imageURL、domain`；

## 伪协议利用

- `http://`：Web常见访问，如`http://127.0.0.1`；
- `file:///`：从文件系统中获取文件内容，如`file:///etc/passwd`；
- `dict://`：字典服务器协议，访问字典资源，如`dict:///ip:6739/info：`；
- `sftp://`：SSH 文件传输协议或安全文件传输协议；
- `ldap://`：轻量级目录访问协议；
- `tftp://`：简单文件传输协议；
- `gopher://`：分布式文档传递服务，可使用 gopherus 生成 payload；由于有部分协议 http 这类不支持，可以 gopher 来进行通讯（mysql，redis 等）；

## 限制及绕过方式

- 限制 `http://www.xxx.com` 的域名；

采用 http 基本身份认证的方式进行绕过，即 @；

eg：`http://www.xxx.com@www.xxyy.com`

> 标准 URL 格式：`协议://用户名:密码@域名/路径`；
> 
> 这里 `www.xxx.com` 被当作**用户名**，而 `www.xxyy.com` 是实际的**域名**；

绕过正则匹配之类的限制；

- 限制请求 IP 不能为内网地址；

短网址绕过、域名解析、进制转换、3XX 重定向；

以 127.0.0.1 为例：

对限制的 IP 进行编码（十六进制、八进制、十进制等【不仅编码数字，有时需要对中间的`.`也进行编码】）；

绕过 localhost 简写为 127.1；或 127.127.127.127；或 0；或 0.0.0.0；

域名解析 IP：将攻击者的域名网站对应的域名解析在服务器上配置域名解析为 127.0.0.1；eg：test.hello.com -> 127.0.0.1；此时，发送请求目标为 test.hello.com ，目标网站会请求 127.0.0.1；

重定向解析绕过：攻击者网站 xx.php：`<?php header("Location:http://127.0.0.1/flag.php");`；发送请求目标为 `test.hello.com/xx.php`；

## 漏洞防御

1. 过滤返回信息，验证远程服务器对请求的响应是比较容易的方法;
2. 统一错误信息，避免用户可以根据错误信息来判断远端服务器的端口状态；
3. 限制请求的端口为 http 常用的端口，比如，80,443,8080,8090；
4. 黑名单内网 ip；避免应用被用来获取获取内网数据，攻击内网；
5. 禁用不需要的协议；仅仅允许 http 和 https 请求。可以防止类似于 `file:///`、`gopher://`、`ftp://` 等引起的问题；

这里以国光的 ssrf 靶场为例：

> https://github.com/sqlsec/ssrf-vuls
> 
> https://github.com/Duoduo-chino/ssrf-vul-for-new

![[attachments/1-2.png]]

> 攻击流程，172.150.23.21 这个服务器的 Web 80 端口存在 SSRF 漏洞，并且 80 端口映射到了公网的 9080，此时攻击者通过这个 9080 端口可以借助 SSRF 漏洞发起对 172 目标内网的探测和攻击；

其中一个示例：172.150.23.24 页面 ping 执行系统命令；

当请求内网地址 172.150.23.24 时，需要让**服务器**/原目标主机触发该 ping 数据包（自己直接在该页面 ping 是失效的）；由于该数据包是 post 请求；post 需要转为 gopher 协议；`gopher://ip:port/_xxxxxx` 来触发 172.159.23.24 rce 漏洞数据包；

（不可能通过 `http://172.159.23.24/?ip=127.0.0.1;cat /flag`这样的请求是不能触发 post 请求来发包；所以需要上方所提到的这种方式来提交；）

一种玩法：有哪种在线加载 HTML 页面功能的站或是对输入的内容会自动解析为 HTML 标签来处理，这样可以通过`iframe`标签来期望页面直接回显出目标内网的内容；eg：`"<iframe src=\"http://127.0.0.1\">"`；

可以利用 HaE 和 Auto-SSRF 插件配合使用自动化的检测漏洞；

> 参考学习：
> 
> https://mp.weixin.qq.com/s/99pPa1jrLR1t7_x40eH8TQ （Auto-SSRF 插件搜索配置）
> 
> https://mp.weixin.qq.com/s/63fC5STI5WAKn7O6c02kyQ
> 
> https://mp.weixin.qq.com/s/zXH3nudCY1VEj8AFMgwwXQ
