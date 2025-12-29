---
title: JAVA安全基础漏洞
date: 2025-12-28
updated: 2025-12-28
tags:
  - Java安全
categories:
  - 安全相关
description: None
---
## SQL 注入

### 动态拼接

java.sql.Statement

`createStatement()` + 动态拼接 `executeQuery()` 执行，一般会存在 SQL 注入漏洞

将接口参数 id 直接定义为 int 则不会存在 SQL 注入漏洞

### 错误的预编译

java.sql.PreparedStatement

setString

错误的预编译，虽然使用了 prepareStatement ，但若使用动态拼接还是会存在漏洞

在使用 order by 时无法使用预编译，还是只能使用原始的方法

### Mybatis

`#{}` 和 `${}` 拼接 SQL 语句，用第二种会存在漏洞（`#{}` 本身也是一种预编译，底层还是用 jdbc 上面那种预编译方法）

但 `order by`、`like`、`in` 也是无法进行预编译
