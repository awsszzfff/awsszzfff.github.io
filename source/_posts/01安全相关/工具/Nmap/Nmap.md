---
title: "Nmap"
date: 2024-11-26
tags:
  - Others
categories:
  - Others
---
常用操作

```shell
nmap -v -Pn -p [port] -sV [IP]
```

常用参数说明

```txt
-v 显示详细扫描过程，扫描进度及统计信息
-Pn 跳过主机发现阶段（不ping）
-p [port] 指定端口
-sV 启用服务版本探测，应用程序及版本号
```

# Nmap

- 功能介绍

1. 检测网络存活主机（主机发现）
2. 检测主机开放端口（端口发现或枚举）
3. 检测相应端口软件（服务发现）版本
4. 检测操作系统，硬件地址，以及软件版本
5. 检测脆弱性的漏洞（nmap的脚本）

- 端口状态

```txt
Open		端口开启，数据有到达主机，有程序在端口上监控
Closed		端口关闭，数据有到达主机，没有程序在端口上监控
Filtered		数据没有到达主机，返回的结果为空，数据被防火墙或IDS过滤
UnFiltered		数据有到达主句，但是不能识别端口当前的状态
Open|Filtered		端口没有返回值，主要发生在UDP、IP、FIN、NULL和Xmas扫描中
Closed|Filtered		只发生在IP ID idle扫描
```

- 基础用法

这里以`192.168.1.1`为例

```txt
nmap -A -T4 192.168.1.1

A: 全扫描/综合扫描
T4: 扫描速度，共有6级，T0-T5

不加端口说明扫描默认端口，1-1024 + nmap-service

单一主机扫描:	nmap 192.168.1.2
子网扫描:	nmap 192.168.1.1/24
多主机扫描:	namp 192.168.1.1 192.168.1.10
主机范围扫描:	nmap 192.168.1.1-100
IP地址列表扫描:	nmap -il target.txt

扫描除指定IP外的所有子网主机: 
nmap 192.168.1.1/24 --exclude 192.168.1.1

扫描除文件中IP外的子网主机: 
nmap 192.168.1.1/24 --excludefile xxx.txt

扫描特定主机上的80,21,23端口: 
nmap -p 80,21,23 192.168.1.1
```

- 扫描全部端口

```txt
nmap -sS -v -T4 -Pn -p 0-65535 -oN FullTCP -il liveHosts.txt

- -sS：SYN扫描，又称半开放扫描，它不打开一个完全的TCP连接，执行快，效率高（一个完整的tcp连接需要3次握手，-sS不需要3次握手）

优点：Nmap发送SYN包到远程主机，但是不会产生任何会话，目标主机几乎不会把连接记入系统日志（防止对方判断为扫描攻击）
缺点：需要root/administrator权限执行

- -Pn：扫描前不需要用ping命令，有些防火墙禁止ping命令。
- -iL：导入需要扫描的列表
```

- 扫描常用端口及服务信息

```txt
nmap -sS -T4 -Pn -oG TopTCP -iL Livehosts.txt

系统扫描
nmap -O -T4 -Pn -oG OSDetect -iL LiveHosts.txt

版本检测
nmap -sV -T4 -Pn -oG ServiceDetect -iL LiveHosts.txt
```

- 漏洞扫描

`nmap -p445 -v --script smb-ghost 192.168.1.0/24`



> 参考学习：
> 
> https://wiki.wgpsec.org/knowledge/tools/nmap.html
> 
> https://blog.csdn.net/Kris__zhang/article/details/106841466
> 
> https://wcute.github.io/2019/03/29/Nmap%20%E5%B8%B8%E7%94%A8%E5%91%BD%E4%BB%A4%E6%80%BB%E7%BB%93/
> 
> https://nmap.org/man/zh/ 【中文参考指南】

