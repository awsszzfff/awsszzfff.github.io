---
title: Windows常用命令&基本操作
date: 2022-06-26
updated: 2022-06-26
tags:
  - Windows
categories:
  - 计算机基础
description: Windows常用命令&基本操作
---
certmgr.msc 证书管理，Fiddler 证书 DO_NOT_TRUST_FiddlerRoot，BurpSuite 证书 PorSwiggerCA 。

```shell
netstat -anb | more

netstat -ano | findstr 端口号
taskkill /pid 进程号 /f
```