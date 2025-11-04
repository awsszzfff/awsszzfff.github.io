---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "Docker 镜像拉取失败"
---

在docker拉取镜像过程中,总是拉取不下来,这时候要考虑一下是不是镜像源有问题了,有没有配置可用的镜像源
例如报错如下:

Error response from daemon: 
Get "https://registry-1.docker.io/v2/":net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)

可用镜像源网站地址(点进去查看具体地址):
1. https://www.kelen.cc/dry/docker-hub-mirror#google_vignette
2. https://cloud.tencent.com/developer/article/2485043
3. https://github.com/dongyubin/DockerHub
