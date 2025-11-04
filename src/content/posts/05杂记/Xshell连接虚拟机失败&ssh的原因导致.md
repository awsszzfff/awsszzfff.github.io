---
title: "Xshell连接虚拟机失败&ssh的原因导致"
date: 2024-11-11
tags:
  - Others
categories:
  - Others
---
`ps -e | grep ssh`（检测是否安装 ssh 服务）

```shell
$ systemctl status sshd
Unit sshd.service could not be found.
$ ps -e | grep ssh
……    ssh-agent
```

安装 sshd
```shell
$ sudo apt-get install openssh-server
```

启动 sshd 服务
```shell
$ /etc/init.d/ssh start

ps -e | grep ssh    # 再次检测
```