---
title: "kali ssh"
date: 2001-01-01
tags:
  - Others
categories:
  - Others
---
`systemctl enable ssh`或`systemctl start ssh`

查看是否开启

`systemctl status ssh`

`Active:inactive(dead)`则表示没有开启
`Active: active (running)`表示已经开启

kali 默认禁止直接 root 用户远程登录，需修改配置文件：

编辑 `sshd_config` 文件 `vim /etc/ssh/sshd_config`

`set nu`显示行号

第34行 `permitRootLogin yes` 取消注释，保存即可；（若没有该参数自己添加即可）

`systemctl reload ssh` 重新载入配置文件；
