---
title: "Linux&常用命令及操作"
date: 2025-08-28
tags:
  - Others
categories:
  - Others
description: None
---
## 重要目录及文件

```shell
/etc/passwd
/etc/shadow
```

```shell
/root/.ssh/id_rsa
```

## 常用命令及操作

```shell
ln -s 创建快捷方式
```

```shell
top
kill -9 id
```

```shell
ssh -i root@ip -p port
```

```bash
curl
```

```bash
# find 搜索文件
find / -name "flag*" 2>/dev/null
# -iname, type f, 
```

```bash
# netstat
netstat -anlp | grep <port>
```

```bash
# cat

# head

# tail
tail /tmp/flag.txt
tail /tmp/flag*
tail -n 20 /tmp/flag.txt

# awk
awk '{print}' /tmp/flag.txt
awk 'NR<=20' /tmp/flag.txt	# NR 行号

# sed
sed -n '1,50p' /tmp/flag.txt	# n抑制默认输出，p打印匹配行
sed '' /tmp/flag.txt		# 输出全部内容

# fold
fold -w 80 /tmp/flag.txt	# 每行按指定宽度自行拆分输出

# tac 倒序查看文件内容
tac -s '^$' /tmp/flag.txt	# 以空行作为分隔符
echo "$(tac /tmp/flag.txt)"	# 使用shell脚本执行
var=$(tac /tmp/flag.txt);echo "$var"	# 使用命令替换
tac /tmp/flag.txt | tac		# 多次逆序（同顺序）
/usr/bin/tac /tmp/flag.txt	# 使用绝对路径调用

# more	文件过长，一页一页的查看

# less
```
