---
title: "Redis"
date: 2025-08-28
tags:
  - Others
categories:
  - Others
description: None
---
```shell
# 客户端工具
apt install redis-tools
# Windows:Another Redis Desktop Manager
```

```shell
# 远程连接
redis-cli -h [ip] -p [port] -a [password]
```

以键值对的方式进行数据的存储

```shell
set <key> <value>	# 设置key值为value
get <key>		#  获取key对应的value
keys *			# 查看所有的key
incr <key>		# 将key的值增加1

# 配置管理
config set dir <paht>	# 设置当前工作目录
config set dbfilename redis.rdb	# 设置备份文件名
config get dbfilename	# 查看刚才设置备份文件

save	# 将上面所有的操作，进行一次备份操作
flushall	# 删除当前 Redis 实例中 所有数据库的所有数据
del key		# 删除指定key
```