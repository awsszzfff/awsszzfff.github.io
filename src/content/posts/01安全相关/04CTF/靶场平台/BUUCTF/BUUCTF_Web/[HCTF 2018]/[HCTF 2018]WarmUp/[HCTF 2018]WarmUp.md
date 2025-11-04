---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "[HCTF 2018]WarmUp"
---
# [HCTF 2018]WarmUp

【文件包含】

进入题目链接看到一张“猥琐”的笑脸，果断F12查看一下源码，可以发现下面有一个提示的php文件，于是直接在原链接上加上`/source.php`访问一下该文件。
![在这里插入图片描述](img/832ba5657f30406a9cea0ec14fd1257f.png)

打开后可以看到php源码，显然是一道代码审计的题目，随后开始分析。
其中不认识的函数可以直接在网上搜索。

```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];   // 白名单（其中包含两个文件）
            if (! isset($page) || !is_string($page)) {      // $page是否有值或是否为字符串
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {      // $page是否在白名单中
                return true;
            }

            $_page = mb_substr(     // 截取$page,从0开始
                $page,
                0,
                mb_strpos($page . '?', '?')     // 将$page和?进行拼接，并返回?在拼接后字符串中首次出现的位置
            );
            if (in_array($_page, $whitelist)) {     // 判断截取的字符串是否在白名单中
                return true;
            }

            $_page = urldecode($page);  // 没在则进行url编码
            $_page = mb_substr(     // 同上
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {     // 同上
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }
    
	// 主要运行代码，接受一个参数file，并对其值进行判断
    if (! empty($_REQUEST['file'])      // 判断是否为空
        && is_string($_REQUEST['file'])     // 判断是否为字符串
        && emmm::checkFile($_REQUEST['file'])       // 调用父类的方法checkFile()
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }
?>
```

根据页面显示代码，尝试直接访问`hint.php`页面，或通过`soucre.php`页面传递参数`file=hint.php`来访问提示页面。

![在这里插入图片描述](img/6c3bb9931acf4dd0864c2ce4458991c1.png)

代码中有两处会返回`true`，因此先不考虑解码的问题，先考虑使函数返回值为`true`，判断语句直接构造payload：`?file=source.php?ffffllllaaaagggg`，此时页面中的笑脸不见了，但是依旧没有`flag`。
再次考虑到提示信息，`ffffllllaaaagggg`这么多层的`flag`猜测文件相对于当前文件可能的位置，因此尝试比当前的上四级文件。
最终 payload：`?file=source.php?../../../../../ffffllllaaaagggg`

![在这里插入图片描述](img/b1fc721141f44c84a5a2588812b7c736.png)

#### 补充：

`file=hint.php%253f/../../../../../../../../ffffllllaaaagggg`也可以作为 payload。

两个 payload 都可以使得返回`true`只不过返回的位置不同。

对于第二个返回`true`要考虑到上面解码函数的问题。

URL传入`?file=hint.php%253f../../../../../ffffllllaaaagggg`，浏览器会自动解一次码，使`$page`的值变为`hint.php%3f../../../../../ffffllllaaaagggg`，代码中 URL解码，使`$_page`的值变为`hint.php?../../../../../ffffllllaaaagggg`，然后截取问号前面的 hint.php 判断在白名单里返回true。