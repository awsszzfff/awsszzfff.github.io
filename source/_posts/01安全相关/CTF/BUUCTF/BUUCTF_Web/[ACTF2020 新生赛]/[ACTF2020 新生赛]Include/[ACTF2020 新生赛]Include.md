---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "[ACTF2020 新生赛]Include"
---
# [ACTF2020 新生赛]Include

【文件包含】

打开题目页面显示一个 tips 的超链接。点击进入，页面有所显示但并不是 flag ，通过观察可以发现，这个超链接所进入的页面为原题目页面提交`/?file=flag.php`参数。

![在这里插入图片描述](img/d0effaf93ef54c6f942a071ac8f25f57.png)

所提交的参数`flag.php`，猜测应该不仅仅是打印这一句话这么简单，由于参数为`file`并且此题目为`Include`，应该是文件包含的题目。

于是尝试通过 PHP 伪协议来读取源文件。

```php
?file=php://filter/read=convert.base64-encode/resource=flag.php
```

![在这里插入图片描述](img/30257c6ad15849c8b697640e78775acb.png)

成功得到一串 base64 编码的字符串，再用工具进行解码得到 flag。

![在这里插入图片描述](img/797a08cebc564eee893506359d04aae1.png)

#### 补充

##### php伪协议

`php://` 是一种伪协议，主要是开启了一个输入输出流，理解为文件数据传输的通道。

```php
php://filter/read/convert.base64-encode/resource=php文件
```

在URL中传入参数如果是 php 文件会被 Web 容器解释，从而看不到源码。通过伪协议`php://filter`的方式来打开数据流，并将其用 base64 编码的方式读取，显示在页面上。

（PHP中还有很多伪协议）

##### 文件包含漏洞

存在文件包含漏洞条件是服务器php配置文件中以下两个参数均为 On ：

```php
allow_url_fopen=On
allow_url_include=On	// 远程文件包含
```