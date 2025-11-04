---
title: "Web安全开发基础-PHP"
date: 2025-01-14
tags:
  - Others
categories:
  - Others
---
## PHP 超级全局变量

![[attachments/20250114134240.png]]

![[attachments/20250114134246.png]]

![[attachments/20250114134309.png]]

![[attachments/20250114134317.png]]

- 变量覆盖安全：
	- `$GLOBALS`：这种全局变量用于在 PHP 脚本中的任意位置访问全局变量；

- 数据接收安全：
	- `$_REQUEST`：用于收集 HTML 表单提交的数据；
	- `$_POST`：广泛用于收集提交 method="post" 的 HTML 表单后的表单数据；
	- `_GET`：收集 URL 中的发送的数据。也可用于提交表单数据（method="get"）；
	- `$_ENV`：是一个包含服务器端环境变量的数组；
	- `$_SERVER`：这种超全局变量保存关于报头、路径和脚本位置的信息；

- 文件上传安全：
	- `$_FILES`：文件上传且处理包含通过 POST 方法上传给当前脚本的文件内容；

- 身份验证安全：
	- `$_COOKIE`：是一个关联数组，包含通过 cookie 传递给当前脚本的内容；【在本地客户端浏览器存储】
	- `$_SESSION`：是一个关联数组，包含当前脚本中所有 session 内容；【在目标服务器存储，存储记录的数据】

案例复现：
1. DuomiCMS 变量覆盖

搭建 DuomiCMS 网站，访问`http://duomicms.com:83/admin/login.php`即后台登录页面

通过代码审计来寻找漏洞点【比较复杂，之后再学习重新分析复现】

找变量覆盖代码 -> 找此文件调用 -> 选择利用覆盖 session -> 找开启 session 文件覆盖

> 参考： https://blog.csdn.net/qq_59023242/article/details/135080259

Payload：`/interface/comment.php?_SESSION[duomi_admin_id]=10&_SESSION[duomi_group_id]=1&_SESSION[duomi_admin_name]=zmh`

2. YcCMS 任意文件上传

找文件上传代码 -> 找此文件调用 -> 找函数调用 -> 过滤 type 用 mime 绕过

> 参考： https://zhuanlan.zhihu.com/p/718742254

Payload：`?a=call&m=upLoad send`

## 登录验证相关

Cookie：存储在客户端浏览器中；用户发送请求验证，服务器设置 Cookie 并将其给用户保存；

- `$_COOKIE`：是一个关联数组，包含通过 cookie 传递给当前脚本的内容；
- `setcookie()`：设置一个 cookie 并发送到客户端浏览器；
- `unset()`：用于删除指定的cookie。

Session：存储在服务器；返回给用户的是一个 SessionID，每次访问时用户带着 SessionID ，服务器与本地存储的 SessionID 对应的文件进行比较；

- `session_start()`：启动会话，用于开始或恢复一个已经存在的会话；
- `$_SESSION`：是一个关联数组，包含当前脚本中的所有session内容；
- `session_destroy()`：销毁当前会话中的所有数据；
- `session_unset()`：释放当前会话中的所有变量；

Session 存储路径：`php.ini`中 `session.save_path` 设置路径

Token：

~~【好像依旧是依靠 Cookie 和 Session 所构建的；生成的 Token 存储在 Session 中，绑定 Cookie；（客户端只存储 token 不保存登录信息；）】~~

HTTP 头中的 Authorization字段来传递 token 信息，方便跨域访问；

【对 Token 依旧不太了解；还有一种新的校验机制 JWT （好像也只是一种令牌格式）本质还是 Token】， JWT（Json Web Token）它会通过`[[header][pyload][signature]]`实现加密前面等操作，来完成登录验证操作；存储在客户端。

可能存在的问题就是窃取 Cookie，Token 校验缺陷或是生成算法过于简单被猜解等；

> 示例： https://xz.aliyun.com/news/1730

## 弱类型脆弱

PHP 中的数据类型是弱类型；

- \`\==\`比较缺陷

弱比较，php 解析器会做隐式类型转换，若两个值的类型不相等就将两个值的类型转换为同一类型进行对比；

- MD5 比较缺陷

进行 hash 加密出来的字符串若存在 0e 开头进行弱比较的话直接判定为 true；

```
QNKCDZO
0e830400451993494058024219903391
240610708
0e462097431906509019562988736854
s878926199a
0e545993274517709034328855841020
s155964671a
0e342768416822451524974117254469
s214587387a
0e848240448830537924465865611904 
s214587387a
0e848240448830537924465865611904
s878926199a
0e545993274517709034328855841020
s1091221200a
0e940624217856561557816327384675
s1885207154a
0e509367213418206700842008763514
```

- 函数`strcmp`类型比较存在缺陷

低版本的`strcmp`比较的是字符串类型，若强行传入其他类型参数，会进行报错并返回 0，利用这一点可以绕过；

 - 函数`Bool`类型比较缺陷

在使用 `json_decode()` 函数或 `unserialize()` 函数时，部分结构被解释成 bool 类型，也会造成缺陷；

示例：

```php
// str传入该值即可绕过：$str = '{"user":true,"pass":true}';

$str=$_GET['s'];
$data = json_decode($str,true);
if ($data['user'] == 'root' && $data['pass']=='123456')
{
   print_r(' 登录成功！ '."\n");
}else{
   print_r(' 登录失败！ '."\n");
}

// 预期：a:2:{s:4:"user";s:4:"root";s:4:"pass";s:6:"xiaodi";}
// 绕过：$str = 'a:2:{s:4:"user";b:1;s:4:"pass";b:1;}';
$str=$_GET['s'];
$data = unserialize($str);
if ($data['user'] == 'root' && $data['pass']=='123456')
{
   print_r(' 登录成功！ '."\n");
} else{
   print_r(' 登录失败！ '."\n");
}
```

- 函数 switch 类型比较缺陷

当在 switch 中使用 case 判断数字时，switch 会将参数转换为 int 类型计算；

- 函数 in_array 数组比较缺陷

当使用 `in_array()` 或 `array_search()` 函数时，如果第三个参数没有设置为 true，则 `in_array()` 或 `array_search()`将使用松散比较来判断；

- \`\=\==\` 数组比较缺陷

在 `md5()` 函数传入数组时会报错返回 NULL，当变量都导致报错返回 NULL 时就能使使得条件成立；

示例：

```php
if ($_GET['username'] !== $_GET['password'] && 
md5($_GET['username']) === md5($_GET['password']))
	die('Flag: '.$flag);
# username[]=1&password[]=2 则可绕过
```

（三等号需要一些特定的函数如这里的 md5 函数，其返回值可以控制则可以利用该条件绕过）

## 模版引擎

为了让前端界面与程序代码分离的一种解决方案，即 html 文件里再也不用写 php 代码；

eg：Smarty 模版引擎，只需在 html 文件中写好 Smarty 标签即可，例 `{name}`，然后调用 Smarty 的方法传递变量参数即可；

可能存在的漏洞：SSTI（Server Side Template Ingection，服务器端模版注入）

> https://xz.aliyun.com/t/11108
> 
> https://www.cnblogs.com/magic-zero/p/8351974.html

## 插件组件

如 文本编辑器，邮箱，图片处理等功能；

> https://www.cnblogs.com/qq350760546/p/6669112.html
> 
> https://www.cnblogs.com/linglinglingling/p/18040866
> 
> https://xz.aliyun.com/t/13432
> 
> https://www.cnblogs.com/TaoLeonis/p/14899198.html

## 框架

利用框架开发，类似于套用公式式的进行开发，对于页面的访问与渲染，数据库的操作等都运用框架自己所定义的方式，而不是传统的路径。

可能更安全（eg：SQL 注入，框架自身已经写好了过滤方式）也可能更危险（框架漏洞）

eg：ThinkPHP 自身所定义的一种数据库查询开发书写格式：`Db::table('think_user')->where('status',1)->select();`

## 文件操作

`$_FILES`：PHP中一个预定义的超全局变量，用于在上传文件时从客户端接收文件，并将其保存到服务器上。它是一个包含上传文件信息的数组，包括文件名、类型、大小、临时文件名等信息。

- `$_FILES["表单值"]["name"]` 获取上传文件原始名称；
- `$_FILES["表单值"]["type"]` 获取上传文件MIME类型；
- `$_FILES["表单值"]["size"]` 获取上传文件字节单位大小；
- `$_FILES["表单值"]["tmp_name"]` 获取上传的临时副本文件名；
- `$_FILES["表单值"]["error"]` 获取上传时发生的错误代码；

- `move_uploaded_file()` 将上传的文件移动到指定位置的函数；

文件显示

- `is_dir()` 用于检查指定的路径是否是一个目录；
- `opendir()` 用于打开指定的目录，返回句柄，用来读取目录的文件和子目录；
- `readdir()` 用于从打开的目录句柄中读取目录中的文件和子目录；
- `open_basedir` PHP.INI 中的设置，用来控制脚本程序访问目录；
- `scandir()` 返回指定目录中的文件和目录，以数组形式返回；
- `ini_set('open_basedir',__DIR__);` 设置配置文件中，只能访问本目录；

文件删除

- `unlink()`文件删除函数，还可调用系统命令删除文件 `system shell_exec exec` 等；

文件下载，修改 HTTP 头实现文件读取解析下载：

```php
header("Content-Type: application/octet-stream");
header("Content-Disposition: attachment; filename=\"" . $file . "\"");
header("Content-Length: " . filesize($file));
readfile($file);
```

文件读取

- `file_get_contents()` 读取文件内容；
- `fopen() fread()` 文件打开读入；

文件包含

`include、require、include_once、require_once` 等

> 审计案例：
> 
> - Rrzcms遍历读取 https://xz.aliyun.com/t/10932
> - Metinfo文件下载 https://mp.weixin.qq.com/s/te4RG0yl_truE5oZzna3Eg
> - Xhcms文件包含 https://xz.aliyun.com/t/11310

## 代码&命令执行

> https://www.yisu.com/ask/52559195.html
> 
> https://www.jb51.net/article/264470.htm

```php
# 容易导致代码执行的 PHP 函数
assert()
pcntl_exec()
array_fi lter()
preg_replace
array_map()
require()
array_reduce()
require_once()
array_diff_uassoc()
register_shutdown_function()
array_diff_ukey()
register_tick_function()
array_udiff()
set_error_handler()
array_udiff_assoc()
shell_exec()
array_udiff_uassoc()
stream_fi lter_register()
array_intersect_assoc()
system()
array_intersect_uassoc()
usort()
array_uintersect()
uasort()
array_uintersect_assoc()
uksort()
array_uintersect_uassoc()
xml_set_character_data_handler()
array_walk()
xml_set_default_handler()
array_walk_recursive()
xml_set_element_handler()
create_function()
xml_set_end_namespace_decl_handler()
escapeshellcmd()
xml_set_external_entity_ref_handler()
exec()
xml_set_notation_decl_handler()
include
xml_set_processing_instruction_handler()
include_once()
xml_set_start_namespace_decl_handler()
ob_start()
xml_set_unparsed_entity_decl_handler()

# 容易导致命令执行的函数
exec()
system()
passthru()
popen()
shell_exec()
pcntl_exec()
```

> 审计案例
> 
> - Yccms 代码执行 https://mp.weixin.qq.com/s/4i4MLsNAlMuLjySBc_rySw
> - CmsEasy 代码执行 https://xz.aliyun.com/t/2577
> - BJCMS 命令执行 https://blog.csdn.net/qq_44029310/article/details/125860865
> - WBCE 命令执行 https://developer.aliyun.com/article/1566395
> - D-Link 命令执行 https://xz.aliyun.com/t/2941
> - 安恒明御安全网关 https://blog.csdn.net/smli_ng/article/details/128301954

## 修复

> https://www.yisu.com/ask/28100386.html
> 
> https://blog.csdn.net/u014265398/article/details/109700309
> 
> https://www.cnblogs.com/xiaochaohuashengmi/archive/2011/10/23/2222105.html

PHP.INI 配置

- 安全模式 safe_mode 命令执行函数会被禁用
- \*路径访问 open_basedir 限制文件操作安全（遍历等）
- \*禁用函数 disable_function 升级版安全模式，自定义限制函数
- \*魔术引号转义 magic_quotes_gpc 同理下面的sql过滤第一个函数
- 数据库访问次数 max_connections 防止数据库爆破
- 禁用远程执行 allow_url_include allow_url_fopen 远程包含开关等
- \*安全会话管理 session.cookie_httponly session.cookie_secure
- 防止跨站脚本攻击（XSS）和中间人攻击（MITM）

代码-内置函数来过滤

```php
# 检测：数据的类型差异，数据的固定内容
gettype()	获取变量的类型
is_float()	检测变量是否是浮点型
is_bool()	检测变量是否是布尔型
is_int()	检测变量是否是整数
is_null()	检测变量是否为NULL
is_numeric()	检测变量是否为数字或数字字符串
is_object()		检测变量是否是一个对象
is_resource()	检测变量是否为资源类型
is_scalar()		检测变量是否是一个标量
is_string()		检测变量是否是字符串
is_array()		检测变量是否是数组
filter_var()	使用特定的过滤器过滤一个变量
FILTER_SANITIZE_STRING 	过滤器可以过滤HTML标签和特殊字符
FILTER_SANITIZE_NUMBER_INT 	过滤器可过滤非整数字符
FILTER_SANITIZE_URL 	过滤器用于过滤URL中的非法字符 
FILTER_VALIDATE_EMAIL 	过滤器来验证电子邮件地址的有效性
```

```php
# SQL注入过滤：
Addslashes()	返回字符串，该字符串为了数据库查询语句等的需要在某些字符前加上了反斜线。这些字符是单引号()、双引号(”)、反斜线()与NULL字符)。
stripslashes()	反引用一个引用字符串,如果magic_quotes_sybase项开启，反斜线将被去除，但是两个反斜线将会被替换成一个。
addcslashes()	返回字符串，该字符串在属于参数charlist列表中的字符前都加上了反斜线。
stripcslashes()	返回反转义后的字符串。可识别类似C语言的\n，r，…八进制以及十六进制的描述。
mysql_escape_string()	此函数并不转义%和_。作用和mysql real escape_string()	基本一样
mysql_real_escape_string()	调用mysql库的函数在以下字符前添加反斜杠:x00、\n、\r、\、x1a
PHP魔术引号当打开时，所有的'(单引号)，”(双引号)，(反斜线)和NULL字符都会被自动加上一个反斜线进行转义。这和addslashes()作用完全相同。
预编译机制
```

```php
# XSS跨站过滤：
htmlspecialchars()	函数把预定义的字符转换为HTML实体。
strip_tags()	函数剥去字符串中的HTML、XML以及PHP的标签。
```

```php
# 命令执行过滤
escapeshellcmd()	确保用户只执行一个命令用户可以指定不限数量的参数用户不能执行不同的命令
escapeshellarg()	确保用户只传递一个参数给命令用户不能指定更多的参数一个用户不能执行不同的命令
```

引用全局文件（将预设的各种过滤函数或正则写入一个全局文件的函数中）来过滤；

通过 WAF 或 AI 算法来过滤；
