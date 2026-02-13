---
title: "Web安全开发基础-JS"
date: 2025-08-06
tags:
  - Others
categories:
  - Others
---
> 学习文档：
> 
> - 原生JS教程 https://www.w3school.com.cn/js/index.asp
> - jQuery库教程 https://www.w3school.com.cn/jquery/index.asp
> - Axios库教程 https://www.axios-http.cn/docs/intro

![[attachments/20250806.png]]

## JS 基础
### Ajax

Ajax 主要作用：

- 数据交换，通过 Ajax 可给服务器发送请求，并获取服务器响应的数据；
- 后台发送：浏览器的请求是后台js发送给服务器的，js会创建单独的线程发送异步请求，这个线程不会影响浏览器的线程运行；
- 局部刷新：浏览器接收到结果以后进行页面局部刷新

> JS 使用外部库都需要先进行远程或本地加载

基本编写示例：

```js
// 原生 JavaScript AJAX 示例（使用 XMLHttpRequest 对象）
<script type="text/javascript">    
    var xhttp = new XMLHttpRequest();
    // 初始化请求，GET请求1.txt文件，异步执行  
    xhttp.open("GET", "1.txt", true);  
    xhttp.send();  // 请求发送
    // 设置回调函数，监听请求状态变化
    xhttp.onreadystatechange = function() {  
    	// 当请求完成 (readyState == 4) 且响应成功 (status == 200) 时执行
        if (xhttp.readyState == 4 && xhttp.status == 200){  
            console.log(xhttp.responseText);  // 打印
        }  
    }  
</script>
```

```js
// 使用 jQuery 库实现 AJAX 技术
<!-- 引入 jQuery 库文件 -->
<script src="https://code.jquery.com/jquery-3.7.1.js"></script>
<script src="jquery-3.7.1.min.js"></script>
<script>    
    // 调用 jQuery 的 ajax() 方法发送 AJAX 请求
    $.ajax({
        method: "GET",           // 请求方法为 GET
        url:"1.txt",             // 请求的目标 URL
        dataType: "text",        // 预期服务器返回的数据类型为文本
        success: function(response){  // 请求成功时的回调函数
            console.log(response);    // 输出响应内容到控制台
        }
    });
</script>
```

```js
// 使用 axios 库实现 AJAX 技术
<!-- 引入 axios 库文件 -->
<script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
<script src="axios.min.js"></script>
<script>    
    
    // 方式一：使用 axios() 方法配置完整参数
    axios({
        method: 'GET',    // 请求方法
        url: '1.txt',     // 请求地址
    }).then(function (response) {  // 使用 then() 方法处理成功响应
        console.log(response.data); // 输出响应数据（response.data 包含实际内容）
    })

    // 方式二：使用 axios 提供的便捷方法 axios.get()
    axios.get('1.txt').then(function (response) {  // 直接发送 GET 请求
        console.log(response.data);  // 输出响应数据
    })
</script>
```

```js
<form action="file.php" method="post" enctype="multipart/form-data">  
    选择文件：<input type="file" name="file_upload" onchange="checkFile(this.value)">  
    <input type="submit" value="上传">  
</form>  
<script src="jquery-3.7.1.min.js"></script>  
<script>  
    // 文件校验函数，接收文件名作为参数  
    function checkFile(filename) {  
        // 定义允许上传的文件扩展名白名单  
        var exts = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'mpeg'];  
        // 查找文件名中最后一个点号的位置（用于分离文件名和扩展名）  
        var index = filename.lastIndexOf(".");  
        // 从点号后一位开始截取扩展名  
        var ext = filename.substr(index + 1);  
          
        // 标记文件是否合法  
        var isValid = false;  
        // 遍历白名单数组进行匹配  
        for (var i = 0; i < exts.length; i++) {  
            // 如果文件扩展名在白名单中（忽略大小写）  
            if (ext.toLowerCase() == exts[i].toLowerCase()) {  
                isValid = true;  // 标记为合法文件  
                break;           // 跳出循环  
            }  
        }  
          
        // 根据文件合法性进行相应处理  
        if (isValid) {  
            alert('文件正确！');  // 弹出提示  
            // 正确上传文件逻辑代码在下面  
        } else {  
            // 如果不在白名单中，弹出非法文件提示  
            alert('非法文件！');  
            // 重定向到当前页面，相当于刷新页面清空选择  
            window.location.replace("file.html");  
        }  
    }  
</script>
```

基本操作就是 JS 绑定某个 HTML 标签或标签属性内容，点击从而触发事件。

### DOM

![[attachments/20250806-1.png]]

DOM (Document Object Model)文档对象模型：

- 访问文档：可以动态获取和修改页面上的内容
- 修改文档结构：可以添加、删除、移动或替换元素
- 处理事件：为页面元素绑定和响应交互事件(如点击、悬停等)

```js
 <!-- 通过ID获取元素并设置href属性 -->
<a id="a">点我</a>
<script type="text/javascript">
	// 通过ID获取元素并直接修改href属性
	// document.getElementById("a").href = "http://www.youku.com";
	
	// 另一种方式：使用setAttribute方法设置href属性
	var a=document.getElementById("a");
	a.setAttribute("href","http://www.baidu.com");
</script>

<!-- 使用HTML属性绑定事件 -->
<button onclick="func()">点我</button>
<script>
	// 定义事件处理函数
	function func() {
		alert("1");  // 弹出提示框显示数字1
	}
</script>

<!-- 按钮元素，通过ID "bn" 进行标识 -->
<button id="bn">点我</button>
<script>        // 获取ID为 "bn" 的按钮元素
	var bn=document.getElementById("bn");
	
	// 通过DOM属性方式为按钮绑定点击事件处理函数
	// 这种方式将匿名函数赋值给元素的onclick属性
	bn.onclick=function(){
		alert("xxx");  // 当按钮被点击时，弹出提示框显示"xxx"
	}
</script>
```

![[attachments/20250806-2.png]]

> 案例：
> 
> https://xz.aliyun.com/news/11945
> 
> https://mp.weixin.qq.com/s/iUlMYdBiOrI8L6Gg2ueqLg

### BOM

BOM (Browser Object Model) 浏览器对象模型：

- 使用 Window 对象对浏览器打开关闭返回新建进行操作。
- 使用 Screen 对象窗口的 screen 属性包含有关客户端显示屏的信息。
- 使用 Navigator 对象指浏览器对象，包含浏览器的信息。
- 使用 Location 对象 Location 对象包含有关当前 URL 的信息
- 使用 History 对象包含用户访问过的 URL，经常使用于页面跳转。
- 使用 Document 对象指文档对象，既属于 BOM 对象，也属于 DOM 对象。

```js
<script>  // 使用 window.open() 方法打开新窗口或标签页，访问百度网站
  window.open("http://www.baidu.com");

  // 说明：window 对象是全局对象，可以省略不写
  // window.document.getElementById() 等同于 document.getElementById()
  // window.screen.width 等同于 screen.width

  // Screen 对象：包含有关用户屏幕的信息
  console.log(screen.height);     // 输出屏幕高度（像素）
  console.log(screen.width);      // 输出屏幕宽度（像素）
  console.log(screen);            // 输出整个 screen 对象

  // Location 对象：包含有关当前 URL 的信息
  console.log(location);          // 输出整个 location 对象
  console.log(location.host);     // 输出主机名和端口号（如：www.example.com:8080）
  console.log(location.hostname); // 输出主机名（如：www.example.com）
  console.log(location.protocol); // 输出协议（如：http: 或 https:）
  console.log(location.port);     // 输出端口号（如：8080）
  console.log(location.pathname); // 输出URL的路径部分（如：/index.html）

  // Navigator 对象：包含有关浏览器的信息
  console.log(navigator);             // 输出整个 navigator 对象
  console.log(navigator.appName);     // 输出浏览器名称
  console.log(navigator.appVersion);  // 输出浏览器版本信息
  console.log(navigator.userAgent);   // 输出用户代理字符串

  // History 对象：包含用户访问过的 URL
  history.back();     // 后退到上一个页面（相当于浏览器的后退按钮）
  history.forward();  // 前进到下一个页面（相当于浏览器的前进按钮）

  // 输出 document.getElementById 方法的引用
  console.log(window.document.getElementById);
</script>
```

### 前端 JS 加密

- 非加密数据大致流程

客户端发送->明文数据传输-服务端接受数据->处理数据

- 加密数据大致流程

明文加密->客户端发送->密文数据传输-服务端接受数据->解密数据->处理数据

```js
<div class="login">
    <h2>后台登录</h2>
    <label for="username">用户名:</label>
    <input type="text" name="username" id="username" class="user">
    <label for="password">密码:</label>
    <input type="password" name="password" id="password" class="pass">
    <button>登录</button>
</div>
<script src="jquery.js"></script>
<script src="crypto-js.js"></script>
<script>
    // 为登录按钮绑定点击事件处理函数
    $("button").click(function () {
        // 获取用户在密码框中输入的原始密码
        var passstr = $('.pass').val();
        // 定义AES加密的密钥
        var aseKey = "aeskey"
        // 使用CryptoJS库对密码进行AES加密
        var aespassstr = CryptoJS.AES.encrypt(
            passstr,                                    // 要加密的内容（用户输入的密码）
            CryptoJS.enc.Utf8.parse(aseKey),           // 解析密钥为UTF-8格式
            {
                mode: CryptoJS.mode.ECB,               // 加密模式为ECB模式
                padding: CryptoJS.pad.Pkcs7            // 填充方式为Pkcs7填充
            }
        ).toString();  // 将加密结果转换为字符串格式

        // 发送AJAX请求到服务器进行登录验证
        $.ajax({
            type: 'POST',                              // 请求方式为POST
            url: 'login.php',                          // 请求地址
            data: {                                    // 发送的数据
                username: $('.user').val(),            // 用户名（明文传输）
                password: aespassstr                   // 密码（已AES加密）
            },
            dataType: 'json',                          // 预期服务器返回JSON格式数据
            success: function (data) {                 // 请求成功的回调函数
                console.log(data);                     // 在控制台输出服务器返回的数据
                // 判断登录是否成功（infoCode为1表示成功）
                if (data['infoCode'] == 1) {
                    alert('登录成功!');                 // 弹出成功提示
                } else {
                    alert('登录失败!');                 // 弹出失败提示
                }
            }
        });
    });
</script>

```

> 前端加密库 Crypto https://github.com/brix/crypto-js
> 
> https://juejin.cn/post/7382893339181613068
> 
> 前端加密库 jsencrypt https://github.com/travist/jsencrypt
> 
> https://www.cnblogs.com/Lrn14616/p/10154529.html

文件上传、登录验证等操作，若通过 JS 验证，攻击者通过对过滤代码的分析，或禁用 JS 或修改返回分析绕过从而导致安全问题。

## NodeJS

> https://www.runoob.com/nodejs/nodejs-tutorial.html

常用第三方库

- express：一个简洁而灵活的 node.js Web应用框架
- body-parser：node.js中间件，用于处理 JSON, Raw, Text 和 UR L编码的数据
- cookie-parser：一个解析 Cookie 的工具。通过 req.cookies 可以取到传过来的 cookie，并把它们转成对象
- multer：node.js中间件，用于处理 enctype="multipart/form-data"（设置表单的 MIME 编码）的表单数据
- mysql：Node.js 来连接 MySQL 专用库，并对数据库进行操作
- ...

```shell
npm i express ...(包名)
```

代码示例及可能存在漏洞解析

```js
// 此时访问http://127.0.0.1:8082/sql?id=1地址则会输出指定数据库中的内容
// 操作不当存在一定的安全问题（SQL 注入）

var mysql = require('mysql'); // 引入mysql模块，用于数据库操作
var express = require('express'); // 引入express框架，用于创建web应用
var app = express(); // 创建express应用实例

// 创建数据库连接配置
var connection = mysql.createConnection({
    host: 'localhost',     // 数据库主机地址
    user: 'root',          // 数据库用户名
    password: '123456',    // 数据库密码
    database: 'phpstudy'   // 数据库名称
});

connection.connect(); // 建立数据库连接

// 定义路由处理函数，处理GET请求到/sql路径
app.get("/sql", function (req, res) {
    const id = req.query.id;                     // 从请求参数中获取id值
    const sql = 'select * from admin where id=' + id; // 构造SQL查询语句（存在SQL注入风险）
    
    // 执行数据库查询
    connection.query(sql, function (err, result) {
        if (err) {
            // 如果查询出错，打印错误信息并返回
            console.log('[SELECT ERROR] - ', err.message);
            return;
        }
        // 查询成功，打印结果并发送给客户端
        console.log(result);
        res.send(result);
    });
})

// 启动服务器，监听8082端口
var server = app.listen(8082, '127.0.0.1', function () {
    var host = server.address().address;  // 获取服务器地址
    var port = server.address().port;     // 获取服务器端口
    console.log("应用实例，访问地址为 http://%s:%s", host, port); // 输出服务器访问地址
})
```

```js
// 同上，访问地址（注意路由地址不同），传入参数，执行命令

const child_process = require('child_process'); // 引入Node.js的子进程模块，用于执行系统命令
var express = require('express'); // 引入express框架，用于创建web应用
var app = express(); // 创建express应用实例
const shell = require('shelljs'); // 引入shelljs模块，提供更便捷的shell命令执行功能

// 立即执行计算器命令（在服务器启动时就会执行）
shell.exec('calc')

// 定义GET路由 /rce，接收cmd参数并执行相应命令
app.get('/rce', function (req, res) {
    const cmd = req.query.cmd; // 从URL查询参数中获取cmd值
    child_process.exec(cmd); // 执行传入的命令（存在命令执行漏洞）
})

// 命令执行示例（已被注释）
// child_process.exec('calc'); // 执行计算器
// child_process.spawnSync('calc'); // 同步方式执行计算器

// 代码执行示例（已被注释）
// eval('child_process.exec(\'calc\');'); // 使用eval执行代码（存在代码执行漏洞）

// 启动服务器，监听8081端口
var server = app.listen(8081, '127.0.0.1', function () {
    var host = server.address().address; // 获取服务器地址
    var port = server.address().port; // 获取服务器端口
    console.log("应用实例，访问地址为 http://%s:%s", host, port); // 输出服务器访问地址
})
```

```js
// 文件、目录的读取

var fs = require("fs");        // 引入文件系统模块，用于文件和目录操作
var express = require('express'); // 引入express框架，用于创建web应用
var app = express();           // 创建express应用实例

// 定义GET路由 /file，用于读取文件内容
app.get("/file", function (req, res) {
    var name = req.query.file;  // 从URL查询参数中获取file值（文件路径）
    //res.send(name);           // 被注释的代码，原本用于返回文件名
    
    // 异步读取指定文件内容
    fs.readFile(name, 'utf8', function (err, data) {
        if(err) throw err;      // 如果读取文件出错则抛出异常
        console.log(data);      // 在控制台输出文件内容
        res.send(data);         // 将文件内容发送给客户端
    })
})

// 定义POST路由 /dir，用于读取目录内容
app.post("/dir", function (req,res) {
    var name = req.query.dir;   // 从URL查询参数中获取dir值（目录路径）
    //res.send(name);           // 被注释的代码，原本用于返回目录名
    
    // 异步读取指定目录内容
    fs.readdir(name, 'utf8', function (err, data) {
        if(err) throw err;      // 如果读取目录出错则抛出异常
        console.log(data);      // 在控制台输出目录内容（文件列表）
        res.send(data);         // 将目录内容发送给客户端
    })
})

// 启动服务器，监听8081端口
var server = app.listen(8081, '127.0.0.1', function () {
    var host = server.address().address;  // 获取服务器地址
    var port = server.address().port;     // 获取服务器端口
    console.log("应用实例，访问地址为 http://%s:%s", host, port); // 输出服务器访问地址
})
```

```js
// 原型链污染，攻击者控制并修改一个对象的原型（__proto__）

// 定义一个简单的JavaScript对象foo，包含属性bar值为1
let foo = {bar: 1}

// 输出foo.bar的值，此时为1
console.log(foo.bar)

// 修改foo对象的原型(__proto__)，将bar属性设置为一个恶意代码字符串
// 这个字符串实际上是用于执行系统命令的代码（执行计算器程序）
foo.__proto__.bar = 'require(\'child_process\').execSync(\'calc/\');'

// 输出foo.bar的值，由于原型链的查找机制，此时输出的是原型上的bar值
// 即上面设置的恶意代码字符串
console.log(foo.bar)

// 创建一个空对象zoo
let zoo = {}

// 通过eval执行zoo.bar，由于zoo对象本身没有bar属性，会沿着原型链查找到
// 原型上的bar属性（即恶意代码字符串），然后eval执行该代码，会启动计算器程序
console.log(eval(zoo.bar))
```

> 案例：
> 
> https://f1veseven.github.io/2022/04/03/ctf-nodejs-zhi-yi-xie-xiao-zhi-shi/
> 
> https://mp.weixin.qq.com/s/mKOlTQclji-oEB5x_bMEMg

## Webpack

> https://docschina.org/
> 
> https://www.webpackjs.com/
> 
> https://mp.weixin.qq.com/s/J3bpy-SsCnQ1lBov1L98WA

模块打包工具，主要用于将 JS 代码和其他资源（eg：CSS、图片、字体等）打包成浏览器可高效加载的文件。

可将多个文件（模块）打包成一个或多个最终的输出文件，管理复杂应用程序，性能优化，缓存优化

可通过配置文件来自定义配置打包的方式 `webpack.config.js`

```shell
# 基本安装使用
npm i webpack --dev

npm i webpack-cli --dev
```

存在安全问题：源码泄露（若打包未进行正确的配置），攻击者可在网页上获取的 `webpack://` js 目录 或 `...js.map` 文件，并通过工具将其还原出来。

- mode 配置

production（生产），development（开发），开发模式下会存在泄漏
还原：浏览器 webpack://

2、devtool配置

参数 devtool 配置不当，会在部署代码文件中生成对应匹配的 soucemap 文件（源码映射），如果将参数 devtool 配置为“source-map”、“cheap-source-map”、“hidden-source-map”、“nosources-source-map”、“cheap-module-source-map”等值时，打包后将生成单独的 map 文件。

> https://mp.weixin.qq.com/s/tLjSb5cinXawMEC7RfJEJQ

```shell
# shuji 可还原map文件

npm install --global shuji
shuji xxx.js.map -o xxxxxxx
npm install --global reverse-sourcemap
reverse-sourcemap --output-dir ./ xxx.js.map
```

## Vue

> https://cn.vuejs.org/

- Vue 创建

创建 vue：`npm create vue@latest`

vite 创建：`npm create vite@latest`

- Vue 启动

`cd <your-project-name>`

安装依赖：`npm install`

开发启动：`npm run dev`

打包构建：`npm run build`

Vue 漏洞几乎没有，

```js
<template>
  <div>
    <h1>XSS 漏洞演示</h1>
    <input v-model="userInput" placeholder="输入你的内容" />
    <button @click="showContent">显示内容</button>
    <!-- 存在漏洞（XSS） -->
    <div v-html="displayContent"></div>
    <!-- 不存在漏洞 vue 框架自身会进行过滤 -->
	<!-- <div {{displayContent}} ></div>-->
  </div>
</template>

<script>
export default {
  data() {
    return {
      userInput: '', // 用户输入
      displayContent: '' // 显示的内容
    };
  },
  methods: {
    showContent() {
      // 直接将用户输入的内容渲染到页面
      this.displayContent = this.userInput;
    }
  }
};
</script>
...
```

> 官方报告漏洞： https://cn.vuejs.org/guide/best-practices/security

> 案例：
> 
> https://mp.weixin.qq.com/s/30XIDREyo0Ose4v8Aa9g2w
> 
> https://mp.weixin.qq.com/s/4KgOZcWUnvor_GfxsMlInA

## 微信小程序

[[../../002信息收集问题#^7ec163|微信小程序]]

> 案例：
> 
> https://mp.weixin.qq.com/s/z28ppqhNJnLVWSScMEqiuw
> 
> https://mp.weixin.qq.com/s/ZfovaAyipqzUIYdL9objPA
> 
> https://mp.weixin.qq.com/s/PK1NhvdrDr3XWEliuyEiig
