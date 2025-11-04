---
title: "JS逆向"
date: 2025-09-24
tags:
  - Others
categories:
  - Others
description: None
---
过滤器筛选数据包，分析调用堆栈（从下向上的顺序），寻找 js 加解密的点。

![[attachments/20251028.png]]

## 常用断点调试

![[attachments/20251028-1.png]]

- 和通常添加代码断点相同，左侧行号处直接点击；
- 条件断点，行号处右键弹出输入框，输入要下断点的条件；（条件满足才会断下）
- XHR 断点，右侧 XHR/fetch breakpoint 处可添加一些指定关键字，在包含某些关键字的时候会断下；
- 事件断点，右侧 Event Listener Breakpoints 处勾选；（常用鼠标点击等操作）

打断点后重新执行操作，分析右侧堆栈调用，以及各 变量/参数 值。

> https://mp.weixin.qq.com/s/E-eip5LXjGHFYmNlrNK-bg

## 反调试绕过

有的网页限制了调试（检测调试方法：无限 Debugger 技术、键盘监听 F12、检测浏览器的高度插值、检测开发者人员工具变量是否为 True、利用 console.log 调用次数、利用代码运行的时间差、利用 toString、检测非浏览器等）

绕过技巧：

禁用所有断点、禁用局部断点、设置条件断点、替换文件执行（修改文件重定向）、通过 bp 修改匹配（流量到 bp 修改替换返回，不过有时会因为修改替换内容，网页无法正常加载使用）、油猴插件配合 HOOK （插件对浏览器执行 JS 删除）

![[attachments/20251030.png]]

JS HOOK 通过拦截和修改 JS 函数对象行为，主要用于动态分析网页行为，修改网页功能，调试和逆向工程，自动化测试，安全研究等 [JS HOOK 安全研究博主](https://github.com/0xsdeo)

```js
# HOOK开发前置基础：
@name 定义脚本的名称
@namespace 用于区分不同脚本的作用域
@version 定义脚本的版本号
@description 描述脚本的功能或用途
@author 定义脚本的作者
@match 定义脚本的运行匹配规则
@icon 定义脚本的图标
@grant 定义脚本所需的特殊权限
```

借助 AI 编写 HOOK 脚本，主要思路就是对 拦截函数 进行替换。

```js
// debugger 卡住的代码
function enableDebugProtection(){
	var dbg = new Function("debugger");
	setInterval(dbg, 3000);
}
enableDebugProtection();

// hook 可以通过重写该函数函数来绕过 debugger
...
// 1. 重写Function构造函数，拦截debugger字符串
const nativeFunction = window.Function;
window.Function = function(...args) {
	if (args[0] === "debugger") {
		return function(){}; // 返回空函数
	}
	return nativeFunction.apply(this, args);
};
// 2. 重写setInterval，防止执行debugger
const nativeSetInterval = window.setInterval;
window.setInterval = function(fn, delay) {
	if (fn && fn.toString().includes("debugger")) {
		console.log("[Anti Debug] Blocked debugger interval");
		return 0; // 返回无效ID
	}
	return nativeSetInterval.apply(this, arguments);
};
// 3. 直接重写原函数
if (typeof enableDebugProtection === 'function') {
	enableDebugProtection = function() {
		console.log("[Anti Debug] enableDebugProtection disabled");
	};
}
...

```

## JS 加解密签名分析

根据调用堆栈寻找加密前后定位，根据关键字或提交 URL，参数名等搜索定位。【定位！】

对于定位到的加密算法可在控制台进行调试测试，或下载 JS 文件，利用 Node 运行调用。

分析加密代码，找到各个参数对应的值，实现加密代码，并通过 python 发送原始请求，获取最终响应。

```python

```

## 代码混淆

常见混淆案例 https://scrape.center/

eval、JJEncode、AAEncode、JSFuck、Obfuscator 等

- eval
	- 特征：出现 eval 关键字
	- 控制台输出（去除 eval() 后）给函数名，新建 JS 文件优化

- JJEncode、AAEncode、JSFuck
	- 特征：包含很多 $ 、包含很多 颜文字、包含很多 `[ ]、()、+、!`
	- 还原：控制台输出（一般去除 `()`调用 后）点击查看或直接运行

- Obfuscator
	- 特征：包含很多 0x 字母无意义的字符串
	- 还原：控制台输出美化代码断点调试输出分析，利用 AST 技术解密还原

> JS 解码/美化平台
> 
> - https://jsdec.js.org/
> - https://lelinhtinh.github.io/de4js/

## AST JS 解码还原

> https://astexplorer.net/

原理：将代码分解为多段有意义的词法单元来具体分析

```txt
const name="qc"
这段代码被分为 const、name、=、qc 四部分
const：VariableDeclaration类型，代表变量声明的具体定义；
name：ldentifier类型，代表一个标识符；
qc：Literal类型，代表文本内容；
最后将 AST 转为可执行的指令并执行
```

> - Literal：简单理解就是字面量，比如 3、"abc"、null 这些都是基本的字面量；
> - Declarations：声明，通常声明方法或者变量；
> - Expressions：表达式，通常有两个作用：一个是放在赋值语句的右边进行赋值，另外还可以作为方法的参数；
> - Statemonts：语句；
> - Identifier：标识符，指代变量名，比如上述例子中的 name 就是 identifier；
> - Classes：类，代表一个类的定义；
> - Functions：方法声明；
> - Modules：模块，可以理解为一个Node.js模块；
> - Program：程序，整个代码可以称为 Program

> - https://mp.weixin.qq.com/s/bOc8PYbFdTyFRQcfSppo8w
> - https://mp.weixin.qq.com/s/rURCR085HiojW2_67enJkA

> OB 混淆还原：
> 
> https://obfuscator.io/
> 
> https://deobfuscate.io/
> 
> https://webcrack.netlify.app/
> 
> https://deli-c1ous.github.io/javascript-deobfuscator/

## JSRPC

> 前端加密对抗：
> 
> https://forum.butian.net/share/3728
> https://forum.butian.net/share/2889

本地编写代码去调用浏览器的 JS 加密函数，不需要过多的考虑函数的具体逻辑。

## Yakit 热加载

> https://yaklang.com/products/Web%20Fuzzer/fuzz-hotpatch

以数据包发包前和发包后的数据修改功能

```yak
// 热加载的模版内容
格式：{{yak(函数名|参数名)}}
如密码：{{yak(upper|{{x(pass_top25)}})}}

// 热加载的代码逻辑
函数名 = func(参数名) {
	return 参数名
}

upper = func(s) {
// 传入的参数，类型为字符串，返回值可以是字符串或数组
	return s.Upper()
}

// 热加载中的魔术方法
// beforeRequest 允许发送数据包前再做一次处理，定义为 func(origin []byte) []byte
beforeRequest = func(req) {
	return []byte(req)
}

// afterRequest 允许对每一个请求的响应做处理，定义为 func(origin []byte) []byte
afterRequest = func(rsp) {
	return []byte(rsp)
}
```

> 补充异步：
> 
> https://mp.weixin.qq.com/s/amnuUWLBRg3Cqb70PLgYMQ
> 
> https://mp.weixin.qq.com/s/udTWXcmXhr3w34Xp-LEaTg
> 
> https://mp.weixin.qq.com/s/HlVc0DGjSSSdbw7z6Ae09g