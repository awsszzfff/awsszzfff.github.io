---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "BUUCTF_二维码"
---
# BUUCTF_二维码

下载题目是个二维码，先用 **QR Research** 进行扫描看看是什么，结果显示 secret is here ，这应该是一个提示，但好像也没什么用~

![1](img/1.png)


尝试用记事本打开，观察一下有没有可用的信息，在其中发现了存在`.txt`文件隐藏（这里也可以拖进 010 或 WinHex 中查看，但本道题都发现的是这两个点）。

由于图片中含有文件，因此用 binwalk 或 foremost 进行扫描分解。

![在这里插入图片描述](img/46ec5e1998b24cd2a1a4faecd8abf504.png)

用 **foremost** 进行分解，产生了一个 zip 压缩文件，才看里面的文件内容需要密码，用 **fcrackzip** 进行破解。

![在这里插入图片描述](img/fe870ee9fd5449c0ab5525a49837a97e.png)

由于 zip 文件中存在文件 4number.txt 猜想密码应该是四位数字。

![在这里插入图片描述](img/bcd6fb38d4624564bd35e9a33cc70278.png)

得到密码，并查看文件得到 flag 。

![在这里插入图片描述](img/2e4d5cc650c246c282388cab2ef615f2.png)
#### 补充

**用其他工具进行操作：**

**binwalk** 分离文件，**ziperello** 破解密码。

![在这里插入图片描述](img/6e5d71c78ba44b6994c465bb63e04b4f.png)
![在这里插入图片描述](img/c574822e61de46dbb67299773a29e6e6.png)

**fcrackzip参数：**

```txt
-b：			使用暴力破解
-c 1：			使用字符集，1指数字集合
-l 4-4：		指定密码长度，最小长度-最大长度
-u：			不显示错误密码，仅显示最终正确密码
```

**010 对 png 的分析：**

![在这里插入图片描述](img/4095ebc6f92c42be83591d37c5f943d0.png)



>参考：
>http://t.csdn.cn/q9sEz
>http://t.csdn.cn/zQI8j