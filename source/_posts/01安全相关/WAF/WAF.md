---
title: WAF
date: 2026-04-08
updated: 2026-04-08
tags:
  - 安全基础
categories:
  - 安全相关
description: WAF
published: false
---
识别自己所能认识的，不认识的放过

性能优先策略，分块传输

过长字符，waf 解析和原始服务解析机制不同

eg：

sql 注入，注释符绕过，各种注释符

小众函数绕过

科学计数法来绕过，eg：id=1 --> id=0e1

.1 !

fuzz 测试

畸形请求绕过，Unicode

特殊后缀 aspx acsx asp phtml php5 

windowws 特殊$DATA::

from-data ->  ~from-data  f-rom-da-ta 

```
from-da+ta000000
:na
me="uploadfile"
```

不同编码 eg：utf-8 -> 传 utf-16 或组合 utf-8 +  utf-16

多重编码

