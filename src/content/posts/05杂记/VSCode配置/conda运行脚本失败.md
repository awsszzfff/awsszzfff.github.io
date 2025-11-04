---
title: "conda运行脚本失败"
date: 2024-11-11
tags:
  - Others
categories:
  - Others
---
```shell
Powershell一般初始化情况下都会禁止脚本执行。只有管理员才有权限更改该策略，非管理员会报错。以管理员身份打开powershell： 
PS E:\> Get-ExecutionPolicy Restricted 
PS E:\> Set-ExecutionPolicy RemoteSigned
PS E:\> Get-ExecutionPolicy -List
执行策略更改 
执行策略可帮助你防止执行不信任的脚本。更改执行策略可能会产生安全风险，如 https:/go.microsoft.com/fwlink/?LinkID=135170 中的 about_Execution_Policies 帮助主题所述。是否要更改执行策略? 
[Y] 是(Y) [A] 全是(A) [N] 否(N) [L] 全否(L) [S] 暂停(S) [?] 帮助 (默认值为“N”): y 　　
1>Unrestricted：权限最高，可以不受限制执行任何脚本。 　　
2>Default：为Powershell默认的策略：Restricted，不允许任何脚本执行。
3>AllSigned：所有脚本都必须经过签名才能在运行。 　　
4>RemoteSigned：本地脚本无限制，但是对来自网络的脚本必须经过签名。

```

> https://www.cnblogs.com/something-/p/17028854.html    C/C++配置Code Runner生成的exe文件至一个文件夹中
> https://wenku.csdn.net/answer/4d8nbrevcy    Anaconda卸载python环境

git进入本机conda环境`source activate your_env_name`