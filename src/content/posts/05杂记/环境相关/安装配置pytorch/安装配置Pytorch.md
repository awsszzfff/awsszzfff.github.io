---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "安装配置Pytorch"
---
【这里是在安装anaconda之后进行pytorch的安装配置】

# 修改Anaconda默认虚拟环境路径

原创建虚拟环境时会提示 environment location: `C:\Users\username\.conda\envs`

创建想要修改到的路径
```
- D:\Anaconda
	- envs
	- pkgs
```

编辑`.condarc`文件，添加：
```
envs_dirs: [D:\Anaconda3\envs, C:\Users\username\.conda\envs] pkgs_dirs: [D:\Anaconda3\pkgs, C:\Users\username\.conda\pkgs]
```

或在 Anaconda Navigator 文件中进行修改
![[attachments/Pasted image 20241105213754.png]]

修改后，安装提示路径则会变成：`D:\Anaconda\envs\`

> 学习参考：https://juejin.cn/post/7193075512057528375

# 安装配置Pytorch

安装所需的python版本`conda create -n pytorch python=3.12`
进入pytorch官网https://pytorch.org/

![[attachments/Pasted image 20240713221019.png]]

根据自己的需求进行选择，复制生成的conda命令进入刚才安装的python环境`conda activate pytorch`进行执行（选y）

```shell
conda install pytorch torchvision torchaudio pytorch-cuda=11.8 -c pytorch -c nvidia
```

完成后执行以下代码进行测试

```python
>>> import torch
>>> torch.cuda.is_available()
True # 返回True表示安装成功，且可调用GPU
```

在该环境下安装 jupyter notebook

```shell
conda install jupyter notebook # 安装jupyter notebook
jupyter notebook # 打开jupyter notebook
```

>【跟着佬的视频学习记录】https://www.bilibili.com/video/BV1hE411t7RN/?share_source=copy_web&vd_source=d1fcb62c082f9710827e86fedf96d9f0
>【给pytorch安jupyter notebook可能存在的问题】https://blog.csdn.net/weixin_51596276/article/details/136786385