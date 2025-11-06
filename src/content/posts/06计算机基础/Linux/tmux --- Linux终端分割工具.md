---
date: 2001-01-01
tags:
  - Linux
  - 工具
categories:
  - 计算机基础
title: tmux --- Linux终端分割工具
---
## 常用操作

```txt
# ctrl b + 
"			上下分割
%			左右分割
箭头			左右切换窗口
alt 箭头		放缩窗口大小
z			最大化小窗口
```

```txt
ctrl w	删前面一个词
alt d	删后面一个词
ctrl d  删后面一个字
alt b	向前移动一个词
alt f	向后移动一个词
ctrl u	删掉前面所有
ctrl k	删掉后面所有
```

## 基础操作

tmux 进入工作空间
大窗口：
ctrl b + c 创建新的窗口
ctrl b + n 向右切换窗口
ctrl b + p 向左切换窗口
ctrl b + 编号
ctrl b + 左右键 切换不同窗口
ctrl b + & 关闭一个窗口
ctrl b + w 查看所有的窗口
小窗口
ctrl b + % 水平分割窗口
ctrl b + " 垂直分割窗口
ctrl b + q 显示窗口标号 + 标号，切花至对应窗口
ctrl b + x 关闭小窗口
ctrl b + z 小窗口最大化
ctrl b(不放) + 左右键 调整大小

ctrl b + d 退出当前的工作空间
tmux a 进入刚才的工作空间
tmux ls 查看当前存在的工作空间
tmux attach -t + i 进入i 的工作空间

