---
title: argparse
date: 2025-12-28
updated: 2025-12-28
tags:
  - Python模块
categories:
  - 程序设计
  - Python
description: None
---
核心四部曲

```python
import argparse  	# 导入模块  
parser = argparse.ArgumentParser()  # 创建解析器对象  
parser.add_argument()  		# 添加参数（告诉程序你想接收什么参数）  
args = parser.parse_args()  	# 解析参数（真正去读取命令行输入的数据）
```