---
title: "Prompt&Agent&MCP"
date: 2025-05-07
lastmod: 2025-05-07
author: awsszzfff

# date: 2023-03-15T11:00:00-07:00
# lastmod: 2023-03-15T11:00:00-07:00

categories:	# 分类
    - AI
tags:		# 标签
    - 基础理论

draft: false	# 草稿
toc: true	# 目录
math: true	# 公式
mermaid: true	# Mermaid流程图

# cover: /images/backcovers/1.jpg	# 背景图
# copyright: true	# 版权
comments: false	# 评论
sponsor: false	# 赞助

description: "Prompt&Agent&MCP是什么~"

---
## Prompt

用户和 AI 模型进行交互时，最初是用户提供 User Prompt （理解为用户的问题），模型结合 System Prompt （理解为系统预设的前提 eg：系统以安全的模式进行回答）两者共同来回答用户的问题；

## Agent

若用户期望模型可以利用本地已经写好的工具（Tools，已经写好的函数调用的形式）来自动化的完成指定的任务；eg：（两个工具 list_files 列出目录，read_file 读文件）

![](../attachments/20250507-1.png)

![](../attachments/20250507-2.png)

中间的 AutoGPT 即 AI Agent（在 Agent Tools 、模型、用户之间“传话”的工具）；

由于生成的 System Prompt 以及模型返回给 Agent 的内容格式等存在差异，模型厂商推出 Function Calling 功能，主要用来规范描述；

## MCP

MCP 一个通信协议，专门用来规范 Agent 和 Tools 服务之间是怎么交互的，一些交互接口，参数格式等；

整体的基本流程：

![](../attachments/20250507.png)

这里的 MCP Server 可以是 Tools 也可以是数据、Prompt 模版；

> 学习原文：
> 
> https://www.bilibili.com/video/BV1aeLqzUE6L/?share_source=copy_web&vd_source=d1fcb62c082f9710827e86fedf96d9f0