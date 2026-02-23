---
title: LangChain
date: 2026-02-14
updated: 2026-02-14
tags:
  - Others
categories:
  - Others
description: None
---
`init_chat_model` 和 `ChatOpenAI` 这些接口没有什么区别，只是 init... 它集成了各模型官方所给的接口

`Structured Outputs` 输出方式，若当前模型官方提供了对应的输出接口，则可以直接调用它来输出期望的输出格式；若官方没有提供，则可以调用 `JsonOutputParser` 等其他 Output Parsers