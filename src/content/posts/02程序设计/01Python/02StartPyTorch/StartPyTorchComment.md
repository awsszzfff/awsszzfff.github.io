---
title: "StartPyTorchComment"
date: 2025-03-05
tags:
  - Others
categories:
  - Others
---
传统机器学习需要人工提取特征并设计模型；深度学习通过构建多层次的神经网络，自动学习和提取特征；-> 图像识别、语音识别等。


在训练过程中，损失函数的使用步骤如下：

1. 前向传播：计算模型的输出（预测值）。
2. 计算损失：将预测值和真实值传入损失函数，得到损失值。
3. 反向传播：调用 `.backward()` 计算梯度。
4. 更新参数：优化器根据梯度更新模型参数。

```python file:一般训练过程
for data, target in dataloader:  # 遍历数据集
    optim.zero_grad()            # 清空之前的梯度，避免梯度累加
    output = net(data)           # 前向传播，计算模型的预测值
    loss = Loss(output, target)  # 计算预测值和真实值之间的损失
    loss.backward()              # 反向传播，计算每个参数的梯度
    optim.step()                 # 根据梯度更新模型参数
```