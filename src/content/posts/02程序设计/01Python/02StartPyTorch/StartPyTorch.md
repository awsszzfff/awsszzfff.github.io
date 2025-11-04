---
title: "StartPyTorch"
date: 2025-03-04
tags:
  - Others
categories:
  - Others
---
- 在 PyTorch 中，自动求导依赖于动态计算图（Dynamic Computation Graph）。计算图记录了所有涉及张量的操作（如加法、乘法等），以便在反向传播时能够正确计算梯度。

```python file:2.1.2-随机种子
torch.seed()  
torch.manual_seed()  
torch.initial_seed()  
torch.get_rng_state()  
torch.set_rng_state()
```

```python file:2.2.2-自动微分
torch.autograd.backward()
torch.autograd.grad()
```

```python file:2.3.2-统计函数
torch.prod()
torch.sum()
torch.mean()
torch.max()
torch.min()
torch.median()
torch.mode()
torch.var()
torch.std()
```

```python file:2.4.2-矩阵运算
torch.add()
torch.sub()
torch.mul()
torch.div()
torch.pow()
torch.sqrt()
torch.rsqrt()
torch.log2()
torch.log10()
torch.floor()
torch.ceil()
torch.round()
torch.trunc()
torch.frac()
```

```python file:4.1-pytorch基础
torch.tensor()
torch.zeros()
torch.ones()
torch.randn()
torch.from_numpy()
torch.zeros_like()
```

```python file:4.2-激活函数
torch.relu()
torch.sigmoid()
torch.tanh()
torch.nn.LeakyReLU()()
```

```python file:4.3-损失函数
nn.MSELoss()
nn.CrossEntropyLoss()
nn.CosineSimilarity()
nn.L1Loss()
```

```python file:4.4-优化器
optim.SGD()
optim.Adam()
optim.RMSprop()
optim.Adagrad()
```