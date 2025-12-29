---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "Random Seed种子"
---
Random seed（随机种子） 是在生成随机数时使用的起始点。它用于控制随机数生成器产生随机数的序列。设置了随机种子后，每次生成的随机数序列将是确定性的，这意味着可以在不同的运行中获得相同的随机数序列，从而使实验可复现。

在机器学习中，确保实验的可复现性是至关重要的，因为它允许其他人重现你的结果并验证你的研究成果。如果不设置随机种子，每次运行程序时生成的随机数都会发生改变，这将导致结果的不可复现性。

在Python中，随机种子是通过random.seed()函数设置的，而在PyTorch中，可以通过设置torch.manual_seed()来实现，在TensorFlow中，使用tf.random.set_seed()设置

下面是两种场景下设置随机种子的示例：
```python
import random

# 设置随机种子
random.seed(123)

# 生成随机数
for _ in range(5):
    print(random.random())

```

在这个例子中，我们设置了随机种子为 123，然后生成了 5 个随机数。如果你再次运行上面的代码，你会发现每次生成的随机数序列都是相同的。

场景2）在使用 PyTorch 训练时：
在 PyTorch 中，可以使用 torch.manual_seed() 来设置随机种子。下面是一个具体的使用案例：

```python
import torch

# 设置随机种子
torch.manual_seed(123)

# 创建一个随机数张量
random_tensor_1 = torch.rand(3, 3)
print("第一次随机数生成结果:")
print(random_tensor_1)

# 再次随机生成，第二次结果和第一次是一样的
random_tensor_2 = torch.rand(3, 3)
random_tensor_2

# 重新设置不的随机种子
torch.manual_seed(456)

# 再次创建一个随机数张量：因为设置了不同的随机数种子，这次生成的结果不和之前两次不同
random_tensor_3 = torch.rand(3, 3)
print("\n第三次随机数生成结果:")
print(random_tensor_3)

```

其他设置代码汇总：

```python
import torch
import random
import tensorflow as tf
import numpy as np

# 设置随机种子
seed = 42


np.random.seed(seed)# 设置 NumPy 中的随机种子
random.seed(seed) #设置 Python 标准库中的随机种子，以确保其他 Python 函数中使用的随机数也是可复现的。

tf.random.set_seed(seed) #设置 TensorFlow 中的随机种子

torch.manual_seed(seed)
torch.cuda.manual_seed(seed) #设置 PyTorch 在 CUDA 环境下的随机种子，以确保 CUDA 计算的结果是可复现的。
torch.cuda.manual_seed_all(seed)  # 如果使用多个GPU，此命令将确保所有的 GPU 使用相同的随机种子。
torch.backends.cudnn.deterministic = True # 确保在使用 cuDNN 加速时结果可复现，但可能会降低性能。
torch.backends.cudnn.benchmark = False #禁用 cuDNN 的自动寻找最适合当前配置的高效算法的功能，以确保结果的一致性。

```

> https://blog.csdn.net/WHYbeHERE/article/details/133930263