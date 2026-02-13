---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "小土堆Pytorch"
---
> TensorBoard、torchvision.transform(ToTensor)、Dataset、Dataloader、torch.nn


使用Pytorch实现神经网络模型的一般流程包括：
1. 准备数据
2. 定义模型
3. 训练模型
4. 评估模型
5. 使用模型
6. 保存模型
## 张量（Tensors）

类似与数组和矩阵，在PyTorch中，用张量对模型的输入和输出及模型参数进行编码。

## Dataset&Dataloader

### Dateset

提供一种方式获取数据及其label
- 如何获取每一个数据及其label
- 告诉我们总共有多少的数据
（获取数据和label并对其进行编号）

所有表示键到数据样本映射关系的数据集都应该继承Dataset抽象类，所有子类都应该重写`__getitem__`，获取一个给定键的数据样本；可以选择重写`__len__`，返回数据集大小
### DataLoader
对数据进行打包，为后面的神经网络提供不同的数据形式（例如将Dataset中的几个为一组传入到神经网络中）
例如从一副扑克牌（”Dataset“）中取出指定参数所对应的扑克牌作为手牌（“DataLoader”）进行出牌（“神经网络”）

```python
from torch.utils.data import Dataset

```

PIL读取图片文件
```python
from PIL import Image
img_path = "E:\\dataset\\train\\ants_image\\0013035.jpg"
img = Image.open(img_path)
img.show() # 显示图片
```

os读取数据集所在目录中的文件
```python
import os
dir_path = "dataset/train/ants"
img_path_list = os.listdir(dir_path) # 读文件夹中的所有文件并保存为列表
path = os.path.join(root_dir, lable_dir) # 拼接两个文件路径
```

## Tensorboard的使用

探究模型在每个阶段的输入和输出，检测训练过程

`SummaryWriter`类，将条目直接写入log_dir中的事件文件，供TensorBoard使用。【生成一个事件文件存放在log_dir中，以此来供TensorBoard使用】

终端运行`tensorboard --logdir=logs(生成的事件文件目录)`，启动事件【添加参数修改端口`--port=6007`】

```python
writer = SummaryWriter("logs")  

# 从PIL到numpy，需要在add_image()中指定shape中每个数字/维所表示的含义
writer.add_image() 
# tag(str) img_tensor(torch.Tensor,numpy.ndarray,or string/blobname) global_step(int)
writer.add_scalar() 
# tag(str)表名 scalar_value(float or string/blobname)y轴 global_step(int)x轴
```

# torchvision

图像处理模块（pytorch中还有许多的模块，文字处理、音频处理等等，官方也提供了许多的数据集、模型供使用）
例如对官方所提供数据集`CIFAR10`进行简单的读取操作，具体参数阅读官方文档【一定要耐下心来读官方文档】

```python
import torchvision  
from torch.utils.tensorboard import SummaryWriter  
  
dataset_transform = torchvision.transforms.Compose([torchvision.transforms.ToTensor()])  
train_set = torchvision.datasets.CIFAR10(root='./datasetP10', train=True, transform=dataset_transform, download=True)  
test_set = torchvision.datasets.CIFAR10(root='./datasetP10', train=False, transform=dataset_transform, download=True)  
  
# print(test_set[0])  

writer = SummaryWriter("p10")  
for i in range(10):  
    img, target = train_set[i]  
    writer.add_image("test_set", img, i)  
  
writer.close()
```
## torchvision中的transforms

transforms主要是对图片进行变换处理，裁剪、格式变换等

transforms可看做一个工具箱，里面有很多的class工具，要使用工具先创建具体的工具对象，然后根据工具对象的使用手册传递工具所需的参数。
【注意输入，输出，作用】
```python
tensor_trans = transforms.ToTensor()  
tensor_img = tensor_trans(img)
```

**关注输入和输出，多查看官方文档，关注方法需要什么参数。**
**不要因为是官方文档就害怕，不要因为是英文就害怕。细心的看就会发现都是纸老虎。**
**不知道返回值的时候，打印或debug，上网查就ok了**

```python
ToPILImg、ToTensor、Compose……
```

## torch.nn

构建神经网络的模块

torch.nn.Model
所有神经网络模版的基本函数，可以自己进行定义
其中的一些方法需要自己重写，构建自己的神经网络

池化：保留数据的特征，同时缩小数据处理量

