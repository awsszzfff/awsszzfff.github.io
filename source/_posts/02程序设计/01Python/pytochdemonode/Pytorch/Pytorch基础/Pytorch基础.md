---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "Pytorch基础"
---
使用Pytorch实现神经网络模型的一般流程包括：
1. 准备数据
2. 定义模型
3. 训练模型
4. 评估模型
5. 使用模型
6. 保存模型

> 【小土堆】 https://blog.csdn.net/weixin_42306148/article/details/123754540
> 		   https://www.cnblogs.com/cauwj/p/16789366.html
> 		   https://www.cnblogs.com/withhelpfire/articles/17541440.html
> 【刘二】 https://blog.csdn.net/weixin_42306148/article/details/124080096

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

# Dataset 数据加载
提供一种方式获取数据及其 label 。
将已有数据的源格式，通过一种方式进行读取，遵循 pytorch 的规则，使其转化为 pytorch 可以利用并处理的一种数据样式。
- 规则：定义一个 class 类，继承 Dataset （from torch.utils.data import Dataset）；在该类中重写三个方法，分别是：初始化`__init__`获取一些在加载数据过程中所需要的参数（eg：路径，标签，文件名等），获取每个数据`__getitem__`，获取数据长度`__len__`。

示例 1：
【在`\data\train`中已有两个数据集文件夹`ants_image bees_image`，分别保存 ants 和 bees 的一些图片。】
该程序所做的就是将其按照 pytorch 的规则进行加载读取。【可用调试模式查看相关变量值】
1、路径、合并路径、把文件夹中的每一个文件名称，做成一个列表（这是 init 要做的事情）；
2、访问 init 中的列表，把列表的名称逐一传递给一个变量，命名为 name ，再次合并路径，并且把文件名连接在路径之后，接下来，用 PIL 中的 Image.open 函数，读取（加载）上述路径的文件（命名为 img ）（这里肯定是图像了），返回 图像 img 和标签 label（这是 getitem 的工作）；
3、最后用 len 返回列表的长度。

```python
import os

from PIL import Image
from torch.utils.data import Dataset


# dataset有两个作用：1、加载每一个数据，并获取其label；2、用len（）查看数据集的长度
class MyData(Dataset):
    def __init__(self, root_dir, label_dir):  # 初始化，为这个函数用来设置在类中的全局变量
        self.root_dir = root_dir
        self.label_dir = label_dir
        self.path = os.path.join(self.root_dir,self.label_dir)  # 单纯的连接起来而已，背下来怎么用就好了，因为在win下和linux下的斜线方向不一样，所以用这个函数来连接路径
        self.img_path = os.listdir(self.path)  # img_path 的返回值，就已经是一个列表了

    def __getitem__(self, idx):  # 获取数据对应的 label
        img_name = self.img_path[idx]  # img_name 在上一个函数的最后，返回就是一个列表了
        img_item_path = os.path.join(self.root_dir, self.label_dir, img_name)  # 这行的返回，是一个图片的路径，加上图片的名称了，能够直接定位到某一张图片了
        img = Image.open(img_item_path)  # 这个步骤看来是不可缺少的，要想 show 或者 操作图片之前，必须要把图片打开(读取)，也就是 Image.open()一下，这可能是 PIL 这个类型图片的特有操作
        label = self.label_dir  # 这个例子中，比较特殊，因为图片的 label 值，就是图片所在上一级的目录
        return img, label  # img 是每一张图片的名称，根据这个名称，就可以使用查看（直接img）、print、size等功能
        # label 是这个图片的标签，在当前这个类中，标签，就是只文件夹名称，因为我们就是这样定义的

    def __len__(self):
        return len(self.img_path)  # img_path，已经是一个列表了，len()就是在对这个列表进行一些操作


if __name__ == '__main__':
    root_dir = "\data\train"
    # root_dir = "data/train"
    ants_label_dir = "ants_image"
    bees_label_dir = "bees_image"
    ants_dataset = MyData(root_dir, ants_label_dir)
    bees_dataset = MyData(root_dir, bees_label_dir)
    train_dataset = ants_dataset + bees_dataset
```

# Tensorboard
一般用来查看训练成果的变化过程，便于观察分析训练的效果从而对参数等进行调整。可以看到具体某一部的输入和输出

```python
from torch.utils.tensorboard import SummaryWriter  

writer = SummaryWriter("logs/tensorBoard_logs")  # 指定一个文件夹，将创建的事件文件存下来

# 常用的两个方法
writer.add_scalar()  # 横纵坐标相关的函数
writer.add_image()  # 图片

writer.close()
```

示例 2：`add_scalar`

```python
from torch.utils.tensorboard import SummaryWriter  

writer = SummaryWriter("logs/tensorBoard_logs") 

# y = 2x  
for i in range(100):  
    writer.add_scalar("y=2x", 2*i, i)  
    # 第一个参数为要显示的名称（不重要）
    # 第二个参数为y轴的值
    # 第三个参数为x轴的值（全局步长）

writer.close()
```

示例 3：`add_image`

```python
from torch.utils.tensorboard import SummaryWriter  
from PIL import Image  
import numpy as np  
  
writer = SummaryWriter("logs/tensorBoard_logs")   
image_path = "data/train/bees_image/17209602_fe5a5a746f.jpg"  
img_PIL = Image.open(image_path)  
img_array = np.array(img_PIL)  

# print(type(img_array))
# print(img_array.shape)  

writer.add_image("train", img_array, 1, dataformats='HWC')  
# 第一个参数是要显示的名称
# 第二个是图片数据，要注意数据类型
# 第三个指当前图片是第几轮的（全局步长）
# 第四个传入图像数据的格式规范
  
writer.close()
```

在终端输入命令`tensorboard --logdir=logs`【启动 tensorboard 事件服务，传入创建事件的文件夹】【添加参数可修改端口`--port=6007`】

# torchvision 中的 transform 模块

常用 ToTensor、ToPILImage、Compose 等一些工具（class）
ToTensor 将 ndarray 或 PIL 类型转换为 Tensor 数据类型；ToPILImage 将 Tensor 或 ndarray 转换为 PIL 类型；Compose 将多个变换组合在一起；…………
示例 4：`ToTensor`
```python
from PIL import Image  
from torch.utils.tensorboard import SummaryWriter  
from torchvision import transforms  
  
img_path = "dataset/train/ants_image/0013035.jpg"  
img = Image.open(img_path)  
  
writer = SummaryWriter("logs/tensorBoard_logs")  
  
tensor_trans = transforms.ToTensor()  
tensor_img = tensor_trans(img)  
  
writer.add_image("Tensor_img",tensor_img)  
  
# print(tensor_img)  
  
writer.close()
```

示例 5：
datasetP10 中存放着

```python
import torchvision  
from torch.utils.tensorboard import SummaryWriter  
  
dataset_transform = torchvision.transforms.Compose([torchvision.transforms.ToTensor()])  
# CIFAR10是官方自带的数据集，download=True，会运行代码时自动下载（如果在当前指定路径中没有该数据集的话）
train_set = torchvision.datasets.CIFAR10(root='./datasetP10', train=True, transform=dataset_transform, download=True)  
test_set = torchvision.datasets.CIFAR10(root='./datasetP10', train=False, transform=dataset_transform, download=True)  
  
writer = SummaryWriter("logs/p10_logs")  
for i in range(10):  
    img, target = train_set[i]  
    writer.add_image("test_set", img, i)  
  
writer.close()
```

![[attachments/test_set.gif]]


# Dataloader
对数据进行打包，为后面的神经网络提供不同的数据形式（例如将 Dataset 中的几个为一组传入到神经网络中）
例如从一副扑克牌（“Dataset”）中取出指定参数所对应的扑克牌作为手牌（“DataLoader”）进行出牌（“神经网络”）

相关参数
- dataset ( Dataset ) 加载数据集
- batch_size ( int , optional ) 每批要加载多少样本（默认值：1）
- shuffle ( bool , optional ) 设置为True在每个 epoch 重新洗牌数据（默认值：False）
- num_workers ( int , optional ）用于数据加载的子进程数。0 表示数据将在主进程中加载。（默认：0）
- drop_last ( bool , optional ）True 如果数据集大小不能被批次大小整除，则设置为丢弃最后一个不完整的批次。False 数据集的大小不能被批大小整除，那么最后一批将更小。（默认：False）

示例 6：
```python
import torchvision  
from torch.utils.data import DataLoader  
from torch.utils.tensorboard import SummaryWriter  
  
# 准备的测试数据集  
test_data = torchvision.datasets.CIFAR10("./datasetP10", train=False, transform=torchvision.transforms.ToTensor(),  
                                         download=True)  
  
test_loader = DataLoader(dataset=test_data, batch_size=64, shuffle=True, num_workers=0, drop_last=True)  
  
# 测试数据集中第一章图片  
img, target = test_data[0]  
print(img.shape)  
print(target)  
  
writer = SummaryWriter("logs/dataloader_logs")  
for epoch in range(2):  
    step = 0  
    for data in test_loader:  
        imgs, targets = data  
        # print(imgs.shape)  
        # print(targets)        
        writer.add_images(f"Epoch{epoch}", imgs, step)  
        step += 1  
  
writer.close()
```

![[attachments/Pasted image 20241007151402.png]]

# nn.Module















注：函数、类等的具体细节还是要看官方文档，尤其是要传入参数的数据类型和数据格式