---
title: "AI&Pytorch基础"
date: 2025-04-23
tags:
  - Others
categories:
  - Others
---
> 机器学习的基本训练过程：计算一个函数关于一个变量在某一取值下的导数，从而基于梯度对参数进行优化；

Pytorch 提供自动计算梯度的功能，仅需执行`tensor.backward()`，则会自动通过反向传播算法完成，在训练模型时会用到该函数；

简单的示例：$z=(x+y)\times(y-2)$

在张量生成时，需显示的设置该变量是否可导，`requires_grad=True`；

```python
x = torch.tensor([2.], requires_grad=True)
y = torch.tensor([3.], requires_grad=True)
z = (x + y) * (y - 2)
z	# tensor([5.], grad_fn=<MulBackward0>)
z.backward()
x.grad	# tensor([1.])
y.grad	# tensor([6.])
```

手工模拟： $\frac{\mathrm{d}z}{\mathrm{d}x}=y-2$ ，$\frac{\mathrm{d}z}{\mathrm{d}y}=x+2y-2$ ，当 $x=2$ ，$y=3$ 时，$\frac{\mathrm{d}z}{\mathrm{d}x}=1$ 和 $\frac{\mathrm{d}z}{\mathrm{d}y}=6$ ；

**注**：梯度不能自动清零，在每次反向传播中会叠加；这可能会导致得不到正确的结果，需要手动清零；

```python
# 继续上面的梯度并不对其清零
z1 = x*y
z1.backward()
x.grad	# tensor([4.])	1 + 3
y.grad	# tensor([8.])	6 + 2

# 清理操作
x.grad.zero_()	# x.grad	# tensor([3.])
y.grad.zero_()	# y.grad	# tensor([2.])
```

$\frac{\mathrm{d}z1}{\mathrm{d}x}=y=3$，$\frac{\mathrm{d}z1}{\mathrm{d}y}=x=2$；

Pytorch 模型构建

Pytorch 中进行模型构建的基本流程：准备训练数据集、构建将要使用的模型、设置损失函数和优化器、模型训练。

常用模块：

```python
import torch
from torch.utils.data import TensorDataset	# 构造数据集对象
from torch.utils.data import DataLoader		# 数据加载器
from torch import nn		# nn模块中有平方损失函数和假设函数
from torch import optim		# optim模块中有优化器函数
# from sklearn.datasets import make_regression	# 创建线性回归模型数据集
```

## 数据相关

以文本多分类任务为例，制作属于自己的数据集：

需要注意的是制作好的数据集要尽可能的均衡，（eg：分为 8 个类别，8 个类别的比例应该是 1:1... 若有一部分比较多，则选择向少量数据对齐）

### Dataset

所有数据集必须继承自`Dataset`或`IterableDataset`；

#### 映射型（Map-style）数据集

继承自`Dataset`类，**表示一个从索引到样本的映射**（索引不一定是整数，可以是自定义的），为了方便通过`dataset[idx]`来访问指定索引的样本；

必须实现`__gititem__()`函数，负责根据指定的 key 返回对应的样本；

> `__gititem__(self, idx)`，`idx`由`DataLoader`自动分配；
> 当使用`DataLoader`加载`Dataset`时，会根据`batch_size`、`shuffle`等参数自动生成一组索引（`dix`）

`__len__()`返回数据集的大小；

##### 自定义数据集

```python

```

#### 迭代型（Iterable-style）数据集

……

### DataLoader

DataLoader 数据加载器，方便对数据进行批量处理和模型训练，通常用于将数据分批次加载到模型中进行训练；

实际训练模型时，需要先将数据集切分为很多 mini-batches，然后按批（batch）将样本送入模型；每一个完整遍历所有样本的循环即一个 epoch；

## 训练相关

优化器用于调整模型参数，以最小化损失函数。损失函数用于衡量模型预测值与真实值之间的差异。训练过程中，通过优化器和损失函数的配合，模型不断的调整参数，以提高预测的准确性；

```
训练阶段：
for each epoch:
    for each batch:
        清空梯度 → 前向传播 → 计算损失 → 反向传播 → 更新参数 → 记录损失
    计算epoch平均训练损失 → 记录到TensorBoard

验证阶段：
for each batch:
    禁用梯度 → 前向传播 → 计算损失 → 记录损失
    计算epoch平均验证损失 → 检查是否保存模型 → 检查早停条件
```

示例（一个简单的训练过程）：

```python
# 训练部分  
def trainer(train_loader, valid_loader, model, config, device):  
	# 定义损失函数 
    criterion = nn.MSELoss(reduction='mean')  
  
    # 定义优化器  
    optimizer = torch.optim.SGD(model.parameters(), lr=config['learning_rate'], momentum=0.9)  
  
    # Tensorboard 的记录器  
    writer = SummaryWriter()  
  
    if not os.path.isdir('./models'):  
        # 创建文件夹-用于存储模型  
        os.mkdir('./models')  

	# 传入超参数
    n_epochs, best_loss, step, early_stop_count = config['n_epochs'], math.inf, 0, 0  
  
	# 训练循环，遍历所有epoch
	for epoch in range(n_epochs):
	    model.train()  # 开启训练模式（启用Dropout/BatchNorm等训练专用层）
	    loss_record = []	# 初始化空列表，记录当前epoch的所有batch损失

		# 设置进度条（在每轮训练的过程中显示训练进度）
		# train_pbar = tqdm(train_loader, position=0, leave=True)
		# train_pbar.set_description(f'Epoch [{epoch + 1}/{n_epochs}]')
		# for x, y in train_pbar:
		
		# 遍历训练集的所有batch
	    for x, y in train_loader:
	    	# --- 前向传播 & 计算损失 ---
	        optimizer.zero_grad()  # 清空优化器中的上一次计算的梯度（防止梯度累积）
	        x, y = x.to(device), y.to(device)  # 将数据移动到CPU/GPU
	        pred = model(x)	# 模型前向计算，得到预测值
	        loss = criterion(pred, y)	# 计算预测值与真实值的损失
	
			# --- 反向传播 & 参数更新 ---
	        loss.backward()  # 反向传播，计算梯度
	        optimizer.step()  # 根据梯度更新模型参数
	
			# --- 记录训练信息 ---
	        step += 1	# 全局步数计数器（用于TensorBoard记录）
	        loss_record.append(loss.detach().item())	# 记录当前batch的损失（脱离计算图）
	
		# --- 计算并记录当前epoch的平均训练损失 ---
	    mean_train_loss = sum(loss_record) / len(loss_record)	# 计算epoch平均损失
	    writer.add_scalar('Loss/train', mean_train_loss, step)	# 写入TensorBoard
	
	    # ===== 验证阶段 =====
	    model.eval()  # 设置模型为评估模式（关闭Dropout/BatchNorm的随机性）
	    loss_record = []	# 重置损失记录列表
	
		# 遍历验证集的所有batch（无需梯度计算）
	    for x, y in valid_loader:
	        x, y = x.to(device), y.to(device)
	        with torch.no_grad():	# 禁用自动求导以节省内存/计算资源
	            pred = model(x)
	            loss = criterion(pred, y)
	        loss_record.append(loss.item())	# 记录验证损失
	
		# --- 计算验证指标 ---
	    mean_valid_loss = sum(loss_record) / len(loss_record)
	    # 打印epoch结果（训练损失 + 验证损失）
	    print(f'Epoch [{epoch + 1}/{n_epochs}]: Train loss: {mean_train_loss:.4f}, Valid loss: {mean_valid_loss:.4f}')
	    writer.add_scalar('Loss/valid', mean_valid_loss, step)	# 记录验证损失
	
	    # ====== 模型保存 & 早停机制 ======
	    if mean_valid_loss < best_loss:	# 如果当前模型更优
	        best_loss = mean_valid_loss	# 更新最佳验证损失
	        torch.save(model.state_dict(), config['save_path'])	# 保存模型权重
	        print('Saving model with loss {:.3f}...'.format(best_loss))
	        early_stop_count = 0	# 重置早停计数器
	    else:
	        early_stop_count += 1	# 模型未提升，计数器+1
	
		# 检查是否触发早停条件
	    if early_stop_count >= config['early_stop']:
	        print('\nModel is not improving, training stopped.')
	        break	# 终止训练循环
```

- `transforms.Compose`: 将多个变换组合成一个单一的变换管道。

> https://transformers.run/c2/2021-12-14-transformers-note-3/

## PS

torch.nn.Moudle

torch.nn.functional

Compose()按顺序处理数据

以图像为例：（训练集和测试集略有不同）统一大小，数据增强（旋转、翻转等）增加数据的多样性、随机性，裁剪（图片的某一部分【最终的图片大小】），ToTensor，Normalize

本质：怎样从数据中作特征提取

分词、ID映射 Embedding向量，每个词对应不同的Embedding向量

指定随机种子，因为每次训练模型使用框架的默认随机初始化值，要保证每次训练随机初始化的值相同，从而为进一步对不同训练出来的模型参数进行对比（这样才具有可比性）

模型使用，持续加载模型（模型推理），持续在GPU中，【eg：训练时用的resnet进行训练的模型参数，加载的时候需要同样的加载原始模型结构，再将新的模型参数赋值给随机初始化的原始模型结构】，数据预处理（对用户传入的数据做与模型训练时进行数据预处理同样的操作）