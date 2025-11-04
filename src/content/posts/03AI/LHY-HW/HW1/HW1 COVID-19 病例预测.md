---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "HW1 COVID-19 病例预测"
---
关于美国新冠阳性病例的预测，给定美国37个州连续五天的数据，前四天包括收集到的个体特征和每天的感染率，第五天只有个体特征。我们要做的就是训练模型，来预测第五天的感染率。

## 获取数据集

- 从Google Drive上下载

```jupyter
!gdown --id '1kLSW_-cW2Huj7bh84YTdimGBOJaODiOS' --output covid.train.csv

!gdown --id '1iiI5qROrAhZn-o4FPqsE97bMzDEFvIdg' --output covid.test.csv
```

- 如果没有安装gdown可执行如下命令：

```shell
git clone https://github.com/wkentaro/gdown.git
cd gdown
pip install gdown
```

- 从Kaggle.上下载（推荐）

https://www.kaggle.com/competitions/ml2022spring-hw1/data

## 数据集分析

37个州+16个特征共五天（感染疑似症状、行为、症状、阳性病率等），阳性病率为 label 值，37个州以 one-hot vectors 进行存储，第一列 id 自动生成的序号。

`train_set`每一行即一笔数据，一笔数据包含118个 feature ，（即依据这些特征来进行训练和预测，但是里面一些特征没有用 eg:id 在使用时可以选择性的删除来提高预测的成功率）

`test_set`只有117个 feature ，（即最后一个 label 为需要进行预测的结果），将预测结果和真实数据带入 loss 函数，计算 loss 值，从而纠正模型。

## 代码实现

### 导入所需要的库

```python
# 数值、矩阵操作  
import math  
import numpy as np  
  
# 数据读取与写入make_dot  
import pandas as pd  
import os  
import csv  
  
# 进度条  
from tqdm import tqdm  
# 如果是使用notebook 推荐使用以下（颜值更高 : ) ）  
# from tqdm.notebook import tqdm  
  
# Pytorch 深度学习张量操作框架  
import torch  
import torch.nn as nn  
from torch.utils.data import Dataset, DataLoader, random_split
# 绘制pytorch的网络  
from torchviz import make_dot
  
# 学习曲线绘制  
from torch.utils.tensorboard import SummaryWriter
```

### 引入随机种子

为了确保实验的可重复性，引入随机种子，使每次所取的随机样本相同。

【以下可作为设置随机种子模板】

```python
# 设置随机种子  
def same_seed(seed):  
    '''  
    设置随机种子(便于复现)  
    '''    
    # 保证每次输入数据时，输出的结果都是相同的  
    torch.backends.cudnn.deterministic = True  # 使用确定的CuDNN算法  
    torch.backends.cudnn.benchmark = False  # 取消CuDNN每次都去寻找最符合当前配置的高效算法  
    np.random.seed(seed)  # numpy 的随机种子
    torch.manual_seed(seed)  # pytorch在CPU上的随机种子
    if torch.cuda.is_available():  
        torch.cuda.manual_seed_all(seed) # pytorch在GPU上的随机种子 
    print(f'Set Seed = {seed}')
```

### 划分数据集
#### 训练集（train_set）

用来训练模型，即确定模型的权重和偏执等参数，通常称这些参数为学习参数；

#### 验证集（valid_set）

用于模型的选择，为了选择超参数（Hyperparameters），如网络层数、网络结点数、迭代次数、学习率等。

为什么要划分出验证集？——防止出现过拟合（overfitting）和找出最好的一组hyperparameters

HW1中只给出训练集和测试集，所以需要将训练集中的一部分划分为验证集

#### 测试集（test_set）

在训练完成后评价最终的模型时使用

【类比：训练集（历年真题），验证集（模拟卷），测试集（考场真题）】

- `train_set`
- `valid_set`
- `test_set`

```python
# 拆分数据集  
def train_valid_split(data_set, valid_ratio, seed):  
    '''  
    数据集拆分成训练集（training set）和 验证集（validation set）  
    valid_ratio->float:划分比例，eg：valid_ratio=0.2,即需要在训练集中划分出20%作为验证集  
    '''    
    valid_set_size = int(valid_ratio * len(data_set))  
    train_set_size = len(data_set) - valid_set_size  
    train_set, valid_set = random_split(data_set, [train_set_size, valid_set_size],  
                                        generator=torch.Generator().manual_seed(seed))  # pytorch提供的划分数据集的方法  
    return np.array(train_set), np.array(valid_set)
```

### 选择特征

选择训练所需的数据集特征

```python
# 特征选择，减少输入变量数量，以降低建模的计算成本（根据需要来选择进行训练所需的特征）  
def select_feat(train_data, valid_data, test_data, select_all=True):  
    '''  
    特征选择  
    选择较好的特征用来拟合回归模型  
    select_all:为True选项所有的特征作为训练用，为Flase选择所需的特征  
    '''    
    y_train, y_valid = train_data[:, -1], valid_data[:, -1]  # 所有行的最后一个元素，y表示label  
    raw_x_train, raw_x_valid, raw_x_test = train_data[:, :-1], valid_data[:, :-1], test_data  # 所有行除了最后一列的所有元素，x是feature  
  
    if select_all:  
        feat_idx = list(range(raw_x_train.shape[1]))  
    else:  
        feat_idx = [0, 1, 2, 3, 4]  # TODO: 选择需要的特征 ，这部分可以自己调研一些特征选择的方法并完善.  
  
    return raw_x_train[:, feat_idx], raw_x_valid[:, feat_idx], raw_x_test[:, feat_idx], y_train, y_valid
```

### 数据集

-  `__init__`——读取数据并进行预处理
- `__getitem__`——每次取出一笔数据
- `__len__`——返回数据的长度

```python
# 数据集  
class COVID19Dataset(Dataset):  
    '''  
    x: np.ndarray  特征矩阵.  
    y: np.ndarray  目标标签, 如果为None,则是预测的数据集  
    '''  
    def __init__(self, x, y=None):  
        if y is None:  
            self.y = y  
        else:  
            self.y = torch.FloatTensor(y)  # 转换为浮点型的tensor  
        self.x = torch.FloatTensor(x)  
  
    def __getitem__(self, idx):  # 获取所给键的数据样本  
        if self.y is None:  
            return self.x[idx]  # 做预测（不确定）  
        return self.x[idx], self.y[idx]  # 做训练  
  
    def __len__(self):  
        return len(self.x)
```

准备完数据集后需要准备 DataLoader ，DataLoader 本质上是一个迭代器，帮助我们多线程的读取数据，并从这个数据集中取几笔数据组成一个 batch 。（下面【准备DataLoader】）

### 构造神经网络模型

- `__init__`
- `forward`——向前传播，可理解为神经网络处理输入的过程

```python
# 神经网络模型  
class My_Model(nn.Module):  
    def __init__(self, input_dim):  
        super(My_Model, self).__init__()  
        # TODO: 修改模型结构, 注意矩阵的维度（dimensions）  
        self.layers = nn.Sequential(  
            nn.Linear(input_dim, 16),  
            nn.ReLU(),  
            nn.Linear(16, 8),  
            nn.ReLU(),  
            nn.Linear(8, 1)  
        )  
  
    def forward(self, x):  
        x = self.layers(x)  
        x = x.squeeze(1)  # (B, 1) -> (B)  
        return x
```

### 设置超参数

```python
# 超参设置，config包含所有训练需要的超参数（便于后续的调参），以及模型需要存储的位置  
device = 'cuda' if torch.cuda.is_available() else 'cpu'  
config = {  
    'seed': 5201314,  # 随机种子，可以自己填写. :)  
    'select_all': True,  # 是否选择全部的特征  
    'valid_ratio': 0.2,  # 验证集大小(validation_size) = 训练集大小(train_size) * 验证数据占比(valid_ratio)  
    'n_epochs': 3000,  # 数据遍历训练次数，预设最多跑3000趟epochs  
    'batch_size': 256,  # 每个batch的大小
    'learning_rate': 1e-5,  # 学习率
    'early_stop': 400,  # 如果early_stop轮损失没有下降就停止训练.  
    'save_path': './models/model.ckpt'  # 模型存储的位置  
}
```


### 训练部分

- 定义损失函数`Loss`
- 定义优化器`optimizer`
- 训练
	- 训练循环
		- `pred = model(train_set)`
		- `loss(pred, train_targets_label)`
		- `optimizer`
		- `loss_record`
	- `average_train_loss`
	- 验证循环
		- `pred = model(valid_set)`
		- `loss(pred, valid_targets_label)`
	- `average_valid_loss`
	- `average`比较
		- 模型保存

```python
# 训练部分  
def trainer(train_loader, valid_loader, model, config, device):  
    criterion = nn.MSELoss(reduction='mean')  # 损失函数的定义  
  
    # 定义优化器  
    # TODO: 可以查看学习更多的优化器 https://pytorch.org/docs/stable/optim.html    # TODO: L2 正则( 可以使用optimizer(weight decay...) )或者 自己实现L2正则.  
    optimizer = torch.optim.SGD(model.parameters(), lr=config['learning_rate'], momentum=0.9)  
  
    # tensorboard 的记录器  
    writer = SummaryWriter()  
  
    if not os.path.isdir('./models'):  
        # 创建文件夹-用于存储模型  
        os.mkdir('./models')  
  
    n_epochs, best_loss, step, early_stop_count = config['n_epochs'], math.inf, 0, 0  
  
    # 训练train loop  
    for epoch in range(n_epochs):  
        model.train()  # 训练模式  
        loss_record = []  
  
        # tqdm可以帮助我们显示训练的进度  
        train_pbar = tqdm(train_loader, position=0, leave=True)  
        # 设置进度条的左边 ： 显示第几个Epoch了  
        train_pbar.set_description(f'Epoch [{epoch + 1}/{n_epochs}]')  
        for x, y in train_pbar:  
            optimizer.zero_grad()  # 将梯度置0（每一趟内循环将梯度清零，避免影响后续梯度值的计算）  
            x, y = x.to(device), y.to(device)  # 将数据一到相应的存储位置(CPU/GPU)  
            pred = model(x)  
            loss = criterion(pred, y)  
            loss.backward()  # 反向传播 计算梯度.  
            optimizer.step()  # 更新网络参数  
            step += 1  
            loss_record.append(loss.detach().item())  
  
            # 训练完一个batch的数据，将loss 显示在进度条的右边  
            train_pbar.set_postfix({'loss': loss.detach().item()})  
  
        # 平均的loss值  
        mean_train_loss = sum(loss_record) / len(loss_record)  
        # 每个epoch,在tensorboard 中记录训练的损失（后面可以展示出来）  
        writer.add_scalar('Loss/train', mean_train_loss, step)  
  
        # 验证valid loop  
        model.eval()  # 将模型设置成 evaluation 模式.  
        loss_record = []  
        for x, y in valid_loader:  
            x, y = x.to(device), y.to(device)  
            with torch.no_grad():  
                pred = model(x)  
                loss = criterion(pred, y)  
  
            loss_record.append(loss.item())  
  
        mean_valid_loss = sum(loss_record) / len(loss_record)  # 平均loss值  
        print(f'Epoch [{epoch + 1}/{n_epochs}]: Train loss: {mean_train_loss:.4f}, Valid loss: {mean_valid_loss:.4f}')  
        # 每个epoch,在tensorboard 中记录验证的损失（后面可以展示出来）  
        writer.add_scalar('Loss/valid', mean_valid_loss, step)  
  
        if mean_valid_loss < best_loss:  
            best_loss = mean_valid_loss  
            torch.save(model.state_dict(), config['save_path'])  # 模型保存  
            print('Saving model with loss {:.3f}...'.format(best_loss))  
            early_stop_count = 0  
        else:  
            early_stop_count += 1  
  
        if early_stop_count >= config['early_stop']:  
            print('\nModel is not improving, so we halt the training session.')  
            return
```

### 设置随机种子

```python
# 设置随机种子便于复现  
same_seed(config['seed'])  
```

### 读取数据

```python
# 读取数据  
# 训练集大小(train_data size) : 2699 x 118 (id + 37 states + 16 features x 5 days)  
# 测试集大小(test_data size）: 1078 x 117 (没有label (last day's positive rate))  
# pd.set_option('display.max_column', 200) # 设置显示数据的列数  
train_df, test_df = pd.read_csv(r'E:\pycharm\pytorch\HWLHY2023\HW1_Regression\covid_train.csv'), pd.read_csv(  
    r'E:\pycharm\pytorch\HWLHY2023\HW1_Regression\covid_test.csv')  
# display(train_df.head(3)) # 显示前三行的样本  
train_data, test_data = train_df.values, test_df.values  
del train_df, test_df  # 删除数据减少内存占用  
```

### 划分数据集

```python
# 划分数据集  
train_data, valid_data = train_valid_split(train_data, config['valid_ratio'], config['seed'])  
  
# 打印数据的大小  
print(f"""train_data size: {train_data.shape} valid_data size: {valid_data.shape} test_data size: {test_data.shape}""")
```

### 特征选择

```python
# 特征选择  
x_train, x_valid, x_test, y_train, y_valid = select_feat(train_data, valid_data, test_data, config['select_all'])  
  
# 打印出特征数量.  
print(f'number of features: {x_train.shape[1]}') 
```

### 构造数据集

```python
# 构造数据集  
train_dataset, valid_dataset, test_dataset = COVID19Dataset(x_train, y_train), \  
    COVID19Dataset(x_valid, y_valid), \  
    COVID19Dataset(x_test)  
```

### 准备DataLoader

```python  
# 准备Dataloader  
# 使用Pytorch中Dataloader类按照Batch将数据集加载  
train_loader = DataLoader(train_dataset, batch_size=config['batch_size'], shuffle=True, pin_memory=True)  
# shuffle 是否打乱该数据，一般训练时设置为True，测试时设置为False
# pin_memory 是否锁页，即训练过程中将张量固定在GPU中，使数据加载的速度更快
valid_loader = DataLoader(valid_dataset, batch_size=config['batch_size'], shuffle=True, pin_memory=True)  
test_loader = DataLoader(test_dataset, batch_size=config['batch_size'], shuffle=False, pin_memory=True)
```

### 预测

```python
# 预测  
def predict(test_loader, model, device):  
    model.eval()  # 设置成eval模式.  
    preds = []  
    for x in tqdm(test_loader):  
        x = x.to(device)  
        with torch.no_grad():  
            pred = model(x)  
            preds.append(pred.detach().cpu())  
    preds = torch.cat(preds, dim=0).numpy()  # cat()将两个张量拼接在一起，行拼接和列拼接0/1
    return preds  
  
  
# 保存预测结果  
def save_pred(preds, file):  
    with open(file, 'w') as fp:  
        writer = csv.writer(fp)  
        writer.writerow(['id', 'tested_positive'])  
        for i, p in enumerate(preds):  
            writer.writerow([i, p])
```

### 预测并保存

```python
# 开始训练
model = My_Model(input_dim=x_train.shape[1]).to(device)  # 将模型和训练数据放在相同的存储位置(CPU/GPU)  
trainer(train_loader, valid_loader, model, config, device)
# 预测并保存结果
preds = predict(test_loader, model, device)  
save_pred(preds, 'pred.csv')
```


## 【需要完成的功能函数和类】

- 设置随机种子
- 划分数据集
	- `train_set`
	- `valid_set`
	- `test_set`
- 特征选择
- 数据集
	- `__init__`
	- `__getitem__`
	- `__len__`
- 神经网络模型
	- `__init__`
	- `forward`

- 定义损失函数`Loss`
- 定义优化器`optimizer`
- 训练
	- 训练循环
		- `pred = model(train_set)`
		- `loss(pred, train_targets_label)`
		- `optimizer`
		- `loss_record`
	- `average_train_loss`
	- 验证循环
		- `pred = model(valid_set)`
		- `loss(pred, valid_targets_label)`
	- `average_valid_loss`
	- `average`比较
		- 模型保存
- 预测
- 保存预测结果

## 完整流程

- 设置随机种子
- 准备数据
- 选择特征
- 构造数据集
- 封装加载数据集
- 引入模型
- 开始训练

```python
# 数值、矩阵操作  
import math  
import numpy as np  
  
# 数据读取与写入make_dot  
import pandas as pd  
import os  
import csv  
  
# 进度条  
from tqdm import tqdm  
# 如果是使用notebook 推荐使用以下（颜值更高 : ) ）  
# from tqdm.notebook import tqdm  
  
# Pytorch 深度学习张量操作框架  
import torch  
import torch.nn as nn  
from torch.utils.data import Dataset, DataLoader, random_split  
# 绘制pytorch的网络  
from torchviz import make_dot  
  
# 学习曲线绘制  
from torch.utils.tensorboard import SummaryWriter  
  
  
# 功能函数  
# 设置随机种子  
def same_seed(seed):  
    '''  
    设置随机种子(便于复现)  
    '''    # 保证每次输入数据时，输出的结果都是相同的  
    torch.backends.cudnn.deterministic = True  # 使用确定的CuDNN算法  
    torch.backends.cudnn.benchmark = False  # 取消CuDNN每次都去寻找最符合当前配置的高效算法  
    np.random.seed(seed)  
    torch.manual_seed(seed)  
    if torch.cuda.is_available():  
        torch.cuda.manual_seed_all(seed)  
    print(f'Set Seed = {seed}')  
  
  
# 拆分数据集  
def train_valid_split(data_set, valid_ratio, seed):  
    '''  
    数据集拆分成训练集（training set）和 验证集（validation set）  
    valid_ratio->float:划分比例，eg：valid_ratio=0.2,即需要在训练集中划分出20%作为验证集  
    '''    valid_set_size = int(valid_ratio * len(data_set))  
    train_set_size = len(data_set) - valid_set_size  
    train_set, valid_set = random_split(data_set, [train_set_size, valid_set_size],  
                                        generator=torch.Generator().manual_seed(seed))  # pytorch提供的划分数据集的方法  
    return np.array(train_set), np.array(valid_set)  
  
  
# 特征选择，减少输入变量数量，以降低建模的计算成本（根据需要来选择进行训练所需的特征）  
def select_feat(train_data, valid_data, test_data, select_all=True):  
    '''  
    特征选择  
    选择较好的特征用来拟合回归模型  
    select_all:为True选项所有的特征作为训练用，为Flase选择所需的特征  
    '''    y_train, y_valid = train_data[:, -1], valid_data[:, -1]  # 所有行的最后一个元素，y表示label  
    raw_x_train, raw_x_valid, raw_x_test = train_data[:, :-1], valid_data[:, :-1], test_data  # 所有行除了最后一列的所有元素，x是feature  
  
    if select_all:  
        feat_idx = list(range(raw_x_train.shape[1]))  
    else:  
        feat_idx = [0, 1, 2, 3, 4]  # TODO: 选择需要的特征 ，这部分可以自己调研一些特征选择的方法并完善.  
  
    return raw_x_train[:, feat_idx], raw_x_valid[:, feat_idx], raw_x_test[:, feat_idx], y_train, y_valid  
  
  
# 数据集  
class COVID19Dataset(Dataset):  
    '''  
    x: np.ndarray  特征矩阵.  
    y: np.ndarray  目标标签, 如果为None,则是预测的数据集  
    '''  
    def __init__(self, x, y=None):  
        if y is None:  
            self.y = y  
        else:  
            self.y = torch.FloatTensor(y)  # 转换为浮点型的tensor  
        self.x = torch.FloatTensor(x)  
  
    def __getitem__(self, idx):  # 获取所给键的数据样本  
        if self.y is None:  
            return self.x[idx]  # 做预测（不确定）  
        return self.x[idx], self.y[idx]  # 做训练  
  
    def __len__(self):  
        return len(self.x)  
  
  
# 神经网络模型  
class My_Model(nn.Module):  
    def __init__(self, input_dim):  
        super(My_Model, self).__init__()  
        # TODO: 修改模型结构, 注意矩阵的维度（dimensions）  
        self.layers = nn.Sequential(  
            nn.Linear(input_dim, 16),  
            nn.ReLU(),  
            nn.Linear(16, 8),  
            nn.ReLU(),  
            nn.Linear(8, 1)  
        )  
  
    def forward(self, x):  
        x = self.layers(x)  
        x = x.squeeze(1)  # (B, 1) -> (B)  
        return x  
  
  
# 超参设置，config包含所有训练需要的超参数（便于后续的调参），以及模型需要存储的位置  
device = 'cuda' if torch.cuda.is_available() else 'cpu'  
config = {  
    'seed': 5201314,  # 随机种子，可以自己填写. :)  
    'select_all': True,  # 是否选择全部的特征  
    'valid_ratio': 0.2,  # 验证集大小(validation_size) = 训练集大小(train_size) * 验证数据占比(valid_ratio)  
    'n_epochs': 3000,  # 数据遍历训练次数  
    'batch_size': 256,  
    'learning_rate': 1e-5,  
    'early_stop': 400,  # 如果early_stop轮损失没有下降就停止训练.  
    'save_path': './models/model.ckpt'  # 模型存储的位置  
}  
  
  
# 训练部分  
def trainer(train_loader, valid_loader, model, config, device):  
    criterion = nn.MSELoss(reduction='mean')  # 损失函数的定义  
  
    # 定义优化器  
    # TODO: 可以查看学习更多的优化器 https://pytorch.org/docs/stable/optim.html    # TODO: L2 正则( 可以使用optimizer(weight decay...) )或者 自己实现L2正则.  
    optimizer = torch.optim.SGD(model.parameters(), lr=config['learning_rate'], momentum=0.9)  
  
    # tensorboard 的记录器  
    writer = SummaryWriter()  
  
    if not os.path.isdir('./models'):  
        # 创建文件夹-用于存储模型  
        os.mkdir('./models')  
  
    n_epochs, best_loss, step, early_stop_count = config['n_epochs'], math.inf, 0, 0  
  
    # 训练train loop  
    for epoch in range(n_epochs):  
        model.train()  # 训练模式  
        loss_record = []  
  
        # tqdm可以帮助我们显示训练的进度  
        train_pbar = tqdm(train_loader, position=0, leave=True)  
        # 设置进度条的左边 ： 显示第几个Epoch了  
        train_pbar.set_description(f'Epoch [{epoch + 1}/{n_epochs}]')  
        for x, y in train_pbar:  
            optimizer.zero_grad()  # 将梯度置0.  
            x, y = x.to(device), y.to(device)  # 将数据一到相应的存储位置(CPU/GPU)  
            pred = model(x)  
            loss = criterion(pred, y)  
            loss.backward()  # 反向传播 计算梯度.  
            optimizer.step()  # 更新网络参数  
            step += 1  
            loss_record.append(loss.detach().item())  
  
            # 训练完一个batch的数据，将loss 显示在进度条的右边  
            train_pbar.set_postfix({'loss': loss.detach().item()})  
  
        # 平均的loss值  
        mean_train_loss = sum(loss_record) / len(loss_record)  
        # 每个epoch,在tensorboard 中记录训练的损失（后面可以展示出来）  
        writer.add_scalar('Loss/train', mean_train_loss, step)  
  
        # 验证valid loop  
        model.eval()  # 将模型设置成 evaluation 模式.  
        loss_record = []  
        for x, y in valid_loader:  
            x, y = x.to(device), y.to(device)  
            with torch.no_grad():  
                pred = model(x)  
                loss = criterion(pred, y)  
  
            loss_record.append(loss.item())  
  
        mean_valid_loss = sum(loss_record) / len(loss_record)  # 平均loss值  
        print(f'Epoch [{epoch + 1}/{n_epochs}]: Train loss: {mean_train_loss:.4f}, Valid loss: {mean_valid_loss:.4f}')  
        # 每个epoch,在tensorboard 中记录验证的损失（后面可以展示出来）  
        writer.add_scalar('Loss/valid', mean_valid_loss, step)  
  
        if mean_valid_loss < best_loss:  
            best_loss = mean_valid_loss  
            torch.save(model.state_dict(), config['save_path'])  # 模型保存  
            print('Saving model with loss {:.3f}...'.format(best_loss))  
            early_stop_count = 0  
        else:  
            early_stop_count += 1  
  
        if early_stop_count >= config['early_stop']:  
            print('\nModel is not improving, so we halt the training session.')  
            return  
  
  
# 设置随机种子便于复现  
same_seed(config['seed'])  
  
# 读取数据  
# 训练集大小(train_data size) : 2699 x 118 (id + 37 states + 16 features x 5 days)  
# 测试集大小(test_data size）: 1078 x 117 (没有label (last day's positive rate))  
# pd.set_option('display.max_column', 200) # 设置显示数据的列数  
train_df, test_df = pd.read_csv(r'E:\pycharm\pytorch\HWLHY2023\HW1_Regression\covid_train.csv'), pd.read_csv(  
    r'E:\pycharm\pytorch\HWLHY2023\HW1_Regression\covid_test.csv')  
# display(train_df.head(3)) # 显示前三行的样本  
train_data, test_data = train_df.values, test_df.values  
del train_df, test_df  # 删除数据减少内存占用  
# 划分数据集  
train_data, valid_data = train_valid_split(train_data, config['valid_ratio'], config['seed'])  
  
# 打印数据的大小  
print(f"""train_data size: {train_data.shape} valid_data size: {valid_data.shape} test_data size: {test_data.shape}""")  
  
# 特征选择  
x_train, x_valid, x_test, y_train, y_valid = select_feat(train_data, valid_data, test_data, config['select_all'])  
  
# 打印出特征数量.  
print(f'number of features: {x_train.shape[1]}')  
  
# 构造数据集  
train_dataset, valid_dataset, test_dataset = COVID19Dataset(x_train, y_train), \  
    COVID19Dataset(x_valid, y_valid), \  
    COVID19Dataset(x_test)  
  
# 准备Dataloader  
# 使用Pytorch中Dataloader类按照Batch将数据集加载  
train_loader = DataLoader(train_dataset, batch_size=config['batch_size'], shuffle=True, pin_memory=True)  
valid_loader = DataLoader(valid_dataset, batch_size=config['batch_size'], shuffle=True, pin_memory=True)  
test_loader = DataLoader(test_dataset, batch_size=config['batch_size'], shuffle=False, pin_memory=True)  
  
  
# 开始训练  
# model = My_Model(input_dim=x_train.shape[1]).to(device)  # 将模型和训练数据放在相同的存储位置(CPU/GPU)  
# trainer(train_loader, valid_loader, model, config, device)  
  
# 预测  
def predict(test_loader, model, device):  
    model.eval()  # 设置成eval模式.  
    preds = []  
    for x in tqdm(test_loader):  
        x = x.to(device)  
        with torch.no_grad():  
            pred = model(x)  
            preds.append(pred.detach().cpu())  
    preds = torch.cat(preds, dim=0).numpy()  
    return preds  
  
  
# 保存预测结果  
def save_pred(preds, file):  
    with open(file, 'w') as fp:  
        writer = csv.writer(fp)  
        writer.writerow(['id', 'tested_positive'])  
        for i, p in enumerate(preds):  
            writer.writerow([i, p])  
  
  
# 预测并保存结果  
model = My_Model(input_dim=x_train.shape[1]).to(device)  # 将模型和训练数据放在相同的存储位置(CPU/GPU)  
trainer(train_loader, valid_loader, model, config, device)  
preds = predict(test_loader, model, device)  
save_pred(preds, 'pred.csv')
```








