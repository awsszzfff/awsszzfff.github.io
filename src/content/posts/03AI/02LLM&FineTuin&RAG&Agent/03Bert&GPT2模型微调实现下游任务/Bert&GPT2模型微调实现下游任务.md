---
title: Bert&GPT2模型微调实现下游任务
date: 2025-07-04
tags:
  - Others
categories:
  - AI
description: Bert&GPT2模型微调实现下游任务
---
基本流程：需求分析，数据（格式转换，数据处理），模型训练（拟合...），模型测试（测试指标），模型部署

## 微调Bert模型实现中文评论情感分析任务

（二分类）

### 数据集准备

```python file:Mydata.py
from torch.utils.data import Dataset  
from datasets import load_from_disk  
  
  
class MyDataset(Dataset):  
    # 初始化数据集  
    def __init__(self, split):  
        # 从磁盘加载数据  
        self.dataset = load_from_disk(r"\data\ChnSentiCorp")  
        if split == "train":  
            self.dataset = self.dataset["train"]  
        elif split == "test":  
            self.dataset = self.dataset["test"]  
        elif split == "validation":  
            self.dataset = self.dataset["validation"]  
        else:  
            print("数据名错误！")  
  
    # 返回数据集长度  
    def __len__(self):  
        return len(self.dataset)  
  
    # 对每条数据单独做处理  
    # 对于NLP，最终输入给模型的应该是编码之后的数据，可以在getitem中处理，也可以在模型训练时再做处理，一般不在gititem中处理  
    def __getitem__(self, item):  
        text = self.dataset[item]["text"]  
        label = self.dataset[item]["label"]  
  
        return text, label  
  
  
if __name__ == '__main__':  
    dataset = MyDataset("train")  
    for data in dataset:  
        print(data)
```

### 网络模型设计

增量微调

```python file:net.py
import torch  
from transformers import BertModel  
  
# 定义设备信息  
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")  
print(DEVICE)  
  
# 加载预训练模型  
pretrained = BertModel.from_pretrained(  
    r"\models\bert-base-chinese\models--bert-base-chinese\snapshots\c30a6ed22ab4564dc1e3b2ecbf6e766b0611a33f").to(  
    DEVICE)  
print(pretrained)  
  
  
# 定义下游任务（增量模型）  
class Model(torch.nn.Module):  
    def __init__(self):  
        super().__init__()  
        # 这里设计一个简单的全连接网络，实现二分类任务
        # （在不改变原有模型的条件下，做增量微调）
        self.fc = torch.nn.Linear(768, 2)  
  
    # 使用模型处理数据（执行前向计算）  
    def forward(self, input_ids, attention_mask, token_type_ids):  
        # 冻结Bert模型的参数，让其不参与训练  
        with torch.no_grad():  
            out = pretrained(input_ids=input_ids, attention_mask=attention_mask, token_type_ids=token_type_ids)  
        # 增量模型参与训练  
        out = self.fc(out.last_hidden_state[:, 0])  
        return out
```

### 模型训练

```python file:train_val.py
# train_val.py -> 模型训练  
import torch  
from MyData import MyDataset  
from torch.utils.data import DataLoader  
from net import Model  
from transformers import BertTokenizer, AdamW  
  
# 定义设备信息  
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")  
# 定义训练的轮次(将整个数据集训练完一次为一轮)  
EPOCH = 30000  
  
# 加载字典和分词器  
token = BertTokenizer.from_pretrained(  
    r"\models\bert-base-chinese\models--bert-base-chinese\snapshots\c30a6ed22ab4564dc1e3b2ecbf6e766b0611a33f")  
  
  
# 将传入的字符串进行编码  
def collate_fn(data):  
    sents = [i[0] for i in data]  
    label = [i[1] for i in data]  
    # 编码  
    data = token.batch_encode_plus(  
        batch_text_or_text_pairs=sents,  
        # 当句子长度大于max_length(上限是model_max_length)时，截断  
        truncation=True,  
        max_length=512,  
        # 一律补0到max_length  
        padding="max_length",  
        # 可取值为tf,pt,np,默认为list  
        return_tensors="pt",  
        # 返回序列长度  
        return_length=True  
    )  
    input_ids = data["input_ids"]  
    attention_mask = data["attention_mask"]  
    token_type_ids = data["token_type_ids"]  
    label = torch.LongTensor(label)  
    return input_ids, attention_mask, token_type_ids, label  
  
  
# 创建数据集  
train_dataset = MyDataset("train")  
train_loader = DataLoader(  
    dataset=train_dataset,  
    # 训练批次  
    batch_size=50,  
    # 打乱数据集  
    shuffle=True,  
    # 舍弃最后一个批次的数据，防止形状出错  
    drop_last=True,  
    # 对加载的数据进行编码  
    collate_fn=collate_fn  
)  
# 创建验证数据集  
val_dataset = MyDataset("validation")  
val_loader = DataLoader(  
    dataset=val_dataset,  
    # 训练批次  
    batch_size=50,  
    # 打乱数据集  
    shuffle=True,  
    # 舍弃最后一个批次的数据，防止形状出错  
    drop_last=True,  
    # 对加载的数据进行编码  
    collate_fn=collate_fn  
)  
if __name__ == '__main__':  
    # 开始训练  
    print(DEVICE)  
    model = Model().to(DEVICE)  
    # 定义优化器  
    optimizer = AdamW(model.parameters())  
    # 定义损失函数  
    loss_func = torch.nn.CrossEntropyLoss()  
  
    # 初始化验证最佳准确率  
    best_val_acc = 0.0  
  
    for epoch in range(EPOCH):  
        for i, (input_ids, attention_mask, token_type_ids, label) in enumerate(train_loader):  
            # 将数据放到DVEVICE上面  
            input_ids, attention_mask, token_type_ids, label = input_ids.to(DEVICE), attention_mask.to(  
                DEVICE), token_type_ids.to(DEVICE), label.to(DEVICE)  
            # 前向计算（将数据输入模型得到输出）  
            out = model(input_ids, attention_mask, token_type_ids)  
            # 根据输出计算损失  
            loss = loss_func(out, label)  
            # 根据误差优化参数  
            optimizer.zero_grad()  
            loss.backward()  
            optimizer.step()  
  
            # 每隔5个批次输出训练信息  
            if i % 5 == 0:  
                out = out.argmax(dim=1)  
                # 计算训练精度  
                acc = (out == label).sum().item() / len(label)  
                print(f"epoch:{epoch},i:{i},loss:{loss.item()},acc:{acc}")  
        # 验证模型（判断模型是否过拟合）  
        # 设置为评估模型  
        model.eval()  
        # 不需要模型参与训练  
        with torch.no_grad():  
            val_acc = 0.0  
            val_loss = 0.0  
            for i, (input_ids, attention_mask, token_type_ids, label) in enumerate(val_loader):  
                # 将数据放到DVEVICE上面  
                input_ids, attention_mask, token_type_ids, label = input_ids.to(DEVICE), attention_mask.to(  
                    DEVICE), token_type_ids.to(DEVICE), label.to(DEVICE)  
                # 前向计算（将数据输入模型得到输出）  
                out = model(input_ids, attention_mask, token_type_ids)  
                # 根据输出计算损失  
                val_loss += loss_func(out, label)  
                # 根据数据，计算验证精度  
                out = out.argmax(dim=1)  
                val_acc += (out == label).sum().item()  
            val_loss /= len(val_loader)  
            val_acc /= len(val_loader)  
            print(f"验证集：loss:{val_loss},acc:{val_acc}")  
            # #每训练完一轮，保存一次参数  
            # torch.save(model.state_dict(),f"params/{epoch}_bert.pth")  
            # print(epoch,"参数保存成功！")  
            # 根据验证准确率保存最优参数  
            if val_acc > best_val_acc:  
                best_val_acc = val_acc  
                torch.save(model.state_dict(), "params/best_bert.pth")  
                print(f"EPOCH:{epoch}:保存最优参数：acc{best_val_acc}")  
        # 保存最后一轮参数  
        torch.save(model.state_dict(), "params/last_bert.pth")  
        print(f"EPOCH:{epoch}:最后一轮参数保存成功！")
```

### 模型评估

输入评测数据 -> 加载训练好的模型参数 -> 根据输出计算模型评估报告

```python file:test.py
# test.py - 模型评估测试模块  
import torch  
from MyData import MyDataset  
from torch.utils.data import DataLoader  
from net import Model  
from transformers import BertTokenizer  
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score  
from sklearn.metrics import confusion_matrix, classification_report  
import matplotlib.pyplot as plt  
import seaborn as sns  
import numpy as np  
import os  
  
# 定义设备信息  
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")  
  
# 加载字典和分词器  
token = BertTokenizer.from_pretrained(  
    r"\models\bert-base-chinese\models--bert-base-chinese\snapshots\c30a6ed22ab4564dc1e3b2ecbf6e766b0611a33f")  
  
  
# 将传入的字符串进行编码  
def collate_fn(data):  
    sents = [i[0] for i in data]  
    label = [i[1] for i in data]  
    # 编码  
    data = token.batch_encode_plus(  
        batch_text_or_text_pairs=sents,  
        # 当句子长度大于max_length(上限是model_max_length)时，截断  
        truncation=True,  
        max_length=512,  
        # 一律补0到max_length  
        padding="max_length",  
        # 可取值为tf,pt,np,默认为list  
        return_tensors="pt",  
        # 返回序列长度  
        return_length=True  
    )  
    input_ids = data["input_ids"]  
    attention_mask = data["attention_mask"]  
    token_type_ids = data["token_type_ids"]  
    label = torch.LongTensor(label)  
    return input_ids, attention_mask, token_type_ids, label  
  
  
def evaluate_model(model, test_loader, device):  
    """  
    评估模型在测试集上的性能  
    :param model: 待评估模型  
    :param test_loader: 测试数据加载器  
    :param device: 计算设备  
    :return: 评估指标字典  
    """    model.eval()  
    all_preds, all_labels = [], []  
  
    for i, (input_ids, attention_mask, token_type_ids, labels) in enumerate(test_loader):  
        # 将数据转移到设备  
        input_ids = input_ids.to(device)  
        attention_mask = attention_mask.to(device)  
        token_type_ids = token_type_ids.to(device)  
        labels = labels.to(device)  
  
        # 前向传播  
        with torch.no_grad():  
            outputs = model(input_ids, attention_mask, token_type_ids)  
            preds = torch.argmax(outputs, dim=1)  
  
        # 收集预测结果  
        all_preds.extend(preds.cpu().numpy())  
        all_labels.extend(labels.cpu().numpy())  
  
    # 计算评估指标  
    metrics = {  
        'accuracy': accuracy_score(all_labels, all_preds),  
        'precision_macro': precision_score(all_labels, all_preds, average='macro'),  
        'recall_macro': recall_score(all_labels, all_preds, average='macro'),  
        'f1_macro': f1_score(all_labels, all_preds, average='macro'),  
        'precision_weighted': precision_score(all_labels, all_preds, average='weighted'),  
        'recall_weighted': recall_score(all_labels, all_preds, average='weighted'),  
        'f1_weighted': f1_score(all_labels, all_preds, average='weighted'),  
        'confusion_matrix': confusion_matrix(all_labels, all_preds),  
        'classification_report': classification_report(all_labels, all_preds, digits=4)  
    }  
    return metrics  
  
  
def plot_confusion_matrix(cm, class_names, save_path=None):  
    """  
    绘制并保存混淆矩阵  
    :param cm: 混淆矩阵  
    :param class_names: 类别名称列表  
    :param save_path: 保存路径（可选）  
    """    plt.figure(figsize=(10, 8))  
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',  
                xticklabels=class_names, yticklabels=class_names)  
    plt.xlabel('预测标签')  
    plt.ylabel('真实标签')  
    plt.title('混淆矩阵')  
  
    if save_path:  
        plt.savefig(save_path, bbox_inches='tight')  
        print(f"混淆矩阵已保存至: {save_path}")  
    plt.show()  
  
  
def save_metrics_to_file(metrics, save_path):  
    """  
    将评估指标保存到文本文件  
    :param metrics: 评估指标字典  
    :param save_path: 保存路径  
    """    with open(save_path, 'w', encoding='utf-8') as f:  
        f.write("模型评估报告\n")  
        f.write("=" * 50 + "\n")  
        f.write(f"准确率 (Accuracy): {metrics['accuracy']:.4f}\n\n")  
  
        f.write("宏平均指标 (Macro-average):\n")  
        f.write(f"  精确率 (Precision): {metrics['precision_macro']:.4f}\n")  
        f.write(f"  召回率 (Recall): {metrics['recall_macro']:.4f}\n")  
        f.write(f"  F1分数 (F1 Score): {metrics['f1_macro']:.4f}\n\n")  
  
        f.write("加权平均指标 (Weighted-average):\n")  
        f.write(f"  精确率 (Precision): {metrics['precision_weighted']:.4f}\n")  
        f.write(f"  召回率 (Recall): {metrics['recall_weighted']:.4f}\n")  
        f.write(f"  F1分数 (F1 Score): {metrics['f1_weighted']:.4f}\n\n")  
  
        f.write("分类报告 (Classification Report):\n")  
        f.write(metrics['classification_report'])  
  
        f.write("\n\n混淆矩阵 (Confusion Matrix):\n")  
        np.savetxt(f, metrics['confusion_matrix'], fmt='%d')  
  
    print(f"评估报告已保存至: {save_path}")  
  
  
if __name__ == '__main__':  
    # 创建数据集  
    test_dataset = MyDataset("test")  
    test_loader = DataLoader(  
        dataset=test_dataset,  
        batch_size=100,  
        shuffle=False,  # 评估时不需要打乱  
        drop_last=False,  # 保留所有样本  
        collate_fn=collate_fn  
    )  
  
    # 开始测试  
    print(f"使用设备: {DEVICE}")  
    model = Model().to(DEVICE)  
  
    # 模型参数路径  
    model_path = "params/best_bert.pth"  
    if not os.path.exists(model_path):  
        raise FileNotFoundError(f"模型参数文件不存在: {model_path}")  
  
    # 加载模型训练参数  
    model.load_state_dict(torch.load(model_path))  
  
    # 评估模型  
    metrics = evaluate_model(model, test_loader, DEVICE)  
  
    # 打印评估结果  
    print("\n" + "=" * 50)  
    print(f"准确率 (Accuracy): {metrics['accuracy']:.4f}")  
    print("\n宏平均指标 (Macro-average):")  
    print(f"  精确率 (Precision): {metrics['precision_macro']:.4f}")  
    print(f"  召回率 (Recall): {metrics['recall_macro']:.4f}")  
    print(f"  F1分数 (F1 Score): {metrics['f1_macro']:.4f}")  
  
    print("\n加权平均指标 (Weighted-average):")  
    print(f"  精确率 (Precision): {metrics['precision_weighted']:.4f}")  
    print(f"  召回率 (Recall): {metrics['recall_weighted']:.4f}")  
    print(f"  F1分数 (F1 Score): {metrics['f1_weighted']:.4f}")  
  
    print("\n分类报告 (Classification Report):")  
    print(metrics['classification_report'])  
  
    # 可视化混淆矩阵  
    # 注意：根据您的实际类别修改class_names  
    class_names = ["类别0", "类别1"]  # 替换为您的实际类别名称  
    plot_confusion_matrix(metrics['confusion_matrix'], class_names, "confusion_matrix.png")  
  
    # 保存评估结果  
    save_metrics_to_file(metrics, "evaluation_report.txt")  
  
    print("评估完成!")
```

### 模型测试使用

```python file:run.py
# 模型使用接口（主观评估）  
  
import torch  
from net import Model  
from transformers import BertTokenizer  
  
# 定义设备信息  
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")  
  
# 加载字典和分词器  
token = BertTokenizer.from_pretrained(  
    r"D:\jukeai\demo_05\model\bert-base-chinese\models--bert-base-chinese\snapshots\c30a6ed22ab4564dc1e3b2ecbf6e766b0611a33f")  
model = Model().to(DEVICE)  
names = ["负向评价", "正向评价"]  
  
  
# 将传入的字符串进行编码  
def collate_fn(data):  
    sents = []  
    sents.append(data)  
    # 编码  
    data = token.batch_encode_plus(  
        batch_text_or_text_pairs=sents,  
        # 当句子长度大于max_length(上限是model_max_length)时，截断  
        truncation=True,  
        max_length=512,  
        # 一律补0到max_length  
        padding="max_length",  
        # 可取值为tf,pt,np,默认为list  
        return_tensors="pt",  
        # 返回序列长度  
        return_length=True  
    )  
    input_ids = data["input_ids"]  
    attention_mask = data["attention_mask"]  
    token_type_ids = data["token_type_ids"]  
    return input_ids, attention_mask, token_type_ids  
  
  
def test():  
    # 加载模型训练参数  
    model.load_state_dict(torch.load("params/best_bert.pth"))  
    # 开启测试模型  
    model.eval()  
  
    while True:  
        data = input("请输入测试数据（输入‘q’退出）：")  
        if data == 'q':  
            print("测试结束")  
            break  
        input_ids, attention_mask, token_type_ids = collate_fn(data)  
        input_ids, attention_mask, token_type_ids = input_ids.to(DEVICE), attention_mask.to(DEVICE), token_type_ids.to(  
            DEVICE)  
  
        # 将数据输入到模型，得到输出  
        with torch.no_grad():  
            out = model(input_ids, attention_mask, token_type_ids)  
            out = out.argmax(dim=1)  
            print("模型判定：", names[out], "\n")  
  
  
if __name__ == '__main__':  
    test()
```

## 其他数据分类

（多分类）

### 数据集准备

PS：数据集的准备根据特定数据而定

```python file:MyData.py
from torch.utils.data import Dataset  
from datasets import load_dataset  
  
  
class MyDataset(Dataset):  
    def __init__(self, split):  
        # 从磁盘加载csv数据  
        self.dataset = load_dataset(path="csv", data_files=f"data/Weibo/{split}.csv", split="train")  
  
    def __len__(self):  
        return len(self.dataset)  
  
    def __getitem__(self, item):  
        text = self.dataset[item]["text"]  
        label = self.dataset[item]["label"]  
  
        return text, label  
  
  
if __name__ == '__main__':  
    dataset = MyDataset("test")  
    for data in dataset:  
        print(data)
```

### 网络模型设计

```python
import torch  
from transformers import BertModel  
  
# 定义设备信息  
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")  
print(DEVICE)  
  
# 加载预训练模型  
pretrained = BertModel.from_pretrained(  
    r"\models\bert-base-chinese\models--bert-base-chinese\snapshots\c30a6ed22ab4564dc1e3b2ecbf6e766b0611a33f").to(  
    DEVICE)  
print(pretrained)  
  
  
# 定义下游任务（增量模型）  
class Model(torch.nn.Module):  
    def __init__(self):  
        super().__init__()  
        # 设计全连接网络，实现八分类任务  
        self.fc = torch.nn.Linear(768, 8)  # 相比与上方关键修改位置
  
    # 使用模型处理数据（执行前向计算）  
    def forward(self, input_ids, attention_mask, token_type_ids):  
        # 冻结Bert模型的参数，让其不参与训练  
        with torch.no_grad():  
            out = pretrained(input_ids=input_ids, attention_mask=attention_mask, token_type_ids=token_type_ids)  
        # 增量模型参与训练  
        out = self.fc(out.last_hidden_state[:, 0])  
        return out
```

### ...（剩余基本相同）

## 微调GPT2模型实现文本生成任务

古诗词生成任务

### 数据集准备

```python
from torch.utils.data import Dataset  
  
  
class MyDataset(Dataset):  
    def __init__(self):  
        with open("data/chinese_poems.txt", encoding="utf-8") as f:  
            lines = f.readlines()  
        lines = [i.strip() for i in lines]  
        self.lines = lines  
  
    def __len__(self):  
        return len(self.lines)  
  
    def __getitem__(self, item):  
        return self.lines[item]  
    # 一般是要返回一行一个数据和其对应的标签，但对于生成模型，一行数据它自身即是数据也是标签
  
  
if __name__ == '__main__':  
    dataset = MyDataset()  
    for data in dataset:  
        print(data)
```

### 训练

```python file:train.py
from transformers import AdamW  
from transformers.optimization import get_scheduler  
import torch  
from data import MyDataset  # 导入自定义的数据集类  
from transformers import AutoModelForCausalLM, AutoTokenizer  # 导入transformers的模型和分词器类  
from torch.utils.data import DataLoader  # 导入PyTorch的数据加载器类  
  
# 实例化自定义数据集  
dataset = MyDataset()  # 创建数据集对象  
  
# 加载预训练的分词器，用于文本编码  
tokenizer = AutoTokenizer.from_pretrained(  
    r"\models\gpt2-chinese-model\models--uer--gpt2-chinese-cluecorpussmall\snapshots\c2c0249d8a2731f269414cc3b22dff021f8e07a3")  
# 加载预训练的模型，用于语言模型任务  
model = AutoModelForCausalLM.from_pretrained(  
    r"\models\gpt2-chinese-model\models--uer--gpt2-chinese-cluecorpussmall\snapshots\c2c0249d8a2731f269414cc3b22dff021f8e07a3")  
  
  
# 定义一个函数，用于将文本数据转换为模型所需的格式  
def collate_fn(data):  
    # 使用分词器对数据进行编码，并填充或截断到固定长度  
    data = tokenizer.batch_encode_plus(data,  
                                       padding=True,  # 填充序列  
                                       truncation=True,  # 截断序列  
                                       max_length=512,  # 最大长度  
                                       return_tensors='pt')  # 返回PyTorch张量  
    # 复制输入ID作为标签，用于语言模型训练  
    data['labels'] = data['input_ids'].clone()  
    return data  
  
  
# 使用DataLoader创建数据加载器，用于批量加载数据  
loader = DataLoader(  
    dataset=dataset,  # 指定数据集  
    batch_size=2,  # 指定批量大小  
    shuffle=True,  # 打乱数据  
    drop_last=True,  # 如果最后一个批次的数据量小于batch_size，则丢弃  
    collate_fn=collate_fn  # 指定如何从数据集中收集样本到批次中  
)  
print(f"数据的长度：{len(loader)}")  # 打印数据加载器中的批次数量  
  
  
# 定义训练函数  
def train():  
    # 定义训练参数  
    EPOCH = 3000  # 训练轮数  
    global model  # 使用全局模型变量  
    DEVICE = "cuda" if torch.cuda.is_available() else "cpu"  # 检测是否有GPU，如果有则使用，否则使用CPU  
    model = model.to(DEVICE)  # 将模型移动到指定设备  
  
    # 定义优化器  
    optimizer = AdamW(model.parameters(), lr=2e-5)  # 使用AdamW优化器，并设置学习率  
    # 定义学习率调度器  
    scheduler = get_scheduler(name="linear",  # 线性调度器  
                              num_warmup_steps=0,  # 预热步数  
                              num_training_steps=len(loader),  # 总训练步数  
                              optimizer=optimizer)  
    model.train()  # 将模型设置为训练模式  
    for epoch in range(EPOCH):  # 循环每一轮训练  
        for i, data in enumerate(loader):  # 遍历数据加载器中的批次  
            for k in data.keys():  # 将数据移动到指定设备  
                data[k] = data[k].to(DEVICE)  
            out = model(**data)  # 前向传播  
            loss = out['loss']  # 获取损失
  
            loss.backward()  # 反向传播  
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)  # 梯度裁剪，防止梯度爆炸  
            optimizer.step()  # 更新模型参数  
            scheduler.step()  # 更新学习率  
  
            optimizer.zero_grad()  # 清空优化器的梯度  
            model.zero_grad()  # 清空模型的梯度  
  
            if i % 50 == 0:  # 每隔50个批次打印一次信息  
                labels = data["labels"][:, 1:]  # 获取真实标签，忽略<bos>标记  
                out = out["logits"].argmax(dim=2)[:, :-1]  # 获取预测结果，忽略<eos>标记  
  
                select = labels != 0  # 选择非填充的标签  
                labels = labels[select]  # 应用选择  
                out = out[select]  # 应用选择  
                del select  # 删除不再使用的select  
                # 计算准确率  
                acc = (labels == out).sum().item() / labels.numel()  # 计算准确率的公式  
                lr = optimizer.state_dict()["param_groups"][0]['lr']  # 获取当前学习率  
  
                # 打印训练信息  
                print(f"epoch:{epoch},batch:{i},loss:{loss.item()},lr:{lr},acc:{acc}")  
  
        # 保存最后一轮模型参数  
        torch.save(model.state_dict(), "params/net.pt")  # 保存模型参数到指定路径  
        print("权重保存成功！")  # 打印成功信息  
  
  
# 当该脚本作为主程序运行时，调用训练函数  
if __name__ == '__main__':  
    train()  # 开始训练过程
```

对于生成模型，一般无法通过具体客观的指标来评估。

### 测试

```python file:detect.py
from transformers import AutoModelForCausalLM, AutoTokenizer, TextGenerationPipeline  
import torch  
  
tokenizer = AutoTokenizer.from_pretrained(  
    r"\models\gpt2-chinese-model\models--uer--gpt2-chinese-cluecorpussmall\snapshots\c2c0249d8a2731f269414cc3b22dff021f8e07a3")  
model = AutoModelForCausalLM.from_pretrained(  
    r"\models\gpt2-chinese-model\models--uer--gpt2-chinese-cluecorpussmall\snapshots\c2c0249d8a2731f269414cc3b22dff021f8e07a3")  
  
# 加载我们自己训练的权重（中文古诗词）  
model.load_state_dict(torch.load("params/net.pt"))  
  
# 使用系统自带的pipeline工具生成内容  
pipeline = TextGenerationPipeline(model, tokenizer, device=0)  
  
for i in range(5):  
    print(pipeline("白日", max_length=24, do_sample=True))
```

### 后处理

```python
# 定制化生成内容  （对其生成格式进行处理）
import torch  
from transformers import AutoTokenizer, AutoModelForCausalLM  
  
tokenizer = AutoTokenizer.from_pretrained(  
    r"\models\gpt2-chinese-model\models--uer--gpt2-chinese-cluecorpussmall\snapshots\c2c0249d8a2731f269414cc3b22dff021f8e07a3")  
model = AutoModelForCausalLM.from_pretrained(  
    r"\models\gpt2-chinese-model\models--uer--gpt2-chinese-cluecorpussmall\snapshots\c2c0249d8a2731f269414cc3b22dff021f8e07a3")  
  
# 加载我们自己训练的权重（中文古诗词）  
model.load_state_dict(torch.load("params/net.pt", map_location="cpu"))  
  
  
# 定义函数，用于生成5言绝句 text是提示词，row是生成文本的行数，col是每行的字符数。  
def generate(text, row, col):  
    # 定义一个内部递归函数，用于生成文本  
    def generate_loop(data):  
        # 禁用梯度计算  
        with torch.no_grad():  
            # 使用data字典中的数据作为模型输入，并获取输出  
            out = model(**data)  
        # 获取最后一个字(logits未归一化的概率输出)  
        out = out["logits"]  
        # 选择每个序列的最后一个logits，对应于下一个词的预测  
        out = out[:, -1]  
  
        # 找到概率排名前50的值，以此为分界线，小于该值的全部舍去  
        topk_value = torch.topk(out, 50).values  
        # 获取每个输出序列中前50个最大的logits（为保持原维度不变，需要对结果增加一个维度，因为索引操作会降维）  
        topk_value = topk_value[:, -1].unsqueeze(dim=1)  
        # 将所有小于第50大的值的logits设置为负无穷，减少低概率词的选择  
        out = out.masked_fill(out < topk_value, -float("inf"))  
  
        # 将特殊符号的logits值设置为负无穷，防止模型生成这些符号。  
        for i in ",.()《》[]「」{}，。":  
            out[:, tokenizer.get_vocab()[i]] = -float('inf')  
        # 去特殊符号  
        out[:, tokenizer.get_vocab()["[UNK]"]] = -float('inf')  
  
        out = out.softmax(dim=1)  
        # 从概率分布中进行采样，选择下一个词的ID  
        out = out.multinomial(num_samples=1)  
  
        # 强值添加标点符号  
        # 计算当前生成的文本长度于预期的长度的比例  
        c = data["input_ids"].shape[1] / (col + 1)  
        # 如果当前的长度是预期长度的整数倍，则添加标点符号  
        if c % 1 == 0:  
            if c % 2 == 0:  
                # 在偶数位添加句号  
                out[:, 0] = tokenizer.get_vocab()["."]  
            else:  
                # 在奇数位添加逗号  
                out[:, 0] = tokenizer.get_vocab()[","]  
        # 将生成的新词ID添加到输入序列的末尾  
        data["input_ids"] = torch.cat([data["input_ids"], out], dim=1)  
        # 更新注意力掩码，标记所有有效位置  
        data["attention_mask"] = torch.ones_like(data["input_ids"])  
        # 更新token的ID类型，通常在BERTm模型中使用，但是在GPT模型中是不用的  
        data["token_type_ids"] = torch.ones_like(data["input_ids"])  
        # 更新标签，这里将输入ID复制到标签中，在语言生成模型中通常用与预测下一个词  
        data["labels"] = data["input_ids"].clone()  
  
        # 检查生成的文本长度是否达到或超过指定的行数和列数  
        if data["input_ids"].shape[1] >= row * col + row + 1:  
            # 如果达到长度要求，则返回最终的data字典  
            return data  
        # 如果长度未达到要求，递归调用generate_loop函数继续生成文本  
        return generate_loop(data)  
  
    # 生成3首诗词  
    # 使用tokenizer对输入文本进行编码，并重复3次生成3个样本。  
    data = tokenizer.batch_encode_plus([text] * 3, return_tensors="pt")  
    # 移除编码后的序列中的最后一个token(结束符号)  
    data["input_ids"] = data["input_ids"][:, :-1]  
    # 创建一个与input_ids形状相同的全1张量，用于注意力掩码  
    data["attention_mask"] = torch.ones_like(data["input_ids"])  
    # 创建一个与input_ids形状相同的全0张量，用于token类型ID  
    data["token_type_ids"] = torch.zeros_like(data["input_ids"])  
    # 复制input_ids到labels，用于模型的目标  
    data['labels'] = data["input_ids"].clone()  
  
    # 调用generate_loop函数开始生成文本  
    data = generate_loop(data)  
  
    # 遍历生成的3个样本  
    for i in range(3):  
        # 打印输出样本索引和对应的解码后的文本  
        print(i, tokenizer.decode(data["input_ids"][i]))  
  
  
if __name__ == '__main__':  
    generate("白", row=4, col=5)
```
