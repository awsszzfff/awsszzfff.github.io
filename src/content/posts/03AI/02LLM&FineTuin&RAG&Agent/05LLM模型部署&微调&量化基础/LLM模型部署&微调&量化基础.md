---
title: "LLM模型部署&微调&量化基础"
date: 2025-08-20
tags:
  - Others
categories:
  - Others
description: None
---
PS: 具体以官网为主（更新较快）

# 模型部署

## Ollama 模型部署

https://ollama.com/ (个人用户部署推荐)

```shell
curl -fsSL https://ollama.com/install.sh | sh
```

魔塔社区搜索 ollama ，利用 魔塔社区加速安装

```shell
ollama serve
ollama list
ollama run <...model_path>
```

Ollama 只能部署 GGUF 格式模型，Ollama 上的模型基本都是量化之后的模型。

### hf 模型转换为 GGUF

llama.cpp 框架

```shell
git clone https://github.com/ggerganov/llama.cpp.git

pip install -r llama.cpp/requirements.txt
```

```shell
# 不量化
python llama.cpp/convert_hf_to_gguf.py ./Meta-Llama-3-8B-Instruct --outtype f16 --verbose --outfile Meta-Llama-3-8B-Instruct-gguf.gguf

# 需要量化（加速并有损效果）
python llama.cpp/convert_hf_to_gguf.py ./Meta-Llama-3-8B-Instruct --outtype q8_0 --verbose --outfile Meta-Llama-3-8B-Instruct-gguf_q8_0.gguf
```

> `--outtype` 是输出类型，代表含义： 
> 
> - q2_k：特定张量（Tensor）采用较高的精度设置，而其他的则保持基础级别；
> - q3_k_l、q3_k_m、q3_k_s：这些变体在不同张量上使用不同级别的精度，从而达到性能和效率的平衡；
> - q4_0：这是最初的量化方案，使用 4 位精度； 
> - q4_1 和 q4_k_m、q4_k_s：这些提供了不同程度的准确性和推理速度，适合需要平衡资源使用的场景；
> - q5_0、q5_1、q5_k_m、q5_k_s：这些版本在保证更高准确度的同时，会使用更多的资源并且推理速度较慢；
> - q6_k 和 q8_0：这些提供了最高的精度，但是因为高资源消耗和慢速度，可能不适合所有用户；
> - fp16 和 f32: 不量化，保留原始精度；

### 转换出的模型部署

```shell
# 创建文件ModeFile（不需要后缀名）作为模型文件，填入以下示例内容
FROM /root/autodl-tmp/Llama3-8B/LLM-Research/Meta-Llama-3-8B-Instruct-gguf8.gguf

# 添加模型到ollama
ollama create llama-3-8B-Instruct --file <ModeFile_path>

# 部署运行
ollama run llama-3-8B-Instruct
```

## vLLM 模型部署

```shell
pip install vllm
```

```shell
vllm serve <...model_path> [--chat-template <...chat_template.jinja>]
# 可指定对话模版


```

> --dtype=half

## LMDeploy 模型部署

```shell
pip install lmdeploy
```

```shell
lmdeploy serve api_server ... --server-port ...
```

## 部署模型调用

单轮对话

```python
#使用openai的API风格调用本地模型
from openai import OpenAI

client = OpenAI(base_url="http://localhost:11434/v1/",api_key="suibianxie")

chat_completion = client.chat.completions.create(
	messages=[{"role":"user","content":"你好，请介绍下你自己。"}],model="qwen3:0.6b"
)

print(chat_completion.choices[0])
```

多轮对话

```python
# 多轮对话  
from openai import OpenAI  
  
  
# 定义多轮对话方法  
def run_chat_session():  
    # 初始化客户端  
    client = OpenAI(base_url="http://localhost:11434/v1/", api_key="suibianxie")  
    # 初始化对话历史  
    chat_history = []  
    # 启动对话循环  
    while True:  
        # 获取用户输入  
        user_input = input("用户：")  
        if user_input.lower() == "exit":  
            print("退出对话。")  
            break  
        # 更新对话历史(添加用户输入)  
        chat_history.append({"role": "user", "content": user_input})  
        # 调用模型回答  
        try:  
            chat_complition = client.chat.completions.create(messages=chat_history, model="deepseek-r1:latest")  
            # 获取最新回答  
            model_response = chat_complition.choices[0]  
            print("AI:", model_response.message.content)  
            # 更新对话历史（添加AI模型的回复）  
            chat_history.append({"role": "assistant", "content": model_response.message.content})  
        except Exception as e:  
            print("发生错误：", e)  
            break  
  
  
if __name__ == '__main__':  
    run_chat_session()
```

> LLM 推理速度（目前） LMDeploy > vLLM > Ollama > Huggingface

一般 huggingface 的推理主要是验证模型微调后的效果，排除由于框架的差异性所导致的效果误差。通过不同框架，不同方式微调的模型得到的模型适配的部署框架效果是不同的。

# 模型微调

- 全量微调
  - 对所有参数进行微调
  - 对算力和显存要求高
  - 效果最佳（前提是数据量和质量优质）
- 局部微调
  - 只调整某些某部分参数，例如输出层，输入层或某些特殊层
  - 对算力和显存要求一般
- 增量微调
  - 通过新增参数的方式进行微调，新的知识存储在新的参数中。
  - 对显存和算力要求低
  - 效果不如全量微调

# 微调方式

## LoRA 微调

局部微调（一般仅会训练到 0.1%~1% 的参数）显存占用较小，训练好的权重可独立保存，动态添加进原始权重中

通过两个小的低秩矩阵来近似的表示原始矩阵；

```txt
前向传播 =>
x -> 原始矩阵
  -> 两个低秩矩阵
=> 融合在一起
反向传播 =>
仅更新两个低秩矩阵
=>
最后将其融合进原始矩阵
```

## QLoRA 微调

量化之后的 LoRA

量化与反量化

# 微调框架

## LLamaFactory

https://llamafactory.readthedocs.io/zh-cn/latest/index.html

```shell
git clone --depth 1 https://github.com/hiyouga/LLaMA-Factory.git
cd LLaMA-Factory
pip install -e .
```

支持的数据类型：Alpaca 和 ShareGPT

```txt
# 单轮
{
  "instruction": "计算这些物品的总费用。 ",	# 人类指令
  "input": "输入：汽车 - $3000，衣服 - $100，书 - $20。",	# 人类输入，可选
  "output": "汽车、衣服和书的总费用为 $3000 + $100 + $20 = $3120。"	# 模型回答
},
```

```txt
# 多轮
[
  {
    "instruction": "人类指令（必填）",
    "input": "人类输入（选填）",
    "output": "模型回答（必填）",
    "system": "系统提示词（选填）",
    "history": [
      ["第一轮指令（选填）", "第一轮回答（选填）"],
      ["第二轮指令（选填）", "第二轮回答（选填）"]
    ]
  }
]
```

### 使用 WebUI 微调

```shell
# webui
llamafactory-cli webui
```

计算类型，混合精度计算

批处理大小越大越好（显卡允许的情况下）

梯度累积（降低更新的次数，每次梯度更新需要反向传播，很慢，一般通过梯度累积再进行梯度更新）

测试 chat

量化

QLoRA 秩32/64（经验） 缩放系数为秩的2倍 a b矩阵的中间维度

测试 chat

导出 export

导出量化 校准数据集

### 使用配置文件微调

复制模版并修改（框架内置微调模版）

```shell
cp examples/train_lora/llama3_lora_sft.yaml configs/qwen2_lora.yaml
```

修改配置文件中的各个参数

启动训练

```shell
llamafactory-cli train configs/qwen2_lora.yaml
```

### 命令行直接指定参数微调

...

### DeepSpeed 分布式训练

分布式训练优化框架

ZeRO（Zero Redundancy Optimizer）

原理：通过分片优化器状态、梯度、参数，消除数据并行中的显存冗余。

阶段划分：

- ZeRO-1：优化器状态分片。
- ZeRO-2：梯度分片 + 优化器状态分片。（一般用来加速训练）
- ZeRO-3：参数分片 + 梯度分片 + 优化器状态分片。（一般解决显存不足的情况）

- 梯度检查点（Activation Checkpointing）：用时间换空间，减少激活值显存占用。
- CPU Offloading：将优化器状态和梯度卸载到CPU内存。
- 混合精度训练：FP16/BP16与动态损失缩放（Loss Scaling）。

## Ollama 部署微调大模型


## PS

对话模版，用于指定角色、消息和其他特定于聊天的 token 如何在输入中编码，会影响模型对问题的理解与回复（但是影响不是非常大，毕竟只是一个模版，主要还是与模型本身能力有关）。

由于各模型、各框架的对话模版不同，导致其在微调训练、部署推理时模型效果会有所差异，所以需要统一对话模版。

将框架的对话模版转换为模型原有的对话模版，或将模型原有对话模版转换为框架的对话模版。

分布式微调：
- 数据并行：将数据划分为多个批次，分发到不同设备，每个设备拥有完整的模型脚本。
- 模型并行：将模型切分到不同设备（eg：按层或张量分片）
	- 横向并行（层拆分）
	- 纵向并行（张量拆分）
- 流水线并行（简单理解就是数据并行和模型并行结合）
- 混合并行（结合上面三种）

