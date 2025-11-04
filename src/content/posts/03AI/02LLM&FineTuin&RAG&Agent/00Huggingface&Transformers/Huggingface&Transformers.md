---
title: "Huggingface&Transformers"
date: 2025-04-14
tags:
  - Others
categories:
  - Others
---
## piplines

`pipeline()`函数，transformers 中的一个高级 API ，主要用于快速加载预训练模型并执行常见任务（如文本分类、翻译、问答等）。封装了预训练模型和对应的前处理和后处理环节。

常用的 pipelines ：

- `feature-extraction` （获得文本的向量化表示）
- `fill-mask` （填充被遮盖的词、片段）
- `ner`（命名实体识别）
- `question-answering` （自动问答）
- `sentiment-analysis` （情感分析）
- `summarization` （自动摘要）
- `text-generation` （文本生成）
- `translation` （机器翻译）
- `zero-shot-classification` （零训练样本分类）

示例：

```python
# 情感分析
from transformers import pipline

classifier = pipline("sentiment-analysis")
result = classifier("I've been waiting for a HuggingFace course my whole life.")
print(result)

results = classifier(
  ["I've been waiting for a HuggingFace course my whole life.", "I hate this so much!"]
)
print(results)
```

```txt
No model was supplied, defaulted to distilbert-base-uncased-finetuned-sst-2-english (https://huggingface.co/distilbert-base-uncased-finetuned-sst-2-english)

[{'label': 'POSITIVE', 'score': 0.9598048329353333}]
[{'label': 'POSITIVE', 'score': 0.9598048329353333}, {'label': 'NEGATIVE', 'score': 0.9994558691978455}]
```

pipeline 会自动选择合适的预训练模型来完成任务；

- pipeline 自动完成以下步骤：
	1. 预处理（preprocessing），将原始文本转换为模型可以理解的输入格式；
	2. 将预处理好的文本送入模型；
	3. 对模型的预测值进行后处理（postprocessing），输出人类可以理解的格式；

![[attachments/20250505.png]]

> - 预处理：
> 	1. 将输入切分为词语、字词或符号，即 tokens；
> 	2. 根据模型的词表将每个 token 映射到对应的 token 编号；
> 	3. 根据模型需要，添加额外输入；

对于输入文本的预处理需要与模型自身预处理操作完全一致，这样模型才能正常工作；每个模型都有特定的预处理操作，通过 [Model Hub](https://huggingface.co/models) 查询；这里使用 `AutoTokenizer` 类和它的 `from_pretrained()` 函数，它可以自动根据模型 checkpoint 名称来获取对应的分词器；

示例：这里以默认的情感分析模型为例；

```python
'''使用分词进行预处理'''

from transformers import AutoTokenizer, AutoModel

checkpoint = "distilbert-base-uncased-finetuned-sst-2-english"	# 加载的模型
tokenizer = AutoTokenizer.from_pretrained(checkpoint)

raw_inputs = [
    "I've been waiting for a HuggingFace course my whole life.",
    "I hate this so much!",
]
inputs = tokenizer(raw_inputs, padding=True, truncation=True, return_tensors="pt")

print(inputs)							# 预处理token化的内容

'''将预处理好的输入送入模型'''

model = AutoModel.from_pretrained(checkpoint)
outputs = model(**inputs)

print(outputs.last_hidden_state.shape)	# 隐藏层最后一层的维度（模型主干网络的原始输出，尚未针对任何任务进行适配，需进一步处理）

===

from transformers import AutoModelForSequenceClassification	# 情感分析用的是该类

model = AutoModelForSequenceClassification.from_pretrained(checkpoint)
outputs = model(**inputs)
print(outputs.logits.shape)		# 模型最终输出的维度（在logits状态，未进行最终的处理）将last_hidden_state通过任务特定的输出头（如分类头）后的原始分数
print(outputs.logits)			# logits值，需通过Softmax转换为概率值

'''对模型输出进行后处理'''
import torch
predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
print(predictions)				# 最终的预测概率值
print(model.config.id2label)	# 最终对应的标签
```

```python
{
    'input_ids': tensor([	# 对应分词之后的tokens映射到的数字编号列表
        [  101,  1045,  1005,  2310,  2042,  3403,  2005,  1037, 17662, 12172, 2607,  2026,  2878,  2166,  1012,   102],
        [  101,  1045,  5223,  2023,  2061,  2172,   999,   102,     0,     0,
             0,     0,     0,     0,     0,     0]
    ]), 
    'attention_mask': tensor([	# 标记哪些是被填充的
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]
    ])
}

'''
Transformer 模块输出是一个三维张量 
(Batch size 输入样本数量，每次输入多少句子
Sequence length 文本序列长度，每个句子被分为多少个token
Hidden size 每个token经过编码后的输出向量的维度)
'''
torch.Size([2, 16, 768])

# 这里对于 batch 中的每一个样本，模型都会输出一个两维的向量（每一维对应一个标签，positive 或 negative）
torch.Size([2, 2])

tensor([[-1.5607,  1.6123],
        [ 4.1692, -3.3464]], 
        grad_fn=<AddmmBackward0>)

tensor([[4.0195e-02, 9.5980e-01],		# [0.0402, 0.9598]
        [9.9946e-01, 5.4418e-04]], 		# [0.9995, 0.0005]
        grad_fn=<SoftmaxBackward0>)

{0: 'NEGATIVE', 1: 'POSITIVE'}
```

> 预训练模型的本体只包含基础的 Transformer 模块，对于给定的输入，它会输出一些神经元的值，称为 hidden states 或者特征 (features)。对于 NLP 模型来说，可以理解为是文本的高维语义表示。这些 hidden states 通常会被输入到其他的模型部分（称为 head），以完成特定的任务，例如送入到分类头中完成文本分类任务。
>
> ![[attachments/20250505-1.png]]
>
> 所有 pipelines 都具有类似的模型结构，只是模型的最后一部分会使用不同的 head 以完成对应的任务。
>
> Transformers 库封装了很多不同的结构，常见的有：
>
> - `*Model` （返回 hidden states）
> - `*ForCausalLM` （用于条件语言模型）
> - `*ForMaskedLM` （用于遮盖语言模型）
> - `*ForMultipleChoice` （用于多选任务）
> - `*ForQuestionAnswering` （用于自动问答任务）
> - `*ForSequenceClassification` （用于文本分类任务）
> - `*ForTokenClassification` （用于 token 分类任务，例如 NER）

> 学习参考示例：(https://transformers.run/c2/2021-12-08-transformers-note-1/)

## 模型（Model）&分词器（Tokenizer）

### 模型（Model）

```python
from transformers import AutoModel

'''加载模型（可以是本地预先下载的模型路径）'''	# 以当前代码块下方第13行为准，（这部分可能存在问题）
model = AutoModel.from_pretrained("./models/bert/")	# 默认会保存在_~/.cache/huggingface/transformers

'''保存模型'''
model = AutoModel.from_pretrained("bert-base-cased")
model.save_pretrained("./models/bert-base-cased/")
# 会在保存路径创建两个文件
# config.json 模型配置文件，记录模型结构
# pytorch_model.bin	模型权重，记录模型参数

# 下载并加载模型的两种方式（tokenizer也一样）
# model = AutoModel.from_pretrained(model_dir)	# 已经下载好模型在指定的model_dir目录，这里的model_dir需要设置具体包含config.json的目录（这才是所能应用模型的目录），只支持绝对路径
# model = AutoModel.from_pretrained("model_name", cache_dir=model_dir)	# 这样会搜索给定的model_dir目录，若存在模型则不再下载，否则会下载至给定的目录下

# cache_dir参数应该是直接修改的缓存目录，而save_pretrained是将缓存的复制到给出的目录
```

> HuggingFace 上的模型，通常只需要下载对应的 config.json 和 pytorch_model.bin，以及分词器对应的 tokenizer.json、tokenizer_config.json 和 vocab.txt。（具体模型可能存在一丢丢的不同）

> - model.safetensors / pytorch_model.bin 等，模型文件
> - config.json 模型配置文件
> 	- vocab_size 字典数量（可识别文字符数）
> - special_tokens_map.json 特殊字符
> - tokenizer.json 字符及编码
> - tokenizer_config.json 字典相关配置
> - vocab.txt 字典（可识别字符）

### 分词器（Tokenizer）

- 按词切分（Word-based）
- 按字符切分（Character-based）
- 按子词切分（Subword）（“tokenization” 被切分为了 “token” 和 “ization”）

```python
'''分词器的加载与保存'''
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("bert-base-cased")
tokenizer.save_pretrained("./models/bert-base-cased/")
# special_tokens_map.json：映射文件，unknown token 等特殊字符的映射关系
# tokenizer_config.json：分词器配置文件，存储构建分词器需要的参数
# vocab.txt：词表，一行一个 token，行号就是对应的 token ID（从 0 开始）
```

文本编码过程：1. 分词 2. 映射：将 tokens 转化为对应的 token IDs；

以 BERT 默认的子词分词策略为例：

```python
'''文本编码'''
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("bert-base-cased")

sequence = "Using a Transformer network is simple"
tokens = tokenizer.tokenize(sequence)	# 分词
print(tokens)

ids = tokenizer.convert_tokens_to_ids(tokens)	# token IDs化
print(ids)

# encode() 将两步合并，会自动添加特殊token，eg：首尾[CLS]和[SEP]

sequence_ids = tokenizer.encode(sequence)
print(sequence_ids)

'''实际应用时'''
tokenized_text = tokenizer("Using a Transformer network is simple")
print(tokenized_text)

'''文本解码'''
decoded_string = tokenizer.decode([101, 7993, 170, 13809, 23763, 2443, 1110, 3014, 102])
print(decoded_string)
```

```python
['using', 'a', 'transform', '##er', 'network', 'is', 'simple']

[7993, 170, 13809, 23763, 2443, 1110, 3014]

[101, 7993, 170, 13809, 23763, 2443, 1110, 3014, 102]

{'input_ids': [101, 7993, 170, 13809, 23763, 2443, 1110, 3014, 102], 
 'token_type_ids': [0, 0, 0, 0, 0, 0, 0, 0, 0], 
 'attention_mask': [1, 1, 1, 1, 1, 1, 1, 1, 1]}

[CLS] Using a Transformer network is simple [SEP]
```

### 处理多段文本

示例：

```python
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

checkpoint = "distilbert-base-uncased-finetuned-sst-2-english"
tokenizer = AutoTokenizer.from_pretrained(checkpoint)
model = AutoModelForSequenceClassification.from_pretrained(checkpoint)

sequence = "I've been waiting for a HuggingFace course my whole life."

tokens = tokenizer.tokenize(sequence)
ids = tokenizer.convert_tokens_to_ids(tokens)
# input_ids = torch.tensor(ids), This line will fail.
input_ids = torch.tensor([ids])
print("Input IDs:\n", input_ids)

output = model(input_ids)
print("Logits:\n", output.logits)

'''实际场景，直接用tokenizer'''
tokenized_inputs = tokenizer(sequence, return_tensors="pt")
print("Inputs Keys:\n", tokenized_inputs.keys())
print("\nInput IDs:\n", tokenized_inputs["input_ids"])

output = model(**tokenized_inputs)
print("\nLogits:\n", output.logits)
```

```python
Input IDs: 
tensor([[ 1045,  1005,  2310,  2042,  3403,  2005,  1037, 17662, 12172,  2607,
          2026,  2878,  2166,  1012]])
Logits: 
tensor([[-2.7276,  2.8789]], grad_fn=<AddmmBackward0>)


Inputs Keys:
dict_keys(['input_ids', 'attention_mask'])

Input IDs:
tensor([[  101,  1045,  1005,  2310,  2042,  3403,  2005,  1037, 17662, 12172,
          2607,  2026,  2878,  2166,  1012,   102]])

Logits:
tensor([[-1.5607,  1.6123]], grad_fn=<AddmmBackward0>)
```

模型只接受批（batch）数据作为输入；由于通常 batch 中的文本有长有短，因此需要对其部分序列进行填充；

Padding 填充操作；Attention Mask 告诉模型哪部分内容是由自己填充的，从而不需要模型一同编码进去；

（若不设置 attention mask 模型会将其填充的部分作为原序列一起编码）不过实际应用中直接使用 tokenizer 分词器会自动构建 attention mask，截断等操作。

```python
# 前面的模型导入等操作同上~~

# 这里直接用两个列表作为两个原序列的ids
sequence1_ids = [[200, 200, 200]]
sequence2_ids = [[200, 200]]
batched_ids = [
    [200, 200, 200],
    [200, 200, tokenizer.pad_token_id],
]
batched_attention_masks = [
    [1, 1, 1],
    [1, 1, 0],
]

print(model(torch.tensor(sequence1_ids)).logits)
print(model(torch.tensor(sequence2_ids)).logits)
print(model(torch.tensor(batched_ids)).logits)
outputs = model(
    torch.tensor(batched_ids), 
    attention_mask=torch.tensor(batched_attention_masks))
print(outputs.logits)
```

```python
tensor([[ 1.5694, -1.3895]], grad_fn=<AddmmBackward0>)
tensor([[ 0.5803, -0.4125]], grad_fn=<AddmmBackward0>)
tensor([[ 1.5694, -1.3895],
        [ 1.3374, -1.2163]], grad_fn=<AddmmBackward0>)
tensor([[ 1.5694, -1.3895],
        [ 0.5803, -0.4125]], grad_fn=<AddmmBackward0>)
```

由于 Transformer 模型对 token 序列的长度有限制，所以在处理长序列时需要其他的处理：设定最大长度截断输入序列；将长文切片为短文本块（chunk），对每个 chunk 编码；

- `padding="longest"`： 将序列填充到当前 batch 中最长序列的长度；
- `padding="max_length"`：将所有序列填充到模型能够接受的最大长度，例如 BERT 模型就是 512；
- 截断操作，`truncation`参数控制，为`True`时大于模型最大接受长度的序列都会被截断；也可通过`max_length`参数控制截断长度；
- `return_tensors`参数设置指定返回张量格式；

```python
# 前面的模型导入等操作同上~~
sequences = [
"I've been waiting for a HuggingFace course my whole life.", 
"So have I!"
]

tokens = tokenizer(sequences, padding=True, truncation=True, return_tensors="pt")
print(tokens)
output = model(**tokens)
print(output.logits)
```

```python
{'input_ids': tensor([
    [  101,  1045,  1005,  2310,  2042,  3403,  2005,  1037, 17662, 12172,
      2607,  2026,  2878,  2166,  1012,   102],
    [  101,  2061,  2031,  1045,   999,   102,     0,     0,     0,     0,
         0,     0,     0,     0,     0,     0]]), 
 'attention_mask': tensor([
    [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]])}

tensor([[-1.5607,  1.6123],
        [-3.6183,  3.9137]], grad_fn=<AddmmBackward0>)
```

### 编码句子对

```python
from transformers import AutoTokenizer

checkpoint = "bert-base-uncased"	# 注意用到的模型是不一样的
tokenizer = AutoTokenizer.from_pretrained(checkpoint)

inputs = tokenizer("This is the first sentence.", "This is the second one.")
print(inputs)

tokens = tokenizer.convert_ids_to_tokens(inputs["input_ids"])
print(tokens)
```

```python
{'input_ids': [101, 2023, 2003, 1996, 2034, 6251, 1012, 102, 2023, 2003, 1996, 2117, 2028, 1012, 102], 
 'token_type_ids': [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1], 	# 表示token属于哪个句子，第一个句子和特殊符号的位置是0，第二个句子的位置是1，只针对于上下文编码（现在基本已被遗弃了）
 'attention_mask': [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]}

['[CLS]', 'this', 'is', 'the', 'first', 'sentence', '.', '[SEP]', 'this', 'is', 'the', 'second', 'one', '.', '[SEP]']
```

### 添加 Token

- [`add_tokens()`](https://huggingface.co/docs/transformers/v4.25.1/en/internal/tokenization_utils#transformers.SpecialTokensMixin.add_tokens) 添加普通 token：参数是新 token 列表，如果 token 不在词表中，就会被添加到词表的最后；（或设置额外参数添加特殊 token `special_tokens=True`）
- [`add_special_tokens()`](https://huggingface.co/docs/transformers/v4.25.1/en/internal/tokenization_utils#transformers.SpecialTokensMixin.add_special_tokens) 添加特殊 token：参数是包含特殊 token 的字典，键值只能从 `bos_token`, `eos_token`, `unk_token`, `sep_token`, `pad_token`, `cls_token`, `mask_token`, `additional_special_tokens` 中选择。同样地，如果 token 不在词表中，就会被添加到词表的最后。添加后，还可以通过特殊属性来访问这些 token，例如 `tokenizer.cls_token` 就指向 cls token；

```python
'''add_tokens()'''
checkpoint = "bert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(checkpoint)
    
num_added_toks = tokenizer.add_tokens(["new_token1", "my_new-token2"])
num_added_toks = tokenizer.add_tokens(["[NEW_tok3]", "[NEW_tok4]"], special_tokens=True)

# 可预先对新token列表进行过滤
new_tokens = ["new_token1", "my_new-token2"]
new_tokens = set(new_tokens) - set(tokenizer.vocab.keys())
tokenizer.add_tokens(list(new_tokens))

'''add_special_tokens()'''
special_tokens_dict = {"cls_token": "[MY_CLS]"}
    
num_added_toks = tokenizer.add_special_tokens(special_tokens_dict)
```

添加 token 后需要重置 embedding 矩阵的大小，将 token 映射到对应的 embedding 。通过 `resize_token_embeddings()` 函数实现；（新提那家 token 的 embedding 时随机初始化的）

```python
# 示例：添加两个特殊token
num_added_toks = tokenizer.add_tokens(['[ENT_START]', '[ENT_END]'], special_tokens=True)
'''随机重置embedding'''
model.resize_token_embeddings(len(tokenizer))

'''实际场景（使用已有token的embedding初始化新添加的token）'''
# 将上面两个都初始化为"entity" toekn对应的embedding
import torch

token_id = tokenizer.convert_tokens_to_ids('entity')
token_embedding = model.embeddings.word_embeddings.weight[token_id]
print(token_id)

with torch.no_grad():	# 初始化embedding过程不可导
    for i in range(1, num_added_toks+1):
        model.embeddings.word_embeddings.weight[-i:, :] = token_embedding.clone().detach().requires_grad_(True)
print(model.embeddings.word_embeddings.weight[-2:, :])
```

根据新添加 token 的语义进行初始化。eg：将值初始化为 token 语义描述中所有 token 的平均值。

```python
# 分别为 [ENT_START] 和 [ENT_END] 编写对应的描述，然后再对它们的值进行初始化
descriptions = ['start of entity', 'end of entity']

with torch.no_grad():
    for i, token in enumerate(reversed(descriptions), start=1):
        tokenized = tokenizer.tokenize(token)
        print(tokenized)
        tokenized_ids = tokenizer.convert_tokens_to_ids(tokenized)
        new_embedding = model.embeddings.word_embeddings.weight[tokenized_ids].mean(axis=0)
        model.embeddings.word_embeddings.weight[-i, :] = new_embedding.clone().detach().requires_grad_(True)
print(model.embeddings.word_embeddings.weight[-2:, :])
```

```python
['end', 'of', 'entity']
['start', 'of', 'entity']
tensor([[-0.0340, -0.0144, -0.0441,  ..., -0.0016,  0.0318, -0.0151],
        [-0.0060, -0.0202, -0.0312,  ..., -0.0084,  0.0193, -0.0296]],
       grad_fn=<SliceBackward0>)
```

## 模型编码

模型是处理字符数据（编码与解码简单的理解）

```python
from transformers import BertTokenizer  
  
# 加载字典和分词器  
token = BertTokenizer.from_pretrained(  
    r"\models\bert-base-chinese\models--bert-base-chinese\snapshots\c30a6ed22ab4564dc1e3b2ecbf6e766b0611a33f")  
# print(token)  
  
  
# 准备要编码的文本数据  
sents = ["白日依山尽，",  
         "价格在这个地段属于适中, 附近有早餐店,小饭店, 比较方便,无早也无所"]  
  
# 批量编码句子  
out = token.batch_encode_plus(  
    batch_text_or_text_pairs=[sents[0], sents[1]],  
    add_special_tokens=True,  
    # 当句子长度大于max_length(上限是model_max_length)时，截断  
    truncation=True,  
    max_length=15,  
    # 一律补0到max_length  
    padding="max_length",  
    # 可取值为tf,pt,np,默认为list  
    return_tensors=None,  
    return_attention_mask=True,  
    return_token_type_ids=True,  
    return_special_tokens_mask=True,  
    # 返回序列长度  
    return_length=True  
)  
# input_ids 就是编码后的词  
# token_type_ids第一个句子和特殊符号的位置是0，第二个句子的位置1（）只针对于上下文编码  
# special_tokens_mask 特殊符号的位置是1，其他位置是0  
# length 编码之后的序列长度  
for k, v in out.items():  
    print(k, ":", v)  
  
# 解码文本数据  
print(token.decode(out["input_ids"][0]), token.decode(out["input_ids"][1]))
```