---
title: "RAG及优化策略&LangChain本地知识库"
date: 2025-07-11
tags:
  - Others
categories:
  - Others
---
## RAG（Retrieval-Augmented Generation）

- 检索增强生成，结合信息检索（Retrieval）和文本生成（Generation）。
- 通过实时检索相关文档或信息，并将其作为上下文输入到生成模型中，从而提高生成结果的时效性和准确性。

- 主要作用：提高实时性、减少幻觉、提升专业领域回答质量、可溯源

![[attachments/2.png]]

### 主要流程

![[attachments/3.jpg]]

1. 数据预处理，构建索引库
	- 知识库构建：收集并整理文档、网页、数据库等
	- 文档分块：将文档切分为适当大小的片段（chunks），方便后续检索。分块策略需要再语义完整性与检索效率之间取得平衡。
	- 向量化处理：使用嵌入模型将文本块转换为向量，并存储在向量数据库中。
2. 检索阶段
	- 查询处理：将用户输入的问题转换为向量，并在向量数据库中进行相似度检索，找到最相关的文本片段。
	- 重排序：对检索结果进行相关性排序，选择最相关的片段作为生成阶段的输入。
3. 生成阶段
	- 上下文组装：将检索到的文本片段与用户问题结合，形成增强的上下文。
	- 生成回答：大模型基于增强上下文生成最终回答。

> RAG 本质即重构一个新的 Prompt。

### NativeRAG

![[attachments/4.png]]

NativeRAG 基本步骤

- Indexing 索引：通过文档加载、切片、向量化及存储，将知识库进行转化和存储。
- Retrieval 检索：在大量知识中，找到小部分有用的信息，给模型进行参考。
- Generation 生成：结合用户提问和检索到的知识，让模型生成有用的答案。

> https://www.promptingguide.ai/research/rag

## LangChain 搭建本地知识库检索基本流程

- 文档加载，并按一定条件切割成片段。
- 将切割的文本片段灌入检索引擎。
- 封装检索接口。
- 构建调用流程：Query -> 检索 -> Prompt -> LLM -> 回复。

### 基本模块导入

```python
import os  
import logging  
import pickle  
from PyPDF2 import PdfReader  

from langchain.chains.question_answering import load_qa_chain  # 加载QA问答链，用于结合文档回答问题  
from langchain_openai import OpenAI, ChatOpenAI  # 使用OpenAI提供的模型进行问答处理  
from langchain_openai import OpenAIEmbeddings  # OpenAI的嵌入模型  
from langchain_community.embeddings import DashScopeEmbeddings  # 阿里云DashScope平台的嵌入模型  
from langchain_community.callbacks.manager import get_openai_callback  # 跟踪API调用成本  
from langchain.text_splitter import RecursiveCharacterTextSplitter  # 文本分割  
from langchain_community.vectorstores import FAISS  # 向量数据库  

from typing import List, Tuple  # 类型提示  
```

### 基本函数实现

#### pdf 文档处理获取文本

```python
 def extract_text_with_page_numbers(pdf) -> Tuple[str, List[int]]:  
    """  
    从PDF中提取文本并记录每行文本对应的页码  
  
    参数:  
        pdf: PDF文件对象  
  
    返回:  
        text: 提取的文本内容  
        page_numbers: 每行文本对应的页码列表  
    """    
    text = ""  # 合并后的文本  
    page_numbers = []  # 每行文本对应的页码列表  
  
    # 遍历PDF中的每一页  
    for page_number, page in enumerate(pdf.pages, start=1):  
        extracted_text = page.extract_text()  
        if extracted_text:  
            text += extracted_text  
            page_numbers.extend([page_number] * len(extracted_text.split("\n")))  
        else:  
            logging.warning(f"No text found on page {page_number}.")  
  
    return text, page_numbers  
```

#### 文本转换至向量数据库

```python
# 全局变量存储chunk_page_info
chunk_page_info_global = None

def process_text_with_splitter(text: str, page_numbers: List[int], save_path: str = None) -> FAISS:  
    """  
    处理文本并创建向量存储，并正确映射每个chunk的页码  
  
    参数:  
        text: 提取的文本内容  
        page_numbers: 每行文本对应的页码列表  
        save_path: 可选，保存向量数据库的路径  
  
    返回:  
        knowledgeBase: 基于FAISS的向量存储对象  
    """    
    # 创建文本分割器，用于将长文本分割成小块  
    text_splitter = RecursiveCharacterTextSplitter(  
        separators=["\n\n", "\n", ".", " ", ""],  
        chunk_size=512,  
        chunk_overlap=128,  
        length_function=len,  
        add_start_index=True,  # 启用返回起始索引  
    )  
  
    # 分割文本，并获取每个chunk的起始索引  
    split_result = text_splitter.create_documents([text])  # 分割后的结果（带有每个chunk的起始索引）
    chunks = [doc.page_content for doc in split_result]  # 所有chunk
    chunk_start_idxs = [doc.metadata.get('start_index', 0) for doc in split_result]  # 每个chunk的起始索引列表
  
    print(f"文本被分割成 {len(chunks)} 个块。")  

	# 创建嵌入模型，OpenAI嵌入模型，配置环境变量 OPENAI_API_KEY# embeddings = OpenAIEmbeddings()  
  
	# 调用阿里百炼平台文本嵌入模型，配置环境变量 DASHSCOPE_API_KEY
    # 嵌入模型  
    embeddings = DashScopeEmbeddings(  
        model="text-embedding-v2"  
    )  
    knowledgeBase = FAISS.from_texts(chunks, embeddings)  
    print("已从文本块创建知识库...")  
  
    # 计算每个字符对应的页码（按行分配）  
    char_page_map = []  
    text_lines = text.split("\n")  
    char_idx = 0  
    for line, page in zip(text_lines, page_numbers):  
        char_page_map.extend([page] * len(line))  
        char_idx += len(line)  
        # 补充换行符的页码  
        char_page_map.append(page)  
        char_idx += 1  
    # 保证char_page_map长度与text长度一致  
    char_page_map = char_page_map[:len(text)]  
  
    # 统计每个chunk的主来源页码  
    chunk_page_info = {}  
    for chunk, start_idx in zip(chunks, chunk_start_idxs):  
        end_idx = start_idx + len(chunk)  
        # 获取chunk对应的页码区间  
        chunk_pages = char_page_map[start_idx:end_idx]  
        if chunk_pages:  
            # 统计出现最多的页码  
            main_page = max(set(chunk_pages), key=chunk_pages.count)  
        else:  
            main_page = "未知"  
        chunk_page_info[chunk] = main_page  
  
    global chunk_page_info_global  
    chunk_page_info_global = chunk_page_info  
  
    # 如果提供了保存路径，则保存向量数据库和页码信息  
    if save_path:  
        os.makedirs(save_path, exist_ok=True)  
        knowledgeBase.save_local(save_path)  
        print(f"向量数据库已保存到: {save_path}")  
        with open(os.path.join(save_path, "page_info.pkl"), "wb") as f:  
            pickle.dump(chunk_page_info, f)  
        print(f"页码信息已保存到: {os.path.join(save_path, 'page_info.pkl')}")  
  
    return knowledgeBase
```

#### 加载向量数据库中的内容

```python
def load_knowledge_base(load_path: str, embeddings=None) -> FAISS:  
    """  
    从磁盘加载向量数据库和页码信息  
  
    参数:  
        load_path: 向量数据库的保存路径  
        embeddings: 可选，嵌入模型。如果为None，将创建一个新的DashScopeEmbeddings实例  
  
    返回:  
        knowledgeBase: 加载的FAISS向量数据库对象  
    """    
    # 如果没有提供嵌入模型，则创建一个新的  
    if embeddings is None:  
        embeddings = DashScopeEmbeddings(  
            model="text-embedding-v2"  
        )  
  
    # 加载FAISS向量数据库，添加allow_dangerous_deserialization=True参数以允许反序列化  
    knowledgeBase = FAISS.load_local(load_path, embeddings, allow_dangerous_deserialization=True)  
    print(f"向量数据库已从 {load_path} 加载。")  
  
    # 加载页码信息  
    page_info_path = os.path.join(load_path, "page_info.pkl")  
    global chunk_page_info_global  
    if os.path.exists(page_info_path):  
        with open(page_info_path, "rb") as f:  
            chunk_page_info = pickle.load(f)  
        chunk_page_info_global = chunk_page_info  # 动态属性  
        print("页码信息已加载。")  
    else:  
        print("警告: 未找到页码信息文件。")  
  
    return knowledgeBase
```

### 基本流程实现

1. PDF文本提取与处理
	- PyPDF2 库的 PdfReader 从 PDF 文件中提取文本在提取过程中记录每行文本对应的页码，便于后续溯源。
	- RecursiveCharacterTextSplitter 将长文本分割成小块，便于向量化处理
2. 向量数据库构建
	- OpenAIEmbeddings / DashScopeEmbeddings 将文本块转换为向量表示
	- FAISS 向量数据库存储文本向量，支持高效的相似度搜索为每个文本块保存对应的页码信息，实现查询结果溯源
3. 语义搜索与问答链
	- 基于用户查询，similarity_search 在向量数据库中检索相关文本块
	- 文本语言模型和 load_qa_chain 构建问答链将检索到的文档和用户问题作为输入，生成回答
4. 成本跟踪与结果展示
	- get_openai_callback 跟踪 API 调用成本
	- 展示问答结果和来源页码，方便用户验证信息

```python
# 读取PDF文件  
pdf_reader = PdfReader('./浦发上海浦东发展银行西安分行个金客户经理考核办法.pdf')  
# 提取文本和页码信息  
text, page_numbers = extract_text_with_page_numbers(pdf_reader)  
# print(text)  
  
print(f"提取的文本长度: {len(text)} 个字符。")  
  
# 处理文本并创建知识库，同时保存到磁盘  
save_dir = "./vector_db"  
knowledgeBase = process_text_with_splitter(text, page_numbers, save_path=save_dir)  
# print(knowledgeBase)  
  
# 处理文本并创建知识库  
# knowledgeBase = process_text_with_splitter(text, page_numbers)  
  
# 设置查询问题  
# query = "客户经理被投诉了，投诉一次扣多少分"  
query = "客户经理每年评聘申报时间是怎样的？"  
if query:  
    # 执行相似度搜索，找到与查询相关的文档  
    docs = knowledgeBase.similarity_search(query) 
    # 合理使用 Top-k 选择召回数量 
    # docs = knowledgeBase.similarity_search(query, k=10)
  
    # 初始化对话大模型  
    chatLLM = ChatOpenAI(  
        # 若没有配置环境变量，请用百炼API Key将下行替换为：api_key="sk-xxx",  
        api_key=os.getenv("DASHSCOPE_API_KEY"),  
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  
        model="deepseek-v3"  
    )  
  
    # 加载问答链  
    chain = load_qa_chain(chatLLM, chain_type="stuff")  
  
    # 准备输入数据  
    input_data = {"input_documents": docs, "question": query}  
  
    # 使用回调函数跟踪API调用成本  
    with get_openai_callback() as cost:  
        # 执行问答链  
        response = chain.invoke(input=input_data)  
        print(f"查询已处理。成本: {cost}")  
        print(response["output_text"])  
        print("来源:")  
  
    # 记录唯一的页码  
    unique_pages = set()  
  
    # 显示每个文档块的来源页码  
    for doc in docs:  
	    text_content = getattr(doc, "page_content", "")  
	    source_page = chunk_page_info_global.get(  
	        text_content.strip(), "未知"  
	    ) if chunk_page_info_global else "未知"
  
        if source_page not in unique_pages:  
            unique_pages.add(source_page)  
            print(f"文本块页码: {source_page}")
```

使用大模型根据本地已构建好的向量数据库来获取答案：

（和上方基本流程处的下半部分基本相同）

```python
from langchain_community.llms import Tongyi  
  
# 设置查询问题  
# query = "客户经理被投诉了，投诉一次扣多少分？"  
query = "客户经理每年评聘申报时间是怎样的？"  
if query:  
    # 示例：如何加载已保存的向量数据库  
    # 注释掉以下代码以避免在当前运行中重复加载  
    # 创建嵌入模型  
    embeddings = DashScopeEmbeddings(  
        model="text-embedding-v2"  
    )  
    # 从磁盘加载向量数据库  
    loaded_knowledgeBase = load_knowledge_base("./vector_db", embeddings)  
    # 使用加载的知识库进行查询  
    docs = loaded_knowledgeBase.similarity_search(query)  
  
    # 初始化对话大模型  
    DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY"),  
    llm = Tongyi(model_name="deepseek-v3", dashscope_api_key=DASHSCOPE_API_KEY)  
  
    # 加载问答链  
    chain = load_qa_chain(llm, chain_type="stuff")  
  
    # 准备输入数据  
    input_data = {"input_documents": docs, "question": query}  
  
    # 使用回调函数跟踪API调用成本  
    with get_openai_callback() as cost:  
        # 执行问答链  
        response = chain.invoke(input=input_data)  
        print(f"查询已处理。成本: {cost}")  
        print(response["output_text"])  
        print("来源:")  
  
    # 记录唯一的页码  
    unique_pages = set()  
  
    # 显示每个文档块的来源页码  
    for doc in docs:  
	    text_content = getattr(doc, "page_content", "")  
	    source_page = chunk_page_info_global.get(  
	        text_content.strip(), "未知"  
	    ) if chunk_page_info_global else "未知"
  
        if source_page not in unique_pages:  
            unique_pages.add(source_page)  
            print(f"文本块页码: {source_page}")
```

## RAG 优化

### 数据准备

提升数据质量

- 构建完整数据准备流程
	1. 数据评估与分类
		- 数据审计：审查其敏感性、实时性、矛盾及不准确性
		- 数据分类：按类型、来源、敏感性、重要性等进行分类
	2. 数据清洗
		- 去重、纠错、更新、一致性检测
	3. 敏感信息处理
		- 敏感数据识别（工具/正则），脱敏或加密
	4. 数据标记与标注
		- 元数据标记：为数据添加元数据，如来源、创建时间等
		- 内容标注：非结构化数据进行标注
	5. 数据治理框架
		- 制定政策：明确数据管理、访问控制和更新流程
		- 责任分配：制定数据治理负责人，确保政策执行
		- 监控与审计：定期监控数据质量，进行审计

- 采用智能文档技术处理
	- 阿里文档智能/微软 LayoutLMv3

> eg：阿里，多粒度知识提取，按不同级别拆分文档，对各粒度 chunk 进行知识提取，去重降噪。

### 知识检索

- 查询转换用户澄清意图（避免意图识别不明确）

	1. NLP 用户意图识别
	2. 查询扩展

eg：如何申请信用卡？

查询扩展 =》

> - 申请信用卡具体步骤？
> - 申请信用卡所需材料？
> - 申请信用卡的资格条件？

#### 高效召回

##### 改进检索算法

利用知识图谱中的语义信息和实体关系，增强对查询和文档的理解，提升召回的相关性

##### 引入重排序（Reranking）

（避免返回大量无关/有关信息利用率低的情况）

重排模型：BGE-Rerank、Cohere Rerank

混合检索：结合向量检索、关键词检索（提取关键词）和语义检索（语义相似性）

##### 优化查询扩展

使用大模型将用户查询改写为多个语义相似的查询，提升召回多样性。

多查询召回 MultiQueryRetriever

```python
from langchain.retrievers import MultiQueryRetriever  
from langchain_community.vectorstores import FAISS  
from langchain_community.embeddings import DashScopeEmbeddings  
  
# 初始化大语言模型（用于查询改写）  
#llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)  
from langchain_community.llms import Tongyi  
DASHSCOPE_API_KEY = 'sk-165156465456d1fa23d1f56asadf213'  
llm = Tongyi(model_name="deepseek-v3", dashscope_api_key=DASHSCOPE_API_KEY) # qwen-turbo  
  
# 创建嵌入模型  
embeddings = DashScopeEmbeddings(  
    model="text-embedding-v1",  
    dashscope_api_key=DASHSCOPE_API_KEY,  
)  
  
# 加载向量数据库，添加allow_dangerous_deserialization=True参数以允许反序列化  
vectorstore = FAISS.load_local("./faiss-1", embeddings, allow_dangerous_deserialization=True)  
  
# 创建MultiQueryRetriever  
retriever = MultiQueryRetriever.from_llm(  
    retriever=vectorstore.as_retriever(),  
    llm=llm  
)  
  
# 示例查询  
query = "客户经理的考核标准是什么？"  
# 执行查询  
results = retriever.invoke(query)  
# results = retriever.get_relevant_documents(query)
  
# 打印结果  
print(f"查询: {query}")  
print(f"找到 {len(results)} 个相关文档:")  
for i, doc in enumerate(results):  
    print(f"\n文档 {i+1}:")  
    print(doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content)
```

##### 双向改写

查询改写成文档（Query2Doc）

文档生成多个可能的查询（Doc2Query）

##### 索引扩展

- 离散索引扩展：关键词抽取、实体识别等生成离散索引，与向量检索互补。
- 连续索引扩展：结合多种向量模型进行多路召回。
- 混合索引召回

##### Small-to-Big

> 特别适用处理长文档或多文档场景。通过小规模内容（eg：摘要、关键句或段落）建立索引，链接到大规模主体中。快速定位相关的小规模内容，并通过链接获取更详细的上下文信息，从而提高检索效率和答案逻辑连贯性。

1. 小规模内容检索
2. 链接到大规模内容
3. 上下文补充：将链接到的大规模内容作为 RAG 系统的上下文输入，结合用户查询和小规模内容，生成更准确连贯的答案。

> eg：哈啰，多路召回。

### 答案生成

- 改进提示词模版

检索到的上下文未提取（存在噪声或相互冲突），生成信息不完整

可原始提示词优化：DeepSeek-R1 或 QWQ 推理链来优化（使其更具体、更符合需求）

- 实施动态防护栏（幻觉）

> 动态防护栏（Dynamic Guardrails）一种在生成式 AI 系统中用于实时监控和调整模型输出的机制，确保生成的内容符合预期、准确且安全。它通过设置规则、约束和反馈机制，动态地干预模型的生成过程，避免生成错误、不完整、不符合格式要求或含有虚假信息（幻觉）的内容。

示例：

动态防护栏规则：

a）检查生成的答案是否包含“步骤”和“材料”。如果缺失，提示模型重新生成。
b）检查生成的答案是否列出所有信用卡的年费。如果缺失，提示模型补充。

> eg：中国移动，FoRAG 两阶段生成策略，先生成大纲，再基于大纲扩展生成。

