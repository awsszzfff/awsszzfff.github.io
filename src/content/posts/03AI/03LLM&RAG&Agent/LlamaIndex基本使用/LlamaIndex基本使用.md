---
title: "LlamaIndex基本使用"
date: 2025-08-08
tags:
  - Others
categories:
  - Others
---
LlamaIndex 开发 RAG 的大模型应用框架。

![[attachments/basic_rag.png]]

## LlamaIndex 核心模块

![[attachments/llamaindex.png]]

> 文档 https://docs.llamaindex.ai/en/stable/
> 
> API 接口文档 https://docs.llamaindex.ai/en/stable/api_reference/

## 数据加载与解析（Loading）

`SimpleDirectoryReader` 本地文件加载器。遍历指定目录，并根据文件扩展名自动加载文件（**文本内容**）。

支持的文件类型：`.csv`、`.docx`、`.epub`、`.hwp`、`.ipynb`、`.jpeg`, `.jpg`、`.mbox`、`.md`、`.mp3`, `.mp4`、`.pdf`、`.png`、`.ppt`, `.pptm`, `.pptx`

### 加载本地文件

```python
# 导入LlamaIndex库中的SimpleDirectoryReader类，用于读取目录中的文档
from llama_index.core import SimpleDirectoryReader

# 创建SimpleDirectoryReader实例，配置文档读取参数
reader = SimpleDirectoryReader(
    input_dir=r'./data',        # 指定输入目录为当前目录下的data文件夹
    recursive=False,            # 设置为False，表示不递归读取子目录
    required_exts=['.pdf']      # 指定只读取.pdf扩展名的文件
)

# 使用reader加载数据，返回Document对象列表
documents = reader.load_data()

# 打印第一个文档的文本内容
print(documents[0].text)
```

默认的 PDFReader 效果不是很理想，可更换文件加载器。（LlamaParse， https://cloud.llamaindex.ai/ 需申请 API key，配置 `LLAMA_CLOUD_API_KEY=XXX`）

```python
# 在系统环境变量里配置 LLAMA_CLOUD_API_KEY=XXX

# 导入LlamaParse类，用于解析PDF等文档
from llama_cloud_services import LlamaParse
# 导入SimpleDirectoryReader类，用于读取目录中的文件
from llama_index.core import SimpleDirectoryReader

# 导入nest_asyncio模块，用于在Jupyter环境中处理异步操作
# import nest_asyncio
# 在Jupyter环境中应用nest_asyncio，解决事件循环冲突问题
# nest_asyncio.apply() # 只在Jupyter笔记环境中需要此操作，否则会报错

# 设置解析器，将PDF文档转换为markdown格式
parser = LlamaParse(
    result_type="markdown"  # 指定输出格式为"markdown"，也可选"text"
)

# 创建文件提取器字典，将.pdf扩展名映射到LlamaParse解析器
file_extractor = {".pdf": parser}

# 使用SimpleDirectoryReader读取./data目录中的PDF文件，并使用指定的文件提取器进行解析
documents = SimpleDirectoryReader(
    input_dir="./data",              # 指定输入目录
    required_exts=[".pdf"],          # 只处理PDF文件
    file_extractor=file_extractor    # 使用自定义的文件提取器
).load_data()

print(documents[0].text)
```

### Data Connectors

用于处理更丰富的数据类型，并将其读取为 Document 的形式

```python
# 直接读取网页内容

# 导入LlamaIndex库中的SimpleWebPageReader类，用于读取网页内容
from llama_index.readers.web import SimpleWebPageReader

# 创建SimpleWebPageReader实例并加载网页数据
# html_to_text=True表示将HTML内容转换为纯文本
documents = SimpleWebPageReader(html_to_text=True).load_data(
    ["https://www.baidu.com"]  # 指定要读取的网页URL列表
)

print(documents[0].text)
```

使用 NodeParsers 对有结构的文档做解析

> HTMLNodeParser 解析 HTML 文档，还有 MarkdownNodeParser、JSONNodeParser 等

```python
# 导入HTMLNodeParser类，用于解析HTML文档结构
from llama_index.core.node_parser import HTMLNodeParser
# 导入SimpleWebPageReader类，用于读取网页内容
from llama_index.readers.web import SimpleWebPageReader

# 加载网页数据，html_to_text=False表示保留HTML结构而不是转换为纯文本
documents = SimpleWebPageReader(html_to_text=False).load_data(
    ["https://liaoxuefeng.com/books/python/advanced/iterator/index.html"]
)

# 创建HTMLNodeParser实例，指定只解析<span>标签
# 默认情况下会解析: ["p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "b", "i", "u", "section"]
parser = HTMLNodeParser(tags=["span"])  # 可以自定义解析哪些标签

# 使用parser从documents中提取nodes
nodes = parser.get_nodes_from_documents(documents)

# 遍历所有nodes并打印每个node的文本内容
for node in nodes:
    print(node.text+"\n")

```


> 更多 Data Connectors
> 
> 内置文件加载器 https://llamahub.ai/l/readers/llama-index-readers-file
> 
> 连接三方服务的数据加载器，如数据库 https://docs.llamaindex.ai/en/stable/module_guides/loading/connector/modules/
> 
> 更多加载器 https://llamahub.ai/

## 文本切分

为方便检索，通常将 Document 切分为 Node（chunk）

```python
# 导入LlamaIndex库中的TokenTextSplitter类，用于将文档分割成token块
from llama_index.core.node_parser import TokenTextSplitter

# 创建TokenTextSplitter实例，配置分块参数
node_parser = TokenTextSplitter(
    chunk_size=512,      # 每个文本块的最大token数量为512
    chunk_overlap=200    # 相邻文本块之间的重叠token数量为200
)

# 使用node_parser将documents分割成节点(nodes)
# show_progress=False表示不显示处理进度条
nodes = node_parser.get_nodes_from_documents(
    documents, # 先前获取的内容
    show_progress=False	# 表示不显示处理进度条	
)

print(nodes[0].text)
```

更多的切割方式：

- SentenceSplitter：切割指定长度 chunk 同时尽量保证句子边界不被切断；
- CodeSplitter：根据 AST （编译器的抽象句法树）切分代码，保证代码功能片段完整；
- SemanticSplitterNodeParser：根据语义相关性对将文本切割；

## 索引与检索

[传统索引](https://en.wikipedia.org/wiki/Search_engine_indexing)、[向量索引](https://medium.com/kx-systems/vector-indexing-a-roadmap-for-vector-databases-65866f07daf5)

向量检索

`VectorStoreIndex` 直接在内存中构建向量存储及索引

```python
# VectorStoreIndex: 用于创建向量存储索引
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
from llama_index.core.node_parser import TokenTextSplitter, SentenceSplitter
from llama_index.embeddings.openai import OpenAIEmbedding

# 加载 PDF 文档
documents = SimpleDirectoryReader(
    "./data", 
    required_exts=[".pdf"],  # 只处理 PDF 文件
).load_data()

# 定义 Node Parser（节点解析器）
# TokenTextSplitter 按 token 数量分割文本
node_parser = TokenTextSplitter(chunk_size=512, chunk_overlap=200)

# 使用 node_parser 将文档切分为节点（nodes）
# 每个节点是一个文本片段，便于后续向量化和检索
nodes = node_parser.get_nodes_from_documents(documents)

# 指定嵌入模型
embed_model = OpenAIEmbedding()  # 使用OpenAI的嵌入模型
# 或者使用本地模型:
# embed_model = HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")


# 构建向量存储索引，默认存储在内存中
# VectorStoreIndex 会自动将 nodes 转换为向量并存储
index = VectorStoreIndex(nodes，embed_model=embed_model)

# 另一种构建索引的方式（被注释掉）
# 直接从文档构建索引，同时指定文本分割方式
# index = VectorStoreIndex.from_documents(documents=documents, transformations=[SentenceSplitter(chunk_size=512)])

# 将索引写入本地文件（被注释掉）
# persist() 方法可以将索引保存到磁盘，避免重复构建
# index.storage_context.persist(persist_dir="./doc_emb")

# 获取检索器
# as_retriever() 创建一个检索器用于查询
# similarity_top_k=2: 每次检索返回最相似的 2 个结果
vector_retriever = index.as_retriever(
    similarity_top_k=2  # 返回2个结果
)

# 执行检索操作
# 使用自然语言查询，检索与"deepseek v3数学能力怎么样？"最相关的文档片段
results = vector_retriever.retrieve("deepseek v3数学能力怎么样？")

# 打印第一个检索结果的文本内容
print(results[0].text)
```

使用指定的向量数据库存储，eg：qdrant

```python
from llama_index.core.indices.vector_store.base import VectorStoreIndex
from llama_index.vector_stores.qdrant import QdrantVectorStore
from llama_index.core import StorageContext

from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance

# 创建一个内存中的Qdrant客户端实例
client = QdrantClient(location=":memory:")
# 定义集合名称
collection_name = "demo"
# 创建一个新的集合，用于存储向量数据
collection = client.create_collection(
    collection_name=collection_name,
    # 设置向量参数：维度大小为1536，距离度量方式为余弦距离
    vectors_config=VectorParams(size=1536, distance=Distance.COSINE)
)

# 创建Qdrant向量存储实例
vector_store = QdrantVectorStore(client=client, collection_name=collection_name)
# 创建存储上下文，关联到刚才创建的向量存储
storage_context = StorageContext.from_defaults(vector_store=vector_store)

# 创建向量索引，使用之前切分好的文档节点和自定义的存储上下文
index = VectorStoreIndex(nodes, storage_context=storage_context)

# 从索引中获取检索器，默认返回最相似的1个结果
vector_retriever = index.as_retriever(similarity_top_k=1)

# 使用检索器查询与"deepseek v3数学能力怎么样"相关的内容
results = vector_retriever.retrieve("deepseek v3数学能力怎么样")

# 打印第一个检索结果的内容
print(results[0])

```

> 更多索引与检索方式
> 
> - 关键字检索
>   - `BM25Retriever`：基于 tokenizer 实现的 BM25 经典检索算法
>   - `KeywordTableGPTRetriever`：使用 GPT 提取检索关键字
>   - `KeywordTableSimpleRetriever`：使用正则表达式提取检索关键字
>   - `KeywordTableRAKERetriever`：使用`RAKE`算法提取检索关键字（有语言限制）
> - RAG-Fusion `QueryFusionRetriever`
> - 还支持 KnowledgeGraph、SQL、Text-to-SQL 等等

检索后处理

LlamaIndex 的 `Node Postprocessors` 提供了一系列检索后处理模块。eg：重排序

```python
# LLMRerank是一个基于大语言模型的重排序后处理器
from llama_index.core.postprocessor import LLMRerank

# 创建LLMRerank实例，设置返回前2个最相关的节点
postprocessor = LLMRerank(top_n=2)

# 使用后处理器对检索到的节点进行重排序，根据查询语句"deepseek v3有多少参数?"来重新评估相关性
# nodes: 之前检索到的节点列表
# query_str: 查询语句，用于重排序时评估节点相关性
nodes = postprocessor.postprocess_nodes(nodes, query_str="deepseek v3有多少参数?")

# 遍历重排序后的节点并打印内容
for i, node in enumerate(nodes):
    # 打印节点索引和文本内容
    print(f"[{i}] {node.text}")
```

## 生成回复

```python
# 单轮问答
qa_engine = index.as_query_engine()
response = qa_engine.query("deepseek v3数学能力怎么样?")
print(response)

# 流式输出
response.print_response_stream()
```

```python
# 多轮问答
chat_engine = index.as_chat_engine()
response = chat_engine.chat("deepseek v3数学能力怎么样?")
response = chat_engine.chat("代码能力呢?")
print(response)

# 流式输出
streaming_response = chat_engine.stream_chat("deepseek v3数学能力怎么样?")
for token in streaming_response.response_gen:
    print(token, end="", flush=True)
```

## 底层接口

### Prompt 模版

```python
# 提示词模版
from llama_index.core import PromptTemplate
prompt = PromptTemplate("写一个关于{topic}的笑话")
prompt.format(topic="小明")	# '写一个关于小明的笑话'
```

```python
# 多轮消息提示词模版
from llama_index.core.llms import ChatMessage, MessageRole
from llama_index.core import ChatPromptTemplate

chat_text_qa_msgs = [
    ChatMessage(
        role=MessageRole.SYSTEM,
        content="你叫{name}，你必须根据用户提供的上下文回答问题。",
    ),
    ChatMessage(
        role=MessageRole.USER, 
        content=(
            "已知上下文：\n" \
            "{context}\n\n" \
            "问题：{question}"
        )
    ),
]
text_qa_template = ChatPromptTemplate(chat_text_qa_msgs)

print(
    text_qa_template.format(
        name="小明",
        context="这是一个测试",
        question="这是什么"
    )
)
```

### 调用 LLM

```python
# 调用LLM
from llama_index.llms.openai import OpenAI
llm = OpenAI(temperature=0, model="gpt-4o")
response = llm.complete(prompt.format(topic="小明"))
print(response.text)

# 可设置全局使用的语言模型
from llama_index.core import Settings
Settings.llm = DeepSeek(model="deepseek-chat", api_key=os.getenv("DEEPSEEK_API_KEY"), temperature=1.5)

# 嵌入模型
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.core import Settings
# 全局设定
Settings.embed_model = OpenAIEmbedding(model="text-embedding-3-small", dimensions=512)
```

> 支持多种语言模型 https://docs.llamaindex.ai/en/stable/module_guides/models/llms/modules/

## 基于 LlamaIndex 实现 RAG

基本功能：

- 加载指定目录的文件
- RAG-Fusion
- 使用 Qdrant 向量数据库，并持久化到本地
- 检索后排序
- 多轮对话

```python
import os
# 导入Qdrant客户端和相关模型配置
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance

# 定义嵌入维度、集合名称和数据库路径常量
EMBEDDING_DIM = 1536  # 向量维度
COLLECTION_NAME = "full_demo"  # Qdrant集合名称
PATH = "./qdrant_db"  # 数据库存储路径

# 创建Qdrant客户端实例，使用本地文件系统存储
client = QdrantClient(path=PATH)

from llama_index.core import VectorStoreIndex, SimpleDirectoryReader, get_response_synthesizer
from llama_index.vector_stores.qdrant import QdrantVectorStore
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.response_synthesizers import ResponseMode
from llama_index.core.ingestion import IngestionPipeline	# （这里没有用到）
# 相较于下面的Settings.transformations提供了更灵活和显式的方式来处理文档
from llama_index.core import Settings
from llama_index.core import StorageContext
from llama_index.core.postprocessor import LLMRerank, SimilarityPostprocessor
from llama_index.core.retrievers import QueryFusionRetriever
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.chat_engine import CondenseQuestionChatEngine
from llama_index.llms.dashscope import DashScope, DashScopeGenerationModels
from llama_index.embeddings.dashscope import DashScopeEmbedding, DashScopeTextEmbeddingModels

# 1. 配置全局大语言模型(LLM)和嵌入模型
Settings.llm = DashScope(model_name=DashScopeGenerationModels.QWEN_MAX, api_key=os.getenv("DASHSCOPE_API_KEY"))
# 使用DashScope的文本嵌入模型
Settings.embed_model = DashScopeEmbedding(model_name=DashScopeTextEmbeddingModels.TEXT_EMBEDDING_V1)

# 2. 配置全局文档处理的转换器
Settings.transformations = [SentenceSplitter(chunk_size=512, chunk_overlap=200)]

# 3. 加载本地文档数据
documents = SimpleDirectoryReader("./data").load_data()

# 如果集合已存在，则删除旧集合
if client.collection_exists(collection_name=COLLECTION_NAME):
    client.delete_collection(collection_name=COLLECTION_NAME)

# 4. 创建新的Qdrant集合
client.create_collection(
    collection_name=COLLECTION_NAME,
    vectors_config=VectorParams(size=EMBEDDING_DIM, distance=Distance.COSINE)  # 配置向量参数
)

# 5. 创建Qdrant向量存储实例
vector_store = QdrantVectorStore(client=client, collection_name=COLLECTION_NAME)

# 6. 创建存储上下文并构建索引
storage_context = StorageContext.from_defaults(vector_store=vector_store)
# 从文档创建向量索引
index = VectorStoreIndex.from_documents(
    documents, storage_context=storage_context
)

# 7. 定义检索后处理模型
reranker = LLMRerank(top_n=2)  # 使用LLM重新排序，只保留前2个结果
# 设置相似度过滤器，过滤掉相似度低于0.6的结果
sp = SimilarityPostprocessor(similarity_cutoff=0.6)

# 8. 定义RAG Fusion检索器
# QueryFusionRetriever通过生成多个查询来提高检索效果
fusion_retriever = QueryFusionRetriever(
    [index.as_retriever()],  # 基础检索器
    similarity_top_k=5,      # 每个查询返回5个最相似的结果
    num_queries=3,           # 生成3个不同的查询
    use_async=False,         # 不使用异步处理
)

# 9. 构建查询引擎
query_engine = RetrieverQueryEngine.from_args(
    fusion_retriever,                    # 使用上面定义的融合检索器
    node_postprocessors=[reranker],      # 使用重排序后处理器
    response_synthesizer=get_response_synthesizer(
        response_mode=ResponseMode.REFINE  # 使用REFINE模式合成响应
    )
)

# 10. 创建对话引擎
# CondenseQuestionChatEngine用于处理多轮对话，会将当前问题与历史对话结合
chat_engine = CondenseQuestionChatEngine.from_defaults(
    query_engine=query_engine,
)

# 11. 启动交互式对话循环
while True:
    # 获取用户输入
    question = input("User:")
    # 如果输入为空，则退出循环
    if question.strip() == "":
        break
    # 使用聊天引擎处理问题
    response = chat_engine.chat(question)
    # 打印AI的回答
    print(f"AI: {response}")
```

---

## Text2SQL

将自然语言转换为 SQL 查询语句

一个成熟的Text2SQL系统需要具备以下关键能力：

|  核心能力   |     说明      |    技术挑战    |
| :-----: | :---------: | :--------: |
|  语义理解   | 理解用户真正的查询意图 | 处理歧义、上下文推断 |
| 数据库结构感知 | 了解表结构、字段关系  | 自动映射字段与实体  |
| 复杂查询构建  | 支持多表连接、聚合等  | 子查询、嵌套逻辑转换 |
|  上下文记忆  | 理解多轮对话中的指代  |   维护查询状态   |
|  错误处理   |  识别并修正错误输入  | 模糊匹配、容错机制  |

技术架构：基于 Workflow 工作流、LangChain 的数据库链和企业级解决方案（[Vanna](https://vanna.ai/)、[自然语言到SQL语言转义（基于大语言模型的NL2SQL）](http://help.aliyun.com/zh/polardb/polardb-for-mysql/user-guide/llm-based-nl2sql?spm=a2c4g.11186623.help-menu-2249963.d_5_25_1_0.5d942b63IaNo7t&scm=20140722.H_2669074._.OR_help-T_cn~zh-V_1)、[自然语言生成智能图表NL2Chart](https://help.aliyun.com/zh/polardb/polardb-for-mysql/user-guide/nl2chart?spm=a2c4g.11186623.help-menu-2249963.d_5_25_1_1.16325ef0KtuFXl&scm=20140722.H_2922405._.OR_help-T_cn~zh-V_1)、[ChatBI](https://cloud.tencent.com/document/product/590/107689)）

## 工作流

LlamaIndex 工作流由事件（event）驱动，由 step 组成，每个 step 处理特定的事件，直到产生 StopEvent 结束。

LlamaIndex Workflows： https://docs.llamaindex.ai/en/stable/module_guides/workflow/

### 使用自然语言查询数据库中的内容

基本流程：

1. 用户输入自然语言查询
2. 系统先去检索跟查询相关的表
3. 根据表的 Schema 让大模型生成 SQL
4. 用生成的 SQL 查询数据库
5. 根据查询结果，调用大模型生成自然语言回复

https://docs.llamaindex.ai/en/stable/optimizing/production_rag/















