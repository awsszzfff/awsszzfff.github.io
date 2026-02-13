---
title: "LangGraph构建多智能体"
date: 2025-07-24
tags:
  - Others
categories:
  - Others
---
## 案例基本流程

- 通过 supervisor 节点，对用户的输入进行分类，然后根据分类结果，选择不同的 agent 节点进行处理
- 每个 agent 节点，都可以选择不同的工具进行处理，最后将处理结果汇总，返回给 supervisor 节点
- supervisor 节点再将结果返回给用户

![[attachments/20250724.png]]

## 模块解释

- 路线规划助手，调度外部 MCP 服务，获取补充信息
- 对对联助手，从向量数据库中获取补充的资料，实现一个典型的 RAG 流程
- 笑话助手，直接与大模型交互获得结果
- 其他问题，只添加一个简单的响应结果

### 核心多智能体系统

```python file:Director.py
import asyncio
import os
from operator import add
from typing import TypedDict, Annotated

import redis
from langchain_redis import RedisConfig, RedisVectorStore
from langchain_community.embeddings import DashScopeEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langgraph.prebuilt import create_react_agent
from langchain_community.chat_models import ChatTongyi
from langchain_core.messages import AnyMessage, HumanMessage, AIMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.config import get_stream_writer
from langgraph.constants import START, END
from langgraph.graph import StateGraph

from config.load_key import load_key

# 定义所有可能的节点类型
nodes = ["supervisor", "travel", "joke", "couplet", "other", END]

llm = ChatTongyi(
    model="qwen-plus",
    api_key=load_key("BAILIAN_API_KEY"),
)

# 定义图的状态结构
class State(TypedDict):
    # 消息列表，使用add操作符合并
    messages: Annotated[list[AnyMessage], add]
    # 消息类型
    type: str


def supervisor_node(state: State):
    '''
    主管节点：负责对用户问题进行分类并路由到相应处理节点
    :param state:
    :return:
    '''
    print(">>> supervisor_node")
    writer = get_stream_writer()
    writer({"node", ">>> supervisor_node"})

    # 分类提示词，指导模型如何对问题进行分类
    # 根据用户的问题，对问题进行分类，分类结果保存在state["type"]中
    prompt = """你是一个专业的客服助手，负责对用户的问题进行分类，并将任务分给其他Agent执行。
    如果用户问题是和旅游路线规划相关的，那就返回 travel；
    如果用户问题是希望讲一个笑话，那就返回 joke；
    如果用户的问题是对一个对联，那就返回 couplet；
    如果是其他的问题，返回 other；
    除了这几个选项外，不要返回任何其他的内容。
    """

    # 构建提示词列表
    prompts = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": state["messages"][0]}
    ]

    # 如果已经有type，表示问题已经处理，直接返回
    if "type" in state:
        writer({"supervisor_step", f"已经获得{state['type']}智能体处理结果"})
        return {"type": END}
    else:
        # 调用模型进行分类
        response = llm.invoke(prompts)
        typeRes = response.content
        writer({"supervisor_step": f"问题分类结果：{typeRes}"})

        # 检查分类结果是否在预定义节点中
        if typeRes in nodes:
            return {"type": typeRes}
        else:
            raise ValueError("type is not in types_node")


def travel_node(state: State):
    '''
    旅游路线规划节点：处理旅游相关问题
    :param state:
    :return:
    '''
    print(">>> travel_node")
    writer = get_stream_writer()
    writer({"node": ">>> travel_node"})

    # 旅游规划系统提示词
    system_prompt = "你是一个专业的旅行规划助手，根据用户的输入，生成一个50字左右的路线规划。"

    # 构建提示词列表
    prompts = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": state["messages"][0]}
    ]

    # 高德地图MCP的配置信息
    client = MultiServerMCPClient(
        {
            # "amap-amap-sse": {
            #     "url": "https://mcp.amap.com/sse?key=451ad40d0e39453600f2a305e31eabe4",
            #     "transport": "streamable_http"
            # },
            "amap-maps": {
                "command": "npx",   # 使用npx启动
                "args": [
                    "-y",
                    "@amap/amap-maps-mcp-server"    # MCP服务器包
                ],
                "env": {
                    "AMAP_MAPS_API_KEY": "451ad40d0e39453600f2a305e31eabe4"
                },
                "transport": "stdio"    # 使用标准输入输出通信stdio
            }
        }
    )

    # 异步获取工具
    tools = asyncio.run(client.get_tools())

    # 创建一个React代理
    agent = create_react_agent(
        model=llm,
        tools=tools
    )

    # 调用代理处理请求
    response = agent.invoke({"messages": prompts})
    writer({"travel_result": response["messages"][-1].content})

    # 返回处理结果
    return {"messages": [HumanMessage(content=response["messages"][-1].content)], "type": "travel"}


def joke_node(state: State):
    '''
    笑话生成节点：处理笑话请求
    :param state:
    :return:
    '''
    print(">>> joke_node")
    writer = get_stream_writer()
    writer({"node": ">>> joke_node"})

    # 笑话生成系统提示词
    system_prompt = "你是一个笑话大师，根据用户的输入，生成一个5字左右的笑话。"

    # 构建提示词列表
    prompts = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": state["messages"][0]}
    ]

    # 调用模型生成笑话
    response = llm.invoke(prompts)
    writer({"joke_result": response.content})

    # 返回笑话结果
    return {"messages": [AIMessage(content=response.content)], "type": "joke"}


def couplet_node(state: State):
    '''
    对联生成节点：处理对联请求
    :param state:
    :return:
    '''
    print(">>> couplet_node")
    writer = get_stream_writer()
    writer({"node": ">>> couplet_node"})

    # 对联生成提示词模版
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", """
        你是一个专业的对联大师，你的任务是根据用户给出的上联，设计下联
        回答时，可以参考下面对联
        参考对联：
            {samples}
        请用中文回答问题
        """),
        ("user", "{text}")  # 用户输入的上联
    ])

    # 获取用户查询
    query = state["messages"][0]

    # 设置API秘钥
    if not os.environ.get("DASHSCOPE_API_KEY"):
        os.environ["DASHSCOPE_API_KEY"] = load_key("BAILIAN_API_KEY")

    # 初始化嵌入模型
    embedding_model = DashScopeEmbeddings(model="text-embedding-v1")
    redis_url = "redis://localhost:6379"

    # 创建Redis客户端
    redis_client = redis.from_url(redis_url)
    print(redis_client.ping())

    # 配置Redis向量存储
    config = RedisConfig(
        index_name="couplet",   # 索引名称
        redis_client=redis_client,
    )

    # 创建向量存储实例
    vector_store = RedisVectorStore(embedding_model, config)

    # 从向量数据库中检索相似对联作为参考
    samples = []
    scored_results = vector_store.similarity_search(query, k=10)    # 检索相似的10个对联样本
    for doc, score in scored_results:
        # print(f"{doc.page_content} - {score}")
        samples.append(doc.page_content)

    # 构建最终提示词
    prompt = prompt_template.invoke({"samples": samples, "text": query})
    writer({"couplet_prompt": prompt})

    # 调用模型生成对联
    response = llm.invoke(prompt)
    writer({"couplet_result": response.content})

    # 返回对联结果
    return {"messages": [HumanMessage(content=response.content)], "type": "couplet"}


def other_node(state: State):
    '''
    其他问题处理节点：处理无法分类的问题
    :param state:
    :return:
    '''
    print(">>> other_node")
    writer = get_stream_writer()
    writer({"node": ">>> other_node"})

    # 返回默认回复
    return {"messages": [HumanMessage(content="我暂时无法回答此问题，请稍后再试。")], "type": "other"}


# 路由
def routing_func(state: State):
    '''
    路由函数：根据问题类型决定下一步执行哪个节点
    :param state:
    :return:
    '''
    if state["type"] == "travel":
        return "travel_node"
    elif state["type"] == "joke":
        return "joke_node"
    elif state["type"] == "couplet":
        return "couplet_node"
    elif state["type"] == END:
        return END
    else:
        return "other_node"


# 构件状态图
builder = StateGraph(State)

# 添加所有节点到图中
builder.add_node("supervisor_node", supervisor_node)
builder.add_node("travel_node", travel_node)
builder.add_node("joke_node", joke_node)
builder.add_node("couplet_node", couplet_node)
builder.add_node("other_node", other_node)

# 添加边（定义节点间的连接关系）
builder.add_edge(START, "supervisor_node")  # 从开始节点到主管节点
# 添加条件边，根据路由函数结果决定下一步
builder.add_conditional_edges("supervisor_node", routing_func,
                              ["travel_node", "joke_node", "couplet_node", "other_node", END])
# 将所有处理节点连接回主管节点
builder.add_edge("travel_node", "supervisor_node")
builder.add_edge("joke_node", "supervisor_node")
builder.add_edge("couplet_node", "supervisor_node")
builder.add_edge("other_node", "supervisor_node")

# 编译图并添加检查点
checkpointer = InMemorySaver()
graph = builder.compile(checkpointer=checkpointer)

if __name__ == "__main__":
    # 配置线程ID
    config = {
        "configurable": {
            "thread_id": "1"
        }
    }

    # 流式执行图，处理对联请求示例
    for chunk in graph.stream({"messages": ["给我一个对联下联，上联是：金榜题名时"]},
                              config,
                              stream_mode="custom"  # 使用自定义模式（调试用一般）
                              ):
        print(chunk)
```

### 系统入口/调用实例

```python file:DirectorServer.py
import random

from Director import graph

config = {
    "configurable": {
        "thread_id": random.randint(1, 10000)
    }
}

query = "请给我讲一个笑话"

res = graph.invoke(
    {"messages": ["今天天气怎么样"]},
    config,
    stream_mode="values"
)

print(res["messages"][-1].content)
```

### 对联数据准备模块

```python file:CoupletLoader.py
# 将对联文本加载到向量数据库中

import os
from config.load_key import load_key
import redis
from langchain_community.embeddings import DashScopeEmbeddings

if not os.environ.get("DASHSCOPE_API_KEY"):
    os.environ["DASHSCOPE_API_KEY"] = load_key("BAILIAN_API_KEY")

embedding_model = DashScopeEmbeddings(model="text-embedding-v1")

redis_url = "redis://localhost:6379"

# 创建 Redis 客户端
redis_client = redis.from_url(redis_url)
print(redis_client.ping())

from langchain_redis import RedisConfig, RedisVectorStore

# 配置Redis向量存储参数
config = RedisConfig(
    index_name="couplet",  # 索引名称
    redis_client=redis_client,
)

# 创建Redis向量存储实例
vector_store = RedisVectorStore(embedding_model, config)

# 读取对联数据文件
lines = []
with open("../resource_/couplettest.csv", "r", encoding="utf-8") as file:
    for line in file:
        print(line)
        lines.append(line)

# 将对联文件提那家到向量数据库中
vector_store.add_texts(lines)
```

### 对联检索演示模块

```python file:CoupletRetraval.py
import os

from langchain_core.prompts import ChatPromptTemplate

from config.load_key import load_key
import redis
from langchain_community.embeddings import DashScopeEmbeddings
from langchain_community.chat_models import ChatTongyi

# 用户输入
query = "帮我对对联，上联：瑞雪兆丰年"

if not os.environ.get("DASHSCOPE_API_KEY"):
    os.environ["DASHSCOPE_API_KEY"] = load_key("BAILIAN_API_KEY")

embedding_model = DashScopeEmbeddings(model="text-embedding-v1")
redis_url = "redis://localhost:6379"

from langchain_redis import RedisConfig, RedisVectorStore

# 配置Redis向量存储参数
config = RedisConfig(
    index_name="couplet",  # 索引名称
    redis_url=redis_url,  # Redis连接地址
)
# 初始化向量存储实例
vector_store = RedisVectorStore(embedding_model, config)

# 存储索引到的相似对联样本
samples = []
# 使用向量相似度检索最相关的10个对联样本
scored_results = vector_store.similarity_search(query, k=10)
for doc, score in scored_results:
    # print(f"{doc.page_content} - {score}")
    samples.append(doc.page_content)

# 定义对联生成的提示词模版
prompt_template = ChatPromptTemplate.from_messages([
    ("system", """
    你是一个专业的对联大师，你的任务是根据用户给出的上联，设计下联
    回答时，可以参考下面对联
    参考对联：
        {samples}
    请用中文回答问题
    """),
    ("user", "{text}")
])

# 填充提示词模版中的变量
prompt = prompt_template.invoke({"samples": samples, "text": query})

# 打印构建好的提示词
print(prompt)

# 初始化模型
llm = ChatTongyi(
    model="qwen-plus",
    api_key=load_key("BAILIAN_API_KEY"),
)

# 模型调用
print(llm.invoke(prompt))
```

