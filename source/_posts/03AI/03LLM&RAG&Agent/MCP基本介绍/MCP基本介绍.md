---
title: "MCP基本介绍"
date: 2025-07-23
tags:
  - Others
categories:
  - Others
---
> https://modelcontextprotocol.io/introduction

MCP 协议，允许应用程序以一种统一的方式向大模型提供 Function call 函数调用。

![[attachments/20250723.png]]

两种实现方式：

- SSE：类似与 HTTP 服务端提供服务，客户端与其建立长连接，客户端访问服务，获取服务数据。
- STDIO：客户端本地执行一个应用程序，通过应用程序获取对应结果。（服务由 MCP 的提供者设计，但执行却在客户端机器执行）

## MCP 工具实现与使用

示例：

```python
# MCP服务端的实现
from mcp.server.fastmcp import FastMCP  

# 创建一个FastMCP实例，名称为roymcpdemo
mcp = FastMCP("roymcpdemo")  
  
# 定义工具函数，两数相加
@mcp.tool()  
def add(a: int, b: int) -> int:  
    """Add two numbers together"""  
    print(f"roy mcp demo called: all({a}, {b})")  
    return a + b  
  
# 定义工具函数weather，获取某个城市的天气
@mcp.tool()  
def weather(city: str):  
    """获取某个城市的天气  
    Args：  
        city：具体城市  
    """    
    return "城市" + city + "天气挺好"  
  
# 定义资源greeting，用于向某人打招呼
@mcp.resource("greeting://{name}")  
def greeting(name: str) -> str:  
    """Greet a person by name."""  
    print(f"roy mcp demo called : greeting({name})")  
    return f"Hello, {name}!"  
  
  
if __name__ == "__main__":  
    # 以sse协议启动服务  
    mcp.run(transport="sse")  
    # 以stdio协议启动服务  
    mcp.run(transport="stdio")
```

sse 协议启动服务可在对应配置文件中添加配置使用：

```python
# sse 协议的配置
"roymcpdemo": {
	"url": "http://127.0.0.1:8000/sse",
}
```

```python
# MCP 客户端的实现，使用stdio协议调用
# mcp模块stdio通信的核心组件  
from mcp import StdioServerParameters, stdio_client, ClientSession  
# ... 创建stdio客户端连接工具 客户端会话管理器  
# 用于处理mcp协议中的各种数据类型  
import mcp.types as types  
  
# 配置stdio服务参数，指定启动服务的命令和参数  
server_params = StdioServerParameters(  
    command="python",  
    args=["./mcp_server.py", "stdio"],  
    env=None  
)  
  
  
# 处理采样消息的回调函数  
# 接收CreateMessageRequestParams类型的消息，返回CreateMessageResult类型的响应  
async def handle_sampling_message(message: types.CreateMessageRequestParams) -> types.CreateMessageResult:  
    print(f"sampling message: {message}")  
    return types.CreateMessageResult(  
        role="assistant",  
        content=types.TextContent(  
            type="text",  
            text="Hello,world! from model"  
        ),  
        model="qwen-plus",  
        stopReason="endTurn"  
    )  
  
  
# 主要的异步执行函数，演示了如何使用stdio客户端与服务端进行交互  
async def run():  
    # 创建与服务端的连接，获取读写流  
    async with stdio_client(server_params) as (read, write):  
        # 创建会话，传入读写流和采样消息回调函数  
        async with ClientSession(read, write, sampling_callback=handle_sampling_message) as session:  
            # 初始化会话  
            await session.initialize()  
            # 获取所有可用提示  
            prompts = await session.list_prompts()  
            print(f"prompts: {prompts}")  
            # 获取所有可用工具  
            tools = await session.list_tools()  
            print(f"tools: {tools}")  
            # 获取所有可用资源  
            resources = await session.list_resources()  
            print(f"resources: {resources}")  
            # 调用weather工具，查询北京的天气  
            result = await session.call_tool("weather", {"city": "北京"})  
            print(f"result: {result}")  
  
  
if __name__ == "__main__":  
    import asyncio  # 用于运行异步代码  
  
    asyncio.run(run())  # 启动主异步函数
```

## 调用已有 MCP 服务回答问题

```python
# 调用执行高德地图客户端MCP服务
from langchain_mcp_adapters.client import MultiServerMCPClient  
from langgraph.prebuilt import create_react_agent  # 创建基于ReAct模式的智能体  
from config.load_key import load_key  
  
from langchain_community.chat_models import ChatTongyi  
import asyncio  
  
llm = ChatTongyi(  
    model="qwen-plus",  
    api_key=load_key("BAILIAN_API_KEY"),  
)  
  
# 用于连接多个MCP服务的客户端  
client = MultiServerMCPClient(  
    {  
    	# sse 服务的配置
        # "amap-amap-sse": {  
        #     "url": "https://mcp.amap.com/sse?key=451ad40d0e39453600f2a305e31eabe4",        
        #     "transport": "streamable_http"        
        # },        
        # stdio 服务的配置
        "amap-maps": {  
            "command": "npx",  
            "args": [  
                "-y",  
                "@amap/amap-maps-mcp-server"  
            ],  
            "env": {  
                "AMAP_MAPS_API_KEY": "451ad40d0e39453600f2a305e31eabe4"  
            },  
            "transport": "stdio"  
        }  
    }  
)  
  
  
async def main():  
    # 获取MCP服务提供的工具列表  
    tools = await client.get_tools()  
    # 创建ReAct模式的智能体  
    agent = create_react_agent(  
        llm,  
        tools,  
    )  
  
    response = await agent.ainvoke(  
        {"messages": [{"role": "user", "content": "在杭州，我要去西湖，请给我推荐一些景点"}]}  
    )  
  
    print(response)  
  
  
asyncio.run(main())
```