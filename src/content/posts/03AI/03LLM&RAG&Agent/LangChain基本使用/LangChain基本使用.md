---
title: "LangChain基本使用"
date: 2025-07-19
tags:
  - Others
categories:
  - Others
---
开发大语言模型提供应用程序支持的框架

Langchain的核心组件:

- 模型（Models）：包含各大语言模型的LangChain接口和调用细节，以及输出解析机制。
- 提示模板（Prompts）：使提示工程流线化，进一步激发大语言模型的潜力。
- 数据检索（Indexes）：构建并操作文档的方法，接受用户的查询并返回最相关的文档，轻松搭建本地知识库。
- 记忆（Memory）：通过短时记忆和长时记忆，在对话过程中存储和检索数据，让ChatBot记住你。
- 链（Chains）：LangChain中的核心机制，以特定方式封装各种功能，并通过一系列的组合，自动而灵活地完成任务。
- 代理（Agents）：另一个LangChain中的核心机制，通过“代理”让大模型自主调用外部工具和内部工具，使智能Agent成为可能。

开源库组成:

- langchain-core ：基础抽象和LangChain表达式语言
- langchain-community ：第三方集成。合作伙伴包（如langchain-openai、langchain-anthropic等），一些集成已经进一步拆分为自己的轻量级包，只依赖于langchain-core
- langchain ：构成应用程序认知架构的链、代理和检索策略
- langgraph：通过将步骤建模为图中的边和节点，使用 LLMs 构建健壮且有状态的多参与者应用程序
- langserve：将 LangChain 链部署为 REST API
- LangSmith：一个开发者平台，可让您调试、测试、评估和监控LLM应用程序，并与LangChain无缝集成

> - 功能模块： https://python.langchain.com/docs/tutorials
> - API 文档： https://python.langchain.com/api_reference/
> - 三方组件集成： https://python.langchain.com/docs/integrations/providers/
> - 更多 HowTo： https://python.langchain.com/docs/how_to/

## 通过 API 的方式调用大模型

---

需要设置模型对应的 API_key，可以通过以下代码实现

```python
# import getpass  
import json  
import os.path  
  
  
def load_key(keyname: str) -> str:  
    file_name = "./Keys.json"  
    if os.path.exists(file_name):  
        with open(file_name, "r") as file:  
            Key = json.load(file)  
        if keyname in Key and Key[keyname]:  
            return Key[keyname]  
        else:  
            # keyval = getpass.getpass("配置文件中没有对应的配置，请输入对应的配置信息：").strip()  
            keyval = input("配置文件中没有对应的配置，请输入对应的配置信息：").strip()  
            Key[keyname] = keyval  
            with open(file_name, "w") as file:  
                json.dump(Key, file, indent=4)  
            return keyval  
    else:  
        # keyval = getpass.getpass("配置文件中没有对应的配置信息，请输入对应的配置信息：").strip()  
        keyval = input("配置文件中没有对应的配置信息，请输入对应的配置信息：").strip()  
        Key = {  
            keyname: keyval  
        }  
        with open(file_name, "w") as file:  
            json.dump(Key, file, indent=4)  
        return keyval  
  
  
if __name__ == "__main__":  
    print(load_key("LANGSMITH_API_KEY"))
```

```python
import os  
from config.load_key import load_key  
  
if not os.environ.get("OPENAI_API_KEY"):  
    os.environ["OPENAI_API_KEY"] = load_key("OPENAI_API_KEY") 
```

可通过如下代码对 API_key 的使用进行监控（需注册申请并配置 LangSmith API_key https://smith.langchain.com/ ）

```python
import os  
from config.load_key import load_key  
  
os.environ["LANGSMITH_TRACING"] = "true"  
os.environ["LANGSMITH_PROJECT"] = "LangChain_Learning_test"  
os.environ["LANGSMITH_API_KEY"] = load_key("LANGSMITH_API_KEY")
```

也可以直接在调用模型时直接给定 API_key ，不过上面这种更方便且安全

---

### 模型的调用和基本使用

```python 
from langchain.chat_models import init_chat_model  

# 创建访问OpenAI的Model
model = init_chat_model(
	"gpt-3.5-turbo", 
	model_provider="openai",
	# base_url="https://api.gptsapi.net/v1"	# 接口，因 OpenAI 默认接口国内不容易访问，可指定代理接口	
	# temperature=0.1	# 该值在[0,2)之间，越大，模型输出随机性越大（重复同一个问题多次输出的随机性）
)
```

> 在模型调用时支持传入更多定制的参数，eg：temperature、top_p 等，从而得到不同的模型输出效果

```python
from langchain_core.messages import HumanMessage, SystemMessage  
# 或通过 from langchain.schema import HumanMessage ... 导入
  
messages = [  
    SystemMessage("Translate the following from English into Chinese"),  
    HumanMessage("I love programming."),  
]  
# 返回一个AIMessage对象
model.invoke(messages)
```

在与大模型交互时，有多种不同的消息作为不同的角色输入给大模型作为提示词

- user/HumanMessage ：用户输入的问题
- system/SystemMessage ：系统角色，描述问题的背景及当前大模型充当的角色
- assistant/AIMessage ：模型输出的答案

```python
# 其他的调用传入消息的方式
# invoke 相当与一次单轮的对话，多个invoke及多个不同的单轮对话
model.invoke("Hello")
model.invoke([{"role": "user", "content": "Hello"}])
model.invoke([HumanMessage("Hello")])
```

LangChain 也对 OpenAI 的调用方式做了封装（以不同的方式调用不同的模型，需要安装对应的依赖）

```python
from langchain_openai import ChatOpenAI  
  
llm = ChatOpenAI(  
    model="gpt-3.5-turbo",  
)  
llm.invoke([  
    SystemMessage("Translate the following from English into Chinese"),  
    HumanMessage("I love programming.")  
])

# 其他大模型调用也是类似的方式
from langchain_deepseek import ChatDeepSeek  
  
llm = ChatDeepSeek(  
    model="deepseek-chat"  
)  
llm.invoke([HumanMessage("你是谁？你可以干什么？")])

# 大模型产品基本都兼容OpenAI API访问接口的方式
from langchain_openai import ChatOpenAI  
from langchain_core.messages.human import HumanMessage  

# 好像这样调用的方式还是比较常用的
llm = ChatOpenAI(  
    model="deepseek-v3",  
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  
    openai_api_key=load_key("BAILIAN_API_KEY"),  
)  
llm.invoke([HumanMessage("你是谁？你可以干什么？")])
```

流式输出

```python
stream = llm.stream([HumanMessage("你是谁？你可以干什么？")])
for chunk in stream:  
    print(chunk.content, end="")
```

### 模型输入与输出

![[attachments/model_io.jpg]]

#### 提示词模版

> 将 Prompt 模版看作带有参数的函数

基本使用

```python
from langchain.prompts import PromptTemplate  
  
template = PromptTemplate.from_template("给我讲个关于{subject}的笑话")   
# 从文件中加载Prompt模版（文件内容"给我讲个关于{subject}的笑话"）
# template = PromptTemplate.from_file("example_prompt_template.txt")

print(template)  
# input_variables=['subject'] input_types={} partial_variables={} template='给我讲个关于{subject}的笑话'

print(template.format(subject='小明'))  
# 给我讲个关于小明的笑话

result = llm.invoke(template.format(subject='小明'))  
print(result.content)
# 好的！这里有一个关于小明的经典笑话：....
```

```python
from langchain_core.prompts import ChatPromptTemplate
# from langchain_core.prompts import HumanMessagePromptTemplate, SystemMessagePromptTemplate

prompt_template = ChatPromptTemplate.from_messages([  
    ("system", "Translate the following from English into {language}"),  
    ("user","{text}")  
]) 

'''
prompt_template = ChatPromptTemplate.from_messages(
    [
        SystemMessagePromptTemplate.from_template("Translate the following from English into {language}"),
        HumanMessagePromptTemplate.from_template("{text}")
    ]
)
'''

prompt = prompt_template.format_messages(language="Chinese", text="I love programming.")  
# [SystemMessage(content='Translate the following from English into Chinese', additional_kwargs={}, response_metadata={}), HumanMessage(content='I love programming.', additional_kwargs={}, response_metadata={})]

response = llm.invoke(prompt)  
print(response.content)	# 我喜欢编程。
```

### 把多轮对话变成模版

```python
# 导入LangChain中用于创建聊天提示模板的相关类
from langchain.prompts import (
    ChatPromptTemplate,              # 聊天提示模板主类
    HumanMessagePromptTemplate,      # 人类消息提示模板类
    MessagesPlaceholder,            # 消息占位符类
)

# 定义一个人类提示模板字符串，包含一个language变量
human_prompt = "Translate your answer to {language}."

# 从模板字符串创建人类消息提示模板实例
human_message_template = HumanMessagePromptTemplate.from_template(human_prompt)

# 创建聊天提示模板，包含历史消息占位符和人类消息模板
chat_prompt = ChatPromptTemplate.from_messages(
    # MessagesPlaceholder用于在模板中占位，"history"是变量名
    # 在实际使用时会被替换为具体的历史对话消息
    [MessagesPlaceholder("history"), human_message_template]
)

# 导入消息类，用于创建AI和人类消息实例
from langchain_core.messages import AIMessage, HumanMessage

# 创建一个人类消息实例，内容是问题
human_message = HumanMessage(content="Who is Elon Musk?")

# 创建一个AI消息实例，内容是对问题的回答
ai_message = AIMessage(
    content="Elon Musk is a billionaire entrepreneur, inventor, and industrial designer"
)

# 格式化提示模板，将占位符替换为实际值
messages = chat_prompt.format_prompt(
    # history变量被替换为包含对话历史的列表
    history=[human_message, ai_message], 
    # language变量被替换为"中文"
    language="中文"
)

# 打印格式化后的消息列表
print(messages.to_messages())
# [HumanMessage(content='Who is Elon Musk?', additional_kwargs={}, response_metadata={}), AIMessage(content='Elon Musk is a billionaire entrepreneur, inventor, and industrial designer', additional_kwargs={}, response_metadata={}), HumanMessage(content='Translate your answer to 中文.', additional_kwargs={}, response_metadata={})]

# 调用语言模型处理格式化后的消息
result = llm.invoke(messages)

# 打印语言模型的响应内容
print(result.content)
# 埃隆·马斯克是一位亿万富翁企业家、发明家和工业设计师。
```

## 结构化输出

### 直接输出 Pydantic 对象

```python
from pydantic import BaseModel, Field

# 定义你的输出对象
class Date(BaseModel):
    year: int = Field(description="Year")
    month: int = Field(description="Month")
    day: int = Field(description="Day")
    era: str = Field(description="BC or AD")
```

```python
from langchain.prompts import PromptTemplate

# 定义结构化输出的模型
structured_llm = llm.with_structured_output(Date)

template = """提取用户输入中的日期。
用户输入:
{query}"""

prompt = PromptTemplate(
    template=template,
)

query = "2023年四月6日天气晴..."
input_prompt = prompt.format_prompt(query=query)

structured_llm.invoke(input_prompt)
# Date(year=2023, month=4, day=6, era='AD')
```

#### 输出指定的格式

```python
# OpenAI 模型的JSON格式  
json_schema = {  
    "title": "Date",  
    "description": "Formated date expression",  
    "type": "object",  
    "properties": {  
        "year": {  
            "type": "integer",  
            "description": "year, YYYY",  
        },  
        "month": {  
            "type": "integer",  
            "description": "month, MM",  
        },  
        "day": {  
            "type": "integer",  
            "description": "day, DD",  
        },  
        "era": {  
            "type": "string",  
            "description": "BC or AD",  
        },  
    },  
}  
structured_llm = llm.with_structured_output(json_schema)  
  
structured_llm.invoke(input_prompt)
# {'day': 6, 'era': 'AD', 'month': 4, 'year': 2023}
```

不同的方式结构化输出

```python
# 导入JsonOutputParser类，用于解析JSON格式的模型输出
from langchain_core.output_parsers import JsonOutputParser

# 创建JsonOutputParser实例，指定使用Date类作为解析目标
# 这会将LLM的输出解析为符合Date模型结构的Python对象
parser = JsonOutputParser(pydantic_object=Date)

# 创建PromptTemplate模板
prompt = PromptTemplate(
    # 定义提示词模板，包含用户查询和格式化指令
    template="提取用户输入中的日期。\n用户输入:{query}\n{format_instructions}",
    # 指定模板中需要填充的变量
    input_variables=["query"],
    # 指定部分变量（预定义变量），这里将自动获取格式化指令
    # parser.get_format_instructions()会生成如何格式化输出的说明文本
    partial_variables={"format_instructions": parser.get_format_instructions()},
)

# 使用模板格式化实际提示词，传入查询内容
input_prompt = prompt.format_prompt(query=query)

# 调用语言模型处理格式化后的提示词
output = llm.invoke(input_prompt)
# 打印模型的原始输出内容
print("原始输出:\n"+output.content)
# 打印解析后的提示
print("\n解析后:")
# 使用解析器解析模型的原始输出，转换为结构化数据
parser.invoke(output)	# {"year": 2023, "month": 4, "day": 6, "era": "AD"}

# 虽然输出结果是一样的，但是他们的类型是不同的
```

```python
# 导入PydanticOutputParser类，用于将LLM输出解析为Pydantic模型对象
from langchain_core.output_parsers import PydanticOutputParser

# 创建PydanticOutputParser实例，指定使用Date类作为解析目标
# 与JsonOutputParser不同，这个解析器会返回Pydantic模型实例而不是字典
parser = PydanticOutputParser(pydantic_object=Date)

# 使用之前定义的prompt模板格式化实际提示词，传入查询内容
# 这里复用了前面单元格中定义的prompt和query变量
input_prompt = prompt.format_prompt(query=query)

# 调用语言模型处理格式化后的提示词
output = llm.invoke(input_prompt)
# 打印模型的原始输出内容
print("原始输出:\n" + output.content)
# 打印解析后的提示
print("\n解析后:")
# 使用Pydantic解析器解析模型的原始输出，转换为Date模型实例
parser.invoke(output)	# Date(year=2023, month=4, day=6, era='AD')
```

利用大模型做格式自动纠错

```python
# OutputFixingParser用于修复格式错误的输出
from langchain.output_parsers import OutputFixingParser

# 创建OutputFixingParser实例
# 这个解析器可以在原始解析器失败时，使用LLM来修复输出格式
# 纠错能力与大模型的能力相关
new_parser = OutputFixingParser.from_llm(parser=parser, llm=llm)

# 创建一个格式错误的输出示例
# 将原来正确的数字"4"替换为中文"四"，破坏了JSON格式
bad_output = output.content.replace("4", "四")

try:
    # 尝试解析格式错误的输出
    parser.invoke(bad_output)
except Exception as e:
    # 捕获并打印解析错误
    print(e)
# Invalid json output: ```json {"year": 2023, "month": 四, "day": 6, "era": "AD"} ```

# OutputFixingParser会尝试修复格式错误并返回正确结果
new_parser.invoke(bad_output)
# Date(year=2023, month=4, day=6, era='AD')
```

## LCEL 表达式

LangChain Expression Language（LCEL），方便组合不同的调用顺序构成 Chain，

```python
from langchain_core.output_parsers import StrOutputParser	# 字符串输出解析器  
from langchain_core.prompts import ChatPromptTemplate  
  
from langchain_openai import ChatOpenAI  
from config.load_key import load_key  

# 提示词模版
prompt_template = ChatPromptTemplate.from_messages([  
    ("system", "Translate the following from English into {language}"),  
    ("user", "{text}")  
])  

# 构建大模型客户端
llm = ChatOpenAI(  
    model="deepseek-v3",  
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  
    openai_api_key=load_key("BAILIAN_API_KEY"),  
)

# 结果解析器StrOutputParser会将AIMessage转换为str，实际上就是获取AIMessage的content属性
parser = StrOutputParser()  
# 构建问答链
chain = prompt_template | llm | parser 
# 直接调用问答链链
print(chain.invoke({"language": "Chinese", "text": "I love programming."}))	# 我爱编程

# 将上次的输出作为下次的输入
# 继续构建复杂的问答链
analysis_prompt = ChatPromptTemplate.from_template(("我应该怎么回答这句话？{talk}。给出10字以内总结性的回答"))
chain2 = {"talk": chain} | analysis_prompt | llm | parser  
print(chain2.invoke({"language": "Chinese", "text": "I love programming."}))	# 好好学习，天天向上
```

示例：

```python
from langchain.prompts import ChatPromptTemplate  # 用于创建聊天提示模板
from langchain_core.output_parsers import StrOutputParser  # 字符串输出解析器
from langchain_core.runnables import RunnablePassthrough  # 可运行的传递组件
from pydantic import BaseModel, Field  # 用于数据验证和模型定义
from typing import List, Dict, Optional  # 类型提示
from enum import Enum  # 枚举类型
import json  # JSON处理
from langchain.chat_models import init_chat_model  # 初始化聊天模型


# 定义排序枚举类型，指定可以按什么字段排序
class SortEnum(str, Enum):
    data = 'data'    # 按流量排序
    price = 'price'  # 按价格排序


# 定义排序顺序枚举类型，指定升序或降序
class OrderingEnum(str, Enum):
    ascend = 'ascend'    # 升序
    descend = 'descend'  # 降序


# 定义语义解析结果的数据模型
class Semantics(BaseModel):
    # 流量包名称，可选字段
    name: Optional[str] = Field(description="流量包名称", default=None)
    # 价格下限，可选字段
    price_lower: Optional[int] = Field(description="价格下限", default=None)
    # 价格上限，可选字段
    price_upper: Optional[int] = Field(description="价格上限", default=None)
    # 流量下限，可选字段
    data_lower: Optional[int] = Field(description="流量下限", default=None)
    # 流量上限，可选字段
    data_upper: Optional[int] = Field(description="流量上限", default=None)
    # 排序字段，可选字段
    sort_by: Optional[SortEnum] = Field(description="按价格或流量排序", default=None)
    # 排序顺序，可选字段
    ordering: Optional[OrderingEnum] = Field(description="升序或降序排列", default=None)


# 创建聊天提示模板
prompt = ChatPromptTemplate.from_messages(
    [
        # 系统消息：设定模型角色和任务
        ("system", "你是一个语义解析器。你的任务是将用户的输入解析成JSON表示。不要回答用户的问题。"),
        # 人类消息：包含用户输入的占位符
        ("human", "{text}"),
    ]
)

# 初始化聊天模型，使用deepseek-chat模型
llm = init_chat_model("deepseek-chat", model_provider="deepseek")

# 配置结构化输出，使模型输出符合Semantics模型定义的格式
structured_llm = llm.with_structured_output(Semantics)
# 这里使用with_structured_output会直接返回指定的结构化Semantics对象，而不是上面所用到的StrOutputParser返回字符串


# 构建LCEL（LangChain表达式语言）链
# 将输入文本传递给提示模板，然后传递给结构化输出模型
'''
# 这里会导致一个大模型输出格式的问题
runnable = (
        {"text": RunnablePassthrough()} | prompt | structured_llm
)
'''

# 重新调整模型输出

from langchain_core.runnables import RunnableLambda

def clear_formate(text: str):  
    if text.startswith('```json'):  
        text = text[7:]  
    if text.endswith('```'):  
        text = text[:-3]  
    return text
    
# 修改 LCEL 表达式，添加清理步骤
runnable = (
    {"text": RunnablePassthrough()} 
    | prompt 
    | llm 
    | StrOutputParser()  # 先将输出解析为字符串
    | RunnableLambda(clear_formate)  # 使用你定义的清理函数
    | RunnableLambda(lambda x: Semantics.model_validate_json(x))  # 再解析为结构化输出
)

'''
# 将输入直接传递给提示模板
# runnable = {"text": RunnablePassthrough()} | prompt
# 等价于:
# runnable = {"text": lambda x: x} | prompt
'''

'''
# 示例：复杂组合
runnable = (
    {"text": RunnablePassthrough(), "extra": lambda x: "附加信息"} 
    | prompt 
    | llm
)
# 这会将输入作为 text 传递，同时添加一个固定的 extra 字段
'''

# 执行链式调用，将用户查询"不超过100元的流量大的套餐有哪些"传入
ret = runnable.invoke("不超过100元的流量大的套餐有哪些")

# 将结果以格式化的JSON形式打印输出
print(
    json.dumps(
        ret.model_dump(),  # 将模型转换为字典
        indent=4,          # 缩进4个空格
        ensure_ascii=False # 确保中文字符正确显示
    )
)
```

设置调用不同的模型

```python
# 导入所需的模块和类
from langchain_core.runnables.utils import ConfigurableField  # 用于定义可配置字段
from langchain_community.chat_models import QianfanChatEndpoint  # 百度千帆模型端点（本代码未使用）
from langchain.prompts import (  # 导入提示模板相关类
    ChatPromptTemplate,
    HumanMessagePromptTemplate,
)
from langchain.chat_models import init_chat_model  # 用于初始化聊天模型
from langchain.schema import HumanMessage  # 人类消息类（本代码未使用）
import os  # 操作系统接口（本代码未使用）

# 初始化 DeepSeek 模型
ds_model = init_chat_model("deepseek-chat", model_provider="deepseek")
# 初始化 OpenAI GPT 模型
gpt_model = init_chat_model("gpt-4o-mini", model_provider="openai")
# 初始化阿里云通义千问模型
qwen_model = init_chat_model("qwen-plus", model_provider="aliyun")

# 使用 configurable_alternatives 方法配置多个模型选项
# 默认使用 gpt_model，也可以切换到 deepseek 模型
model = gpt_model.configurable_alternatives(
    ConfigurableField(id="llm"),  # 定义一个ID为"llm"的可配置字段
    default_key="gpt",  # 默认键为"gpt"
    deepseek=ds_model,  # 添加DeepSeek模型
    qwen=qwen_model,	# 添加qwen模型
)

# 创建聊天提示模板
prompt = ChatPromptTemplate.from_messages(
    [
        HumanMessagePromptTemplate.from_template("{query}"),  # 使用模板变量{query}
    ]
)

# 构建 LCEL（LangChain 表达式语言）链
chain = (
    {"query": RunnablePassthrough()}  # 将输入直接传递给提示模板中的{query}
    | prompt  # 应用提示模板
    | model   # 调用模型
    | StrOutputParser()  # 解析模型输出为字符串
)

# 运行链，并指定使用"gpt"模型
ret = chain.with_config(configurable={"llm": "gpt"}).invoke("请自我介绍")
# 使用 DeepSeek 模型
ret = chain.with_config(configurable={"llm": "deepseek"}).invoke("请自我介绍")
# ...

# 打印模型返回的结果
print(ret)

```

可以构建多个并行的问答链，构建复杂的大模型应用逻辑

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableMap, RunnableLambda, RunnableWithMessageHistory  

# 提示词模版
prompt_template_zh = ChatPromptTemplate.from_messages([  
    ("system", "Translate the following from English into Chinese"),  
    ("user", "{text}")  
])  
  
prompt_template_fr = ChatPromptTemplate.from_messages([  
    ("system", "Translate the following from English into French"),  
    ("user", "{text}")  
])  

# 构建问答链
chain_zh = prompt_template_zh | llm | parser  
chain_fr = prompt_template_fr | llm | parser  

# 并行执行两个问答链
parallel_chains = RunnableMap({  
    "zh_translation": chain_zh,  
    "fr_translation": chain_fr,  
})  

# 合并结果
final_chain = parallel_chains | RunnableLambda(lambda x: f"Chinese:{x['zh_translation']}\nFrech: {x['fr_translation']}")  

# 调用问答链
print(final_chain.invoke("I love programming."))
# Chinese:我喜欢编程。
# Frech: J'adore la programmation. 
```

可根据不同的需求来动态构建不同的链。

> LangChain 中只要是顶级父类 Runnable 的子类，都可以链接成一个序列。

> 更多操作：
> 
> - 配置运行时变量： https://python.langchain.com/docs/how_to/configure/
> - 故障回退： https://python.langchain.com/docs/how_to/fallbacks/
> - 并行调用： https://python.langchain.com/docs/how_to/parallel/
> - 逻辑分支： https://python.langchain.com/docs/how_to/routing/
> - 动态创建 Chain: https://python.langchain.com/docs/how_to/dynamic_chain/
> 
> 更多例子： https://python.langchain.com/docs/how_to/lcel_cheatsheet/

### 多轮对话

```python
# 这里将多轮对话的聊天记录存储在内存中
from langchain_core.chat_history import InMemoryChatMessageHistory  

# 这是BaseChatMessageHistory 的子类
history = InMemoryChatMessageHistory()  

# 第一轮聊天
history.add_user_message("I love programming.")  
aimessage = llm.invoke(history.messages)  
print(aimessage.content)  
history.add_ai_message(aimessage)
# history.add_message(HumanMessage(content=aimessage.content))  

# 第二轮聊天
history.add_user_message("重复回答")  
aimessage2 = llm.invoke(history.messages)  
print(aimessage2.content)  
history.add_ai_message(aimessage2)
# history.add_message(AIMessage(content=aimessage2.content))  

# add_user_message、add_ai_message 是 add_message 的简化，若使用则需要给定 BaseMessage 类型，该函数期望传入 BaseMessage 对象

# history.add_message(aimessage2)不过好像这样传也对，只不过下面输出历史聊天记录处报错，str没有content不太懂~

# 历史聊天记录
print("Chat History:")  
for message in history.messages:  
    print(f"{type(message).__name__}: {message.content}")
```

存储到对应的存储系统中，而不是内存中（结束即丢失~）

> LangChain 提供基于其他存储系统的扩展依赖： https://python.langchain.com/docs/integrations/memory/

以 Redis 为例：

```python
from langchain_redis import RedisChatMessageHistory 

# 也是BaseChatMessageHistory的子类，本地启动Redis服务
history = RedisChatMessageHistory(  
    session_id="test",  
    url="redis://localhost:6379",  
)  

# 第一轮聊天
history.add_user_message("I love programming.")  
aimessage = llm.invoke(history.messages)  
print(aimessage.content)  
history.add_ai_message(aimessage)  

# 第二轮聊天
history.add_user_message("重复回答")  
aimessage2 = llm.invoke(history.messages)  
print(aimessage2.content)  
history.add_ai_message(aimessage2)
```

聊天历史消息整合 LCEL

```python
from langchain_core.runnables.history import RunnableWithMessageHistory  

llm = ChatOpenAI(  
    model="deepseek-v3",  
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  
    openai_api_key=load_key("BAILIAN_API_KEY"),  
) 

runnable = RunnableWithMessageHistory(  
    llm,  
    get_session_history=lambda: history,    # 获取会话历史  
) 

# 清除历史聊天记录
# history.clear()
# 之后的每次聊天都会自动带上Redis中的记录
runnable.invoke("重复回答")


# 构建问答链
prompt_template = ChatPromptTemplate.from_messages([  
    ("user", "{text}")  
])

chain = prompt_template | llm | parser
runnable = RunnableWithMessageHistory(  
    chain,  
    get_session_history=lambda: history,    # 获取会话历史  
) 
runnable.invoke("text": "重复回答")
```

## 使用 Tools 机制 Function Calling

通过调用外部 API 接口，获取外部数据，然后让大模型再使用这些数据输出期望的内容。

> https://python.langchain.com/docs/integrations/chat/

### 原生 OpenAI 函数调用

```python
import json
from openai import OpenAI

client = OpenAI()

# 1. 定义本地函数
def get_current_weather(location, unit="celsius"):
    """模拟获取天气信息的函数"""
    # 实际应用中这里会调用真实的天气API
    weather_info = {
        "location": location,
        "temperature": 22 if unit == "celsius" else 72,
        "unit": unit,
        "description": "晴朗"
    }
    return json.dumps(weather_info)

def get_stock_price(symbol):
    """模拟获取股票价格的函数"""
    # 模拟股票数据
    stock_data = {
        "symbol": symbol,
        "price": 150.25,
        "change": "+1.5%"
    }
    return json.dumps(stock_data)

# 2. 定义可用的函数列表
functions = [
    {
        "name": "get_current_weather",
        "description": "获取指定地点的当前天气信息",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {	# 参数1
                    "type": "string",
                    "description": "城市名，例如：北京、上海"
                },
                "unit": {	# 参数2
                    "type": "string",
                    "enum": ["celsius", "fahrenheit"]	# 可选值
                }
            },
            "required": ["location"]	# 必须的参数
        }
    },
    {
        "name": "get_stock_price",
        "description": "获取指定股票代码的当前价格",
        "parameters": {
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "股票代码，例如：AAPL、GOOGL"
                }
            },
            "required": ["symbol"]
        }
    }
]

# 3. 主要的函数调用处理逻辑
def run_conversation():
    # 用户查询
    messages = [
        {"role": "user", "content": "今天北京的天气怎么样？"}
    ]
    
    # 第一次调用：让模型决定是否需要调用函数
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages,
        functions=functions,
        function_call="auto"  # auto表示让模型自动决定
    )
    
    message = response.choices[0].message
    
    # 4. 检查模型是否需要调用函数
    if message.function_call:
        # 提取函数名和参数
        function_name = message.function_call.name
        function_args = json.loads(message.function_call.arguments)
        
        print(f"模型决定调用函数: {function_name}")
        print(f"函数参数: {function_args}")
        
        # 5. 根据函数名调用相应的本地函数
        if function_name == "get_current_weather":
            function_response = get_current_weather(
                location=function_args.get("location"),
                unit=function_args.get("unit", "celsius")
            )
        elif function_name == "get_stock_price":
            function_response = get_stock_price(
                symbol=function_args.get("symbol")
            )
        
        print(f"函数返回结果: {function_response}")
        
        # 6. 将函数调用结果添加到消息历史中
        messages.append(message)  # 添加模型的函数调用请求
        messages.append({
            "role": "function",
            "name": function_name,
            "content": function_response
        })
        
        # 7. 第二次调用：让模型基于函数结果生成自然语言回复
        second_response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages
        )
        
        return second_response.choices[0].message.content
    else:
        # 如果不需要调用函数，直接返回模型回复
        return message.content

# 运行示例
if __name__ == "__main__":
    result = run_conversation()
    print("最终回答:", result)

```

- 用JSON格式详细描述每个函数的名称、功能描述和参数规范
- 包括参数类型、是否必需等信息，让大模型能够理解如何调用

- 第一次调用：发送用户问题给模型，模型决定是否需要调用函数
- 函数调用判断：检查模型响应中是否包含 function_call
- 本地函数执行：根据模型返回的函数名和参数，在本地执行相应函数
- 结果回传：将函数执行结果作为新的消息发送给模型
- 第二次调用：模型基于函数结果生成最终的自然语言回答

### 手动模拟 Agent 工具调用

> 半自动工具调用，需要手动管理消息列表和调用流程

在与大模型聊天的过程中告诉模型本地应用能提供哪些工具来使用。

示例：大模型获取当前日期

```python
import datetime  
from langchain.tools import tool  
from langchain_openai import ChatOpenAI  
from config.load_key import load_key  
  
llm = ChatOpenAI(  
    model="deepseek-v3",  
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  
    openai_api_key=load_key("BAILIAN_API_KEY"),  
)  

# 定义工具，注意要添加注释
@tool  
def get_current_date():  
    """获取今天日期"""  
    return datetime.datetime.today().strftime("%Y-%m-%d")  

# 大模型绑定工具
llm_with_tools = llm.bind_tools([get_current_date])  

# 把所有的消息存到一起
query = "今天是几号"  
messages = [HumanMessage(query)]  

# 询问大模型，模型会判断需要调用的工具，并返回一个调用工具的请求
# 第一次访问大模型返回的结果
# 调用带有工具的模型，尝试让模型决定是否需要调用工具
ai_msg = llm_with_tools.invoke(messages)  

# 打印输出中的工具调用
print(ai_msg.tool_calls) 
# [{'name': 'get_current_date', 'args': {}, 'id': 'call_792f20593342411da440e7', 'type': 'tool_call'}]

### 回传 Function Call 的结果 ###

# 模型输出添加到消息列表中，用于后续使用
messages.append(ai_msg)   

# 创建可用工具的字典映射，方便根据工具名称查找对应工具函数
all_tools = {"get_current_date": get_current_date}  


# 判断模型是否调用了本地工具
if ai_msg.tool_calls:  
    for tool_call in ai_msg.tool_calls:  
    	# 从工具字典中取出对应的工具函数
        selected_tool = all_tools[tool_call["name"].lower()]  
        # 调用工具函数并传入参数
        tool_msg = selected_tool.invoke(tool_call)  
        # 将工具返回的结果添加到消息列表
        messages.append(tool_msg)  
        
# 使用更新后的消息列表再次调用模型，获取最终回答
print(llm_with_tools.invoke(messages).content)
# 今天是2025年7月20号
```

> 模型第一次会返回一个带有 tool_calls 属性的 ai_msg ，即需要调用的工具。随后再执行对应的工具方法，将执行结果和之前的消息一起传递给大模型，模型综合工具给出答案。

#### 自定义工具名称

```python
# 若不指定参数，则使用默认的方法名作为工具名
@tool("get_current_date")
def get_current_date():
	"""获取今天的日期"""
	return datetime.datetime.today().strftime("%Y-%m-%d") 
```

#### 自定义工具描述

该描述是给大模型用的，模型会根据该描述来判断是否需要调用这个工具。描述信息可以直接添加注释，也可以用`@tool`装饰器的参数来定制。定义工具时，除了需要定义工具的描述，还可以定义参数的描述，模型也可以通过参数的描述来判断如何调用该工具。

```python 
from langchain.tools import tool  
from langchain_openai import ChatOpenAI  
from config.load_key import load_key  
  
llm = ChatOpenAI(  
    model="deepseek-v3",  
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  
    openai_api_key=load_key("BAILIAN_API_KEY"),  
)  
  
# 定义工具，注意要添加注释
@tool(description="获取某个城市的天气")  
def get_city_weather(city: str):  
    """获取某个城市的天气  
    Args:        
    	city: 具体城市  
    """    
    return "城市" + city + "今天天气不错"  
  
# 大模型绑定工具
llm_with_tools = llm.bind_tools([get_city_weather])  

# 工具容器
all_tools = {"get_city_weather": get_city_weather}  

# 把所有消息存到一起
query = "西安什么天气"  
messages = [query]  

# 询问大模型，模型会判断需要调用的工具，并返回一个调用工具的请求
# 第一次访问大模型返回的结果
ai_msg = llm_with_tools.invoke(messages)  
messages.append(ai_msg)  

# 打印需要调用的工具
print(ai_msg.tool_calls) 
# [{'name': 'get_city_weather', 'args': {'city': '西安'}, 'id': 'call_b2b525d089ae40f2b3e5c4', 'type': 'tool_call'}]

# 调用本地工具
if ai_msg.tool_calls:  
    for tool_call in ai_msg.tool_calls:  
        selected_tool = all_tools[tool_call["name"].lower()]  
        tool_msg = selected_tool.invoke(tool_call)  
        messages.append(tool_msg)  
# 第二次返回的结果
print(llm_with_tools.invoke(messages).content)
# 西安今天的天气不错。
```

#### 深度定制工具

`StructuredTool.from_function` 来结构化定制工具，其比 `@tools` 具有更多的属性配置。

```python
from langchain_openai import ChatOpenAI  
from langchain_core.tools import StructuredTool  
from config.load_key import load_key  
  
llm = ChatOpenAI(  
    model="deepseek-v3",  
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  
    openai_api_key=load_key("BAILIAN_API_KEY"),  
)  
  
  
def bad_city_weather(city: str):  
    """获取某个城市的天气  
    Args:        
    	city: 具体城市  
    """    
    return "城市" + city + "今天天气不错"  
  
#定义工具，该方法有更多的定制参数
weatherTool = StructuredTool.from_function(
	func=bad_city_weather, 
	description="获取某个城市的天气", 
	name="bad_city_weather"
)  
  
all_tools = {"bad_city_weather": weatherTool}  
llm_with_tools = llm.bind_tools([weatherTool])  

# 把所有消息存到一起
query = "西安什么天气"  
messages = [query]  

# 第一次访问大模型返回的结果
ai_msg = llm_with_tools.invoke(messages)  
messages.append(ai_msg)  
  
print(ai_msg.tool_calls)  
# [{'name': 'bad_city_weather', 'args': {'city': '西安'}, 'id': 'call_f0ac7cfd421b488a829585', 'type': 'tool_call'}]

# 调用本地工具
if ai_msg.tool_calls:  
    for tool_call in ai_msg.tool_calls:  
        selected_tool = all_tools[tool_call["name"].lower()]  
        tool_msg = selected_tool.invoke(tool_call)  
        messages.append(tool_msg)  
# 第二次返回的结果
print(llm_with_tools.invoke(messages).content)
# 西安今天的天气不错。
```

#### 结合大模型定制工具

LangChain 允许将一个接收字符串或字典作为参数的 Runnable 实例直接转换成一个工具。

> langchain 0.3 版本测试阶段

```python
import datetime  
from langchain_openai import ChatOpenAI  
from langchain_core.output_parsers import StrOutputParser  
from langchain_core.prompts.chat import ChatPromptTemplate  
from config.load_key import load_key  
  
llm = ChatOpenAI(  
    model="deepseek-v3",  
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  
    openai_api_key=load_key("BAILIAN_API_KEY"),  
)  

# LCEL 定制一个chain
prompt = ChatPromptTemplate.from_messages([  
    ("human", "你好，请用下面这种语言回答我的问题：{language}。")  
])  

parser = StrOutputParser()  

chain = prompt | llm | parser  
  
# 将chain转换为tool  
as_tool = chain.as_tool(
	name="translatetool", 
	description="翻译工具"
)  
  
all_tools = {"translatetool": as_tool}  
print(as_tool.args)  
# 绑定工具  
llm_with_tools = llm.bind_tools([as_tool])  
  
query = "好好学习，天天向上"  
messages = [query]  
  
ai_msg = llm_with_tools.invoke(messages)  
messages.append(ai_msg)  
print(ai_msg.tool_calls)  

if ai_msg.tool_calls:  
    for tool_call in ai_msg.tool_calls:  
        selected_tool = all_tools[tool_call["name"].lower()]  
        tool_msg = selected_tool.invoke(tool_call)  
        messages.append(tool_msg)  
print(llm_with_tools.invoke(messages).content)
# "好好学习，天天向上" 的英文翻译是 "Study hard and make progress every day."
```


> LangChain 提供的工具： https://python.langchain.com/docs/integrations/tools/

### Agent 调用工具

> 全自动工具调用，Agent 自动决定何时调用工具及如何处理结果

简化上面自己判定并调用 tool_call ，保存历史信息的操作。

```python
from langchain.tools import tool    
from langchain.agents import initialize_agent, AgentType  
from langchain_openai import ChatOpenAI    
from config.load_key import load_key    
    
llm = ChatOpenAI(    
    model="deepseek-v3",    
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",    
    openai_api_key=load_key("BAILIAN_API_KEY"),    
)    
    
# 定义工具，注意要添加注释  
@tool(description="获取某个城市的天气")    
def get_city_weather(city: str):    
    """获取某个城市的天气  
    Args:        
    	city: 具体城市      
    """      
return "城市" + city + "今天天气不错"    
    
# 初始化代理  
# 注意：这种方式可以用，但建议弃用（方便快捷但灵活性差）
agent = initialize_agent( 
    tools=[get_city_weather],  
    llm=llm,  
    agent=AgentType.OPENAI_FUNCTIONS,  # 指定代理的类型。这里使用的是OPENAI_FUNCTIONS类型，表示代理会以OpenAI函数调用的方式与模型交互。
    verbose=True,  # True在控制台输出代理执行过程的详细日志信息
)  
  
query = "西安什么天气"  
response = agent.invoke(query)  
print(response)
```

该智能体会在回答问题之前尝试进行推理。它会判断是否需要调用工具，若需要则调用，随后根据其返回结果，重新生成问题，直到得到一个答案为止。

#### 示例 new 

```python
from langchain_openai import ChatOpenAI  
from langchain import hub  
from langchain_tavily import TavilySearch  
# from langchain_community.tools.tavily_search import TavilySearchResults 弃用  
from langchain.agents import create_openai_functions_agent  
from langchain.agents import AgentExecutor  
  
# 加载环境变量.env文件  
from dotenv import load_dotenv  
  
load_dotenv()  
  
# 初始化大模型  
# llm = ChatOpenAI(model="gpt-4o", temperature=0)  
  
llm = ChatOpenAI(  
    temperature=0.95,  
    model="qwen-plus",  
    openai_api_key='sk-31bb7a65dd4047aba9b14a95c08be52c',  
    openai_api_base="https://dashscope.aliyuncs.com/compatible-mode/v1"  
)  
  
# 添加工具  
search = TavilySearch()  # 网络搜索工具  
# search = TavilySearchResults()  
tools = [search]  
  
# LangChain Hub的预定义提示词模版，模板专为OpenAI函数调用风格的Agent设计  
prompt = hub.pull("hwchase17/openai-functions-agent")  
  
# 当然也可以自己定义模版  
'''  
custom_prompt = ChatPromptTemplate.from_messages([  
    ("system", """你是一个 helpful 的 AI 助手，能够使用可用的工具来帮助用户解决问题。  
  
你可以使用以下工具：  
{tools}  
  
请根据用户的输入决定是否需要使用工具，以及使用哪个工具。"""),  
    ("user", "{input}"),    MessagesPlaceholder(variable_name="agent_scratchpad")  # 用于存储中间步骤  
])  
'''  
  
print(prompt)  
  
# 创建基于函数调用的agent，将agent和工具结合起来  
agent = create_openai_functions_agent(llm, tools, prompt)  
  
# 管理agent执行流程，将  
agent_executor = AgentExecutor(agent=agent, tools=tools,  
                               verbose=True,  # 显示详细过程  
                               handle_parsing_errors=True  # 处理解析错误  
                               )  
# 执行  
agent_executor.invoke({"input": "目前市场上苹果手机16的各个型号的售价是多少？"})  

# 若是存在多轮历史对话，可添加
res = agent_executor.invoke({"input": "你好？我丢雷老牟啊~"})  
chat_history = []
chat_history.append(HumanMessage(content=res['input']))
chat_history.append(AIMessage(content=res['output']))
agent_executor.invoke(
	{
		"input": "我丢什么啊？",
        "chat_history": chat_history
    }
)
# 答：雷老牟(bushi~
```

```python
# 另一种添加工具的方式
from langchain_core.tools import Tool
tools = [Tool(
             name="func01",
             func=func01,
             description="工具函数描述01",
             args={"参数01": "参数描述01"}
         ),
         Tool(
             name="func02,
             func=func02,
             description="工具函数描述02",
             args={"参数02": "参数描述02"}
         )
         ]
# 工具调用和上面的方式一样
# agent = create_openai_functions_agent...（直接匹配函数调用）
# agent = create_self_ask_with_search_agent...（主动提问获取信息）
# agent = create_react_agent...（推理+行动循环）

# 工具灵活使用，可以在工具函数中调用外部API工具，再用agent调用该工具函数~
```

## 使用向量数据库

> LangChain 支持的向量数据库： https://python.langchain.com/docs/integrations/vectorstores/

示例：以 Redis 向量数据库为例

```python
# embedding 模型
from langchain_community.embeddings import DashScopeEmbeddings  
  
embedding_model = DashScopeEmbeddings(  
    model="text-embedding-v1",  
)

redis_url = "redis://localhost:6379"  
  
import redis  
  
redis_client = redis.from_url(redis_url)  
print(redis_client.ping())  # 测试
  
from langchain_redis import RedisConfig, RedisVectorStore  

# Redis 配置对象
config = RedisConfig(  
    index_name="fruit",  # 本次存储指定索引名
    redis_url=redis_url,  # 指定Redis连接
)  

# Redis向量实例，用于向量存储和检索
vector_store = RedisVectorStore(embedding_model, config=config)  

# 文本添加进向量数据库
vector_store.add_texts(["香蕉好哇", "苹果还行", "西瓜又大又圆"])  

# 进行相似性搜索，返回匹配的两个结果
scored_results = vector_store.similarity_search_with_score("哪个水果最香", k=2)  

# 遍历搜索结果并打印
for doc, score in scored_results:  
    print(f"{doc.page_content} - {score}")

# 可通过Retriver来简化复杂的检索过程
# 构建检索器，类似为similarity，检索的文档个数为2  
retriver = vector_store.as_retriever(search_type="similarity", search_kwargs={"k": 2})  
retriver.invoke("哪个水果最香")
```

### 链式使用 Retriver

```python
from langchain_core.prompts import ChatPromptTemplate  
  
# 创建提示模版  
prompt = ChatPromptTemplate.from_messages([  
    ("human", "请根据以下的上下文，回答问题：{question}"),  
])  
  
  
# 格式转换函数，prompt.invoke返回PromptValue对象，retriver.invoke需要转换成str  
def format_prompt_value(prompt_value):  
    return prompt_value.to_string()  
  
  
# 链式连接检索器和提示模版  
chain = prompt | format_prompt_value | retriver  
# 调用链并传入用户问题  
documents = chain.invoke({"question": "哪个水果最香"})  
for doc in documents:  
    print(doc.page_content)
```

## 构建RAG问答流程

### 索引构建

![[attachments/data_connection.jpg]]

主要对相关文档处理，形成知识库，便于后续检索

![[attachments/20250721.png]]

加载并解析文档

LangChain 中很多的 DocumentLoader 工具，可以加载各种文档格式的数据。

```python
# 加载pdf文档
from langchain_community.document_loaders import PyMuPDFLoader  
  
loader = PyMuPDFLoader("./data/deepseek-v3-1-4.pdf") 

# 使用 loader 加载并分割 PDF 文档，将结果存储在 pages 变量中
# load_and_split() 方法会将 PDF 的每一页作为单独的文档对象返回
pages = loader.load_and_split()  
# 打印第一页（索引为 0）的内容
# page_content 属性包含该页的实际文本内容
print(pages[0].page_content)

# 文档分割
from langchain_text_splitters import RecursiveCharacterTextSplitter  
  
text_splitter = RecursiveCharacterTextSplitter(  
    chunk_size=512,  
    chunk_overlap=200,   
    length_function=len,  
    add_start_index=True,  
)  
  
# 使用文本分割器对第一页PDF内容进行分割，创建文档对象列表  
paragraphs = text_splitter.create_documents([pages[0].page_content])  
# 遍历分割后的文档段落  
for para in paragraphs:  
    # 打印每个段落的内容  
    print(para.page_content)  
    print('-------')
```

```python
# 加载txt文档
from langchain_community.document_loaders import TextLoader 

loader = TextLoader("./meituan-questions.txt", encoding="utf-8")  
documents = loader.load()  
print(documents)


# 递归的加载文件夹中的文档
from langchain_community.document_loaders import DirectoryLoader  
  
directLoader = DirectoryLoader("./resource", glob="**/*.txt", loader_cls=TextLoader, show_progress=True)  
directLoader.load()
```

切分内容

将整体的文件切分为独立的知识片段。

```python
from langchain_text_splitters import CharacterTextSplitter  
  
# 切分文档  
# （相比于上面用到的RecursiveCharacterTextSplitter分割方式更加简单粗暴）
text_splitter = CharacterTextSplitter(chunk_size=512, chunk_overlap=0, separator="\n\n", keep_separator=True)  
  
segments = text_splitter.split_documents(documents)  
print(len(segments))  
for segment in segments:  
    print(segment.page_content)
```

可以自定义的切分

```python
import re  
  
# 自行切分文档  
texts = re.split(r"\n\n", documents[0].page_content)  
segments = text_splitter.split_text(documents[0].page_content)  
  
# 将文档片段转换为document对象  
segment_documents = text_splitter.create_documents(segments)  
print(len(segment_documents))  
for segment in segment_documents:  
    print(segment.page_content)
```

文本向量化（和上面向量数据库部分的操作一样）

```python
# embedding 模型  
from langchain_community.embeddings import DashScopeEmbeddings    
    
embedding_model = DashScopeEmbeddings(    
    model="text-embedding-v1",    
)  
  
redis_url = "redis://localhost:6379"    
    
from langchain_redis import RedisConfig, RedisVectorStore    
# Redis 配置对象  
config = RedisConfig(    
    index_name="meituan-index",  # 本次存储指定索引名  
    redis_url=redis_url,  # 指定Redis连接  
)    
  
# Redis向量实例，用于向量存储和检索  
vector_store = RedisVectorStore(embedding_model, config=config)    
  
# 文本添加进向量数据库  
vector_store.add_documents(segment_documents)
```

### 检索增强阶段

用户提出的问题，到向量数据库中检索出关联性较强的 Segment ，再将其和用户的问题整理成完整的 Prompt 发给大模型整合输出。

![[attachments/20250721-1.png]]

检索相关信息

```python
query="在线支付取消订单后钱怎么返还"  
  
retriever = vector_store.as_retriever()  
relative_segments = retriever.invoke(query, k=5)  
print(relative_segments)
```

构建提示词

```python
# eg: 1
prompt_template = ChatPromptTemplate.from_messages([  
    ("user", """你是一个答疑机器人，你的任务是根据下述给定的已知信息回答用户的问题。  
    已知信息：{content}  
    用户问题：{question}  
    如果已知信息不包含用户问题的答案，或者已知信息不足以回答用户的问题，请直接回复“我无法回答您的问题”。  
    请不要输出已知信息中不包含的信息或答案。    请用中文回答用户问题。""")  
])  
  
text = []  
  
for segment in relative_segments:  
    text.append(segment.page_content)  
  
prompt = prompt_template.invoke({"context": text, "question": query})  
print(prompt)  

# eg: 2
prompt_template = ChatPromptTemplate.from_messages([  
    ("system", "Translate the following from English into {language}"),  
    ("user", "{text}")  
])  
prompt = prompt_template.invoke({"text": "I love programming.", "language": "Spanish"})  
print(prompt)
```

调用模型回复

```python
response = llm.invoke(prompt)
print(response.content)
```

也可以通过 LCEL 语法链来实现

```python
# 收集document内容  
def collect_documents(segments):  
    text = []  
     # 遍历每个文档片段
    for segment in segments:  
    	# 提取片段的内容并添加到列表中
        text.append(segment.content)  
    return text  
  
  
# retriever.invoke(query, k=5)
# itemgetter 用于从字典中提取指定键的值
from operator import itemgetter  

# 构建一个复杂的处理链（LCEL表达式）
chain = (
		# 输入映射部分：定义如何处理输入数据
		{  
			# context 字段的处理流程：  
			# 1. 从输入字典中提取 "question" 键的值  
			# 2. 将问题传递给 retriever（检索器）进行相似性检索  
			# 3. 将检索结果传递给 collect_documents 函数收集内容
             "context": itemgetter("question") | retriever | collect_documents,  
            # question 字段的处理流程：
        	# 直接从输入字典中提取 "question" 键的值
             "question": itemgetter("question")
        }  
        # 将处理后的字典传递给提示模板
         | prompt_template  
        # 将格式化后的提示传递给语言模型
         | llm  
        # 将模型输出解析为字符串
         | StrOutputParser()  
         )  
response = chain.invoke({"question": query})  
print(response)
```
