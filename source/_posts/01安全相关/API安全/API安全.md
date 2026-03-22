---
title: API安全
date: 2023-03-28
updated: 2024-08-09
tags:
  - 安全基础
categories:
  - 安全相关
description: API安全
draft: false
---
> https://github.com/arainho/awesome-api-security

## API 接口检测

根据不同接口的特征或依赖语言的不同判断接口类型

JS 中提取，枚举爆破以及响应提示信息来判断并获取 API 接口的信息

攻击/探测方式：

- 修改请求方法：OPTIONS、PUT、MOVE、DELETE 等上传恶意文件、修改页面等；
- 未授权访问 URL 路径；
- 构造/修改请求参数，遍历、重发；
- 对特殊参数，如 userid 等修改探测身份伪造/篡改未授权访问；
- 修改消息头/消息体（Hosts、Referer 等）；

## 不同 API 接口类型特征检测

示例

### RESTful API

使用标准 HTTP 方法，eg：

- `GET` - 获取数据（查看）
- `POST` - 创建数据（添加）
- `PUT` - 替换整个资源（全量更新）
- `PATCH` - 只更新部分内容（增量更新）
- `DELETE` - 删除数据（删除）
- `OPTIONS` - 询问服务器所支持的请求方式

以资源为导向，每个 URL 端点代表一个资源，eg：

- `GET /users` - 获取所有用户
- `GET /users/1` - 获取 ID 为 1 的用户
- `POST /users` - 创建新用户

### GraphQL

> https://graphql.cn/learn/introspection/
> https://mp.weixin.qq.com/s/gpm8w0HHW5wNKQLq4AtGyg
> https://blog.csdn.net/qq_61812944/category_12417979.html

相比上面每个端点一个资源，graphql 可以仅通过一个端点，传入一个结构化的接口查询，服务器相对应的返回对应接口的数据，eg：

```graphql
# 客户端查询
query {
  user(id: 1) {
    name
    email
  }
}

# 服务器只返回：
{
  "data": {
    "user": {
      "name": "张三",
      "email": "xxx@example.com"
    }
  }
}
```

自省能力，GraphQL API 可以"自我描述"，客户端可以查询这个 API 有哪些类型、字段、方法。

```graphql
# 询问 API 有哪些类型
{
  __schema {
    types {
      name
    }
  }
}
```

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection

存在的安全问题

- 自省导致的模式泄露，`__schema` 查询获取存在的模式详细信息；
- 类型混淆， GraphQL 模式中存在多个具有相同名称但不同定义的类型，可能导致意外的数据访问；
- 字段枚举，枚举 API 字段以及关联关系；
- 敏感信息泄露，用户凭据、API 密钥、数据库结构等。

绕过自省方式：

- 特殊字符、空格、换行、逗号等字符
- 弱正则匹配，修改请求方式、请求类型绕过

数据库架构的 URL 编码查询

```graphql
# 数据包提交添加Payload内容
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}

query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
```

不同的 API 接口会对应不同的功能，意味着可以测试对应接口可能存在的漏洞，eg：xss、ssrf...

### SOAP API

基于 xml 格式进行数据传输。不依赖特定传输协议，可通过 HTTP、SMTP、TCP 等。

SOAP 服务通常提供 WSDL（Web Services Description Language） 文件，作为 xml 格式说明书（说明服务的方法、所需参数、返回数据类型）

判断方式：

- 数据包里面 xml 格式存在特征 soap 字符
- URL 后加?wsdl 能成功显示 xml 格式数据

```xml
<!-- eg： -->
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <!-- 可选的头部信息，如认证令牌 -->
    <auth:Token>abc123</auth:Token>
  </soap:Header>
  <soap:Body>
    <!-- 实际的请求/响应数据 -->
    <getUserRequest>
      <userId>123</userId>
    </getUserRequest>
  </soap:Body>
</soap:Envelope>
```

### Open API

eg：Swagger 将对应的 api 接口文件导入接口工具进行测试。

> 接口工具（Apifox、Postman 等） + 漏扫工具（Xray、AWVS 等）联动，更偏向于常规漏洞；但对于信息泄露、逻辑漏洞、403、参数需要人工添加特殊值。

## WebSocket API

全双工通信，建立在 TCP 之上，允许客户端和服务器之间建立持久连接，实现双向实时通信。

应用场景：需要进行实时通信及反馈的场景，网页聊天、共享文档、金融交易等

URL 格式：

-  `ws://` 类似与 http 使用明文传输，默认端口为 80

`ws://host[:port]path[?query]`

- `wss://` 类似于 https 使用 TLS 加密传输，默认端口为 443

`wss://host[:port]path[?query]`

处常规漏洞外，CSWSH（跨站点网站劫持，最为广泛的漏洞）类似于 CSRF，在没有验证请求源的情况下，任意来源可连接 WebSocket 服务器进行数据交互，攻击者构造恶意页面，诱导用户访问并借助身份信息与服务器建立连接。
