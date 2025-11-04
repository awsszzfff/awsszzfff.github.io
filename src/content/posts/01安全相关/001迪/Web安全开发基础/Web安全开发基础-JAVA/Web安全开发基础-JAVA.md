---
title: "Web安全开发基础-JAVA"
date: 2025-09-17
tags:
  - Others
categories:
  - Others
description: None
---
## Web服务-Servlet

![[attachments/20250917.png]]

![[attachments/20250917-1.png]]

![[attachments/20250917-2.png]]

> - https://mp.weixin.qq.com/s/c_4fOTBKDcByv8MZ9ayaRg
> - https://blog.csdn.net/qq_52173163/article/details/121110753

- 过滤器
- 监听器 https://blog.csdn.net/qq_52797170/article/details/124023760

- 内存马 https://mp.weixin.qq.com/s/hev4G1FivLtqKjt0VhHKmw

## 数据库连接

Maven配置 https://blog.csdn.net/cxy2002cxy/article/details/144809310

### JDBC 

https://www.jianshu.com/p/ed1a59750127

pom.xml 依赖下载与引用 https://mvnrepository.com/

```java
// 2、注册数据库驱动
Class.forName("com.mysql.jdbc.Driver");
// 3、建立数据库连接
String url ="jdbc:mysql://localhost:3306/phpstudy";
Connection connection=DriverManager.getConnection(url,"root","123456");
// 4、创建Statement执行SQL
Statement statement= connection.createStatement();
ResultSet resultSet = statement.executeQuery(sql);
// 5、结果ResultSet进行提取
while (resultSet.next()){
    int id = resultSet.getInt("id");
    String page_title = resultSet.getString("page_title");
    .......
}
```


- 安全写法(预编译 PreparedStatement)： `"select * from admin where id=?"`
- 不安全写法(拼接)： `"select * from admin where id="+id`（存在注入漏洞）

### Hibernate

（依赖 hibernate-core，mysql-connector-java）

- 安全写法：`String hql = "FROM User WHERE username=:username";`
- 不安全写法：`String hql = "FROM User WHERE username='"+username+"'";`

### MyBatis

mybatis，mysql-connector-java

- 安全写法： `select * from admin where id = #{id}`
- 不安全写法：`select * from admin where id = ${id}`

## 反射&类加载&构造方法等

![[attachments/20250917-3.png]]

![[attachments/20250917-4.png]]

![[attachments/20250917-5.png]]

![[attachments/20250917-6.png]]

java 反射 https://xz.aliyun.com/t/9117

在**运行时**获得程序或程序集中每一个类型的成员和成员的信息，从而**动态的创建、修改、调用、获取其属性**，而不需要事先知道运行的对象是谁。划重点：在运行时而不是编译时。（不改变原有代码逻辑，自行运行的时候动态创建和编译即可）

- 反射机制开发应用场景
	- Spring框架的IOC基于反射创建对象和设置依赖属性。
	- SpringMVC的请求调用对应方法，也是通过反射。
	- JDBC的 Class#forName(String className) 方法，也是使用反射。
- 安全应用场景
	- 构造利用链，触发命令执行；
	- 反序列化中的利用链构造；
	- 动态获取或执行任意类中的属性或方法；
	- 动态代理的底层原理是反射技术；
	- rmi 反序列化也涉及到反射操作；

不安全的利用链 https://zhuanlan.zhihu.com/p/165273855

反序列化利用链 https://xz.aliyun.com/t/7031

安全应用案例-内存马技术 https://github.com/pen4uin/java-memshell-generator

