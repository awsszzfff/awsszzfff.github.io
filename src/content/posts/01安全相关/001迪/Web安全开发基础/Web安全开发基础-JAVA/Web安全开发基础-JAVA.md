---
title: Web安全开发基础-JAVA
date: 2025-09-17
tags:
  - 安全开发基础
categories:
  - 安全相关
description: Web安全开发基础-JAVA
---
## Web服务-Servlet

Servlet 生命周期

1. `init()`：初始化阶段，只被调用一次，Servlet 第一次创建时被调用；
2. `service()`：服务阶段，主要处理来自客户端的请求，根据 HTTP 请求类型来调用对应的方法（`doGet()`、`doPost()`、`doPut()` 等）；
3. `destroy()`：销毁阶段，只被调用一次，Servlet 生命期结束时被调用；一般在关闭系统时执行。

![[attachments/20250917.png]]

![[attachments/20250917-1.png]]

![[attachments/20250917-2.png]]

> - https://mp.weixin.qq.com/s/c_4fOTBKDcByv8MZ9ayaRg
> - https://blog.csdn.net/qq_52173163/article/details/121110753

pom.xml 配置 servlet 依赖

```xml
<dependency>  
    <groupId>javax.servlet</groupId>  
    <artifactId>javax.servlet-api</artifactId>  
    <version>3.1.0</version>  
    <scope>compile</scope>  
</dependency>
```

servlet 中需根据 URL 路径匹配映射到对应的 servlet 。web.xml 中注册 servlet（即路径映射类名，浏览器访问对应的路径实际访问的是哪个类）

```xml
<web-app>  
	<!-- 应用的显示名称 -->
    <display-name>Archetype Created Web Application</display-name>  
     <!-- 注册 Servlet：定义名称和对应的类 -->
    <servlet>        
	    <servlet-name>FirstServlet</servlet-name>  
	    <servlet-class>FirstServlet</servlet-class>  
    </servlet>   
    
    <!-- 映射 Servlet：将 URL 路径绑定到已注册的 Servlet --> 
    <servlet-mapping>        
	    <servlet-name>FirstServlet</servlet-name>  
	    <url-pattern>/FirstServlet</url-pattern>  
    </servlet-mapping>
</web-app>
```

- 过滤器 Filter ，常用于过滤一些字符编码、危险字符等，用来统一业务，防范 SQL 注入、XSS 等；
- 监听器 Listener ，主要做一些初始化内容（监听器在过滤器之前启动） https://blog.csdn.net/qq_52797170/article/details/124023760

- 内存马 https://mp.weixin.qq.com/s/hev4G1FivLtqKjt0VhHKmw

同样的需要在 web.xml 文件中配置过滤器、监听器等映射关系从而使其生效（或用`@WebFilter()` 注解的方式进行注册）。（程序执行访问 web.xml 文件从上到下，所以过滤器、监听器一般放在前面）

## JSP

基于 Java ，动态网页技术，JSP 标签在 HTML 页面中插入 Java 代码。

生命周期：编译阶段（解析 JSP 文件 -> 将 JSP 文件转为 Servlet -> 编译 Servlet）、初始化阶段、执行阶段、销毁阶段。

（SpringBoot 默认不引入 JSP 解析，需引入特定依赖，JSP 木马逐渐没落）

## Spring MVC

MVC 一种软件框架模式，即模型（Model）处理数据逻辑 、视图（View）信息显示、控制器（Controller）控制数据与用户交互。

控制器通常负责从视图读取数据，处理用户输入，并向模型发送数据，也可以从模型中读取数据，再发送给视图，由视图显示。

![[attachments/20251112.png]]

![[attachments/20251112-1.png]]

https://pdai.tech/md/spring/spring-x-framework-springmvc.html

https://pdai.tech/files/kaitao-springMVC.pdf

Spring,Spring MVC及Spring Boot区别： https://www.jianshu.com/p/42620a0a2c33

## Spring Boot



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

---

服务器配置修改为： https://start.aliyun.com

