---
title: Web安全开发基础-JAVA
date: 2025-09-17
tags:
  - 安全开发基础
categories:
  - 安全相关
description: Web安全开发基础-JAVA
---
![[attachments/20251113.png]]

> https://www.javasec.org/
> 
> https://mp.weixin.qq.com/s/c_4fOTBKDcByv8MZ9ayaRg

## Web 服务-Servlet

Servlet 生命周期

1. `init()`：初始化阶段，只被调用一次，Servlet 第一次创建时被调用；
2. `service()`：服务阶段，主要处理来自客户端的请求，根据 HTTP 请求类型来调用对应的方法（`doGet()`、`doPost()`、`doPut()` 等）；
3. `destroy()`：销毁阶段，只被调用一次，Servlet 生命期结束时被调用；一般在关闭系统时执行。

![[attachments/20250917.png]]

![[attachments/20250917-1.png]]

![[attachments/20250917-2.png]]

> https://blog.csdn.net/qq_52173163/article/details/121110753

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

同样的需要在 web.xml 文件中配置过滤器、监听器等映射关系从而使其生效（或用 `@WebFilter()` 注解的方式进行注册）。（程序执行访问 web.xml 文件从上到下，所以过滤器、监听器一般放在前面）

## JSP

基于 Java ，动态网页技术，JSP 标签在 HTML 页面中插入 Java 代码。

生命周期：编译阶段（解析 JSP 文件 -> 将 JSP 文件转为 Servlet -> 编译 Servlet）、初始化阶段、执行阶段、销毁阶段。

（SpringBoot 默认不引入 JSP 解析，需引入特定依赖，JSP 木马逐渐没落）

## Spring MVC

MVC 一种软件框架模式，即模型（Model）处理数据逻辑、视图（View）信息显示、控制器（Controller）控制数据与用户交互。

控制器通常负责从视图读取数据，处理用户输入，并向模型发送数据，也可以从模型中读取数据，再发送给视图，由视图显示。

![[attachments/20251112.png]]

![[attachments/20251112-1.png]]

- DispatcherServlet（调度器 Servlet）接收客户端所有请求并将其分派给适当的处理程序（Controller）；
- HandlerMapping（处理程序映射）将请求映射到相应的处理程序（Controller）；
- HandlerAdapter（处理程序适配器）负责调用实际的处理程序（Controller）来处理请求，并将处理结果返回给 DispatcherServlet ；


> https://pdai.tech/md/spring/spring-x-framework-springmvc.html
> 
> https://pdai.tech/files/kaitao-springMVC.pdf

Spring,Spring MVC 及 Spring Boot 区别： https://www.jianshu.com/p/42620a0a2c33

> https://juejin.cn/post/6844903912034533383
> 
> https://potoyang.gitbook.io/spring-in-action-v5/

## 简单项目层级架构

**Controller → Service → Mapper → Entity** 经典四层结构

```txt
浏览器
   ↓ (HTTP GET /user/1)
Controller（UserController）
   ↓ 调用 userService.getUserById(1)
Service（UserServiceImpl）
   ↓ 调用 userMapper.findById(1)
Mapper（UserMapper + UserMapper.xml）
   ↓ 执行 SQL：SELECT * FROM user WHERE id = 1
数据库（MySQL / PostgreSQL 等）
   ↑ 返回结果集
Mapper → 将结果自动映射为 User 对象
   ↑ 返回 User 对象
Service → 可能做额外处理（如脱敏、组合数据）
   ↑ 返回处理后的 User
Controller → 将 User 转为 JSON 返回
   ↑
浏览器（收到 JSON 响应）
```

## Spring Boot

https://springdoc.cn/spring-boot/

## 模版引擎

### Thymeleaf

https://xz.aliyun.com/news/9962

### FreeMarker

https://mp.weixin.qq.com/s/TtNxfSYsB4HMEpW_OBniew

### Velocity

https://blog.csdn.net/2401_83799022/article/details/141600988

## Actuator 监控依赖

健康检查，审计，指标收集，HTTP 跟踪等，帮助监控和管理 Spring Boot 应用

![[attachments/20251128-1.png]]

安全问题 heapdump 泄露

SpringCloud Gateway RCE

https://www.cnblogs.com/qgg4588/p/18104875

接口依赖-Swagger

https://blog.csdn.net/lsqingfeng/article/details/123678701

自动化测试

应用接口泄露

未授权访问、信息泄露、文件上传等

打包部署 JAR&WAR https://mp.weixin.qq.com/s/HyqVt7EMFcuKXfiejtfleg

> 打包报错解决
> 
> https://blog.csdn.net/Mrzhuangr/article/details/124731024
> https://blog.csdn.net/wobenqingfeng/article/details/129914639

war 包

1. pom.xml 加入或修改：

`<packaging>war</packaging>`

2. 启动类里面加入配置：

```java
public class TestSwaggerDemoApplication extends SpringBootServletInitializer

@Override
protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {

	return builder.sources(TestSwaggerDemoApplication.class);
}
```

maven -> clean -> package

java -jar xxxxxx.jar

war 放置 tomcat 后启动

## 身份验证

身份验证的常见技术：

1. JWT
2. Shiro
3. Spring Security
4. OAuth 2.0
5. SSO
6. JAAS

JWT

![[attachments/20251128-2.png]]

https://mp.weixin.qq.com/s/xH_v825bNqDszwmMOe8CBw

SpringSecurity

https://mp.weixin.qq.com/s/5tj6O4TA04QWyWnsd-EmEA

https://mp.weixin.qq.com/s/M1FiPKJRAWgwaKCtyNW8eQ

## 文件操作

### 上传

Multipartfile

ServletFileUpload

### 读取

java.nio.file.Files

java.io.FileReader

java.io.BufferedReader

Scanner

RandomAccessFile 断点续传

commons-io

Files.readString

## 命令执行

java.lang.Runtime

java.lang.ProcessBuilder

java.lang.UNIXProcess/ProcessImpl

ProcessImpl 是更为底层的实现，Runtime 和 ProcessBuilder 执行命令实际上也是调用了 ProcessImpl 这个类；

```java
// 方法1
Process process = Runtime.getRuntime().exec("calc");

// 方法2
ProcessBuilder builder = new ProcessBuilder("calc");
Process process = builder.start();

// 方法3
String[] cmd = {"calc"};

// 1. 获取 ProcessImpl 类
Class<?> processImplClass = Class.forName("java.lang.ProcessImpl");

// 2. 获取私有的 start 方法（注意参数类型）
Method startMethod = processImplClass.getDeclaredMethod(
	"start",
	String[].class,   // 命令数组
	Map.class,        // 环境变量（null 表示继承当前环境）
	String.class,     // 工作目录（如 "."）
	ProcessBuilder.Redirect[].class, // 重定向（null 表示默认）
	boolean.class     // 是否 redirectErrorStream（false 即可）
);

// 3. 设置可访问（绕过 private 限制）
startMethod.setAccessible(true);

// 4. 调用方法（静态方法，第一个参数为 null）
Process process = (Process) startMethod.invoke(
	null,     // 静态方法，实例为 null
	cmd,      // 命令
	null,     // 环境变量
	".",      // 工作目录
	null,     // 重定向
	false     // 是否合并错误流
);
```

## 数据库连接

Maven 配置 https://blog.csdn.net/cxy2002cxy/article/details/144809310

### JDBC 

https://www.jianshu.com/p/ed1a59750127

pom.xml 依赖下载与引用 https://mvnrepository.com/

```java
// 2、注册数据库驱动
Class.forName("com.mysql.jdbc.Driver");
// 3、建立数据库连接
String url = "jdbc:mysql://localhost:3306/phpstudy";
Connection connection = DriverManager.getConnection(url,"root","123456");
// 4、创建Statement执行SQL
Statement statement= connection.createStatement();
ResultSet resultSet = statement.executeQuery(sql);
// 5、结果ResultSet进行提取
while (resultSet.next()){
    int id = resultSet.getInt("id");	// 获取对应的值
    String page_title = resultSet.getString("page_title");
    .......
}
```

- 安全写法(预编译 PreparedStatement)： `"select * from admin where id=?"`
- 不安全写法(拼接)： `"select * from admin where id=" + id`（存在注入漏洞）

### Hibernate

（pom.xml 引用依赖 hibernate-core，mysql-connector-java）

- 安全写法：`String hql = "FROM User WHERE username=:username";`
- 不安全写法：`String hql = "FROM User WHERE username='"+username+"'";`

### MyBatis

mybatis，mysql-connector-java

- 安全写法： `select * from admin where id = #{id}`
- 不安全写法：`select * from admin where id = ${id}`

上面两种都是用 xml 和实体类/对象之间的映射关系来进行数据库操作。

## 反射&类加载&构造方法等

java 反射 https://xz.aliyun.com/t/9117 、 https://www.zhihu.com/question/377483107

在**运行时**获得程序或程序集中每一个类型的成员和成员的信息，从而**动态的创建、修改、调用、获取其属性**，而不需要事先知道运行的对象是谁。划重点：在运行时而不是编译时。（不改变原有代码逻辑，自行运行的时候动态创建和编译即可）

- 反射机制开发应用场景
	- Spring 框架的 IOC 基于反射创建对象和设置依赖属性。
	- SpringMVC 的请求调用对应方法，也是通过反射。
	- JDBC 的 Class #forName (String className) 方法，也是使用反射。
- 安全应用场景
	- 构造利用链，触发命令执行；
	- 反序列化中的利用链构造；
	- 动态获取或执行任意类中的属性或方法；
	- 动态代理的底层原理是反射技术；
	- RMI 反序列化也涉及到反射操作；

![[attachments/20250917-3.png]]

### 利用反射获取对应类的几种方式

```java
import com.user.User;

public class GetClass {
    public static void main(String[] args) throws ClassNotFoundException {
        Class<?> aClass = Class.forName("com.user.User");
        System.out.println(aClass);

        User user = new User();
        Class<? extends User> aClass1 = user.getClass();
        System.out.println(aClass1);

        Class userClass = User.class;
        System.out.println(userClass);

        ClassLoader systemClassLoader = ClassLoader.getSystemClassLoader();
        Class<?> aClass2 = systemClassLoader.loadClass("com.user.User");
        System.out.println(aClass2);
    }
}
```

### 获取成员变量

![[attachments/20250917-4.png]]

### 获取成员方法

![[attachments/20250917-5.png]]

### 获取构造方法

![[attachments/20250917-6.png]]

获取对应的方法后，通过 newInstance() 来实例化对象，invoke() 传参并执行。

### 利用反射进行命令执行

```java
// 利用反射进行命令执行
Class<?> clazz = Class.forName("java.lang.Runtime");  
Method execMethod = clazz.getMethod("exec", String.class);  
Method getRuntimeMethod = clazz.getMethod("getRuntime");  
Object runtime = getRuntimeMethod.invoke(null);  
execMethod.invoke(runtime, "calc.exe");


Class<?> clazz = Class.forName("java.lang.Runtime");  
Constructor m = clazz.getDeclaredConstructor();  
System.out.println(m);  
m.setAccessible(true);  
Method c1 = clazz.getMethod("exec", String.class);  
System.out.println(c1);  
c1.invoke(m.newInstance(), "calc.exe");


Class<?> clazz = Class.forName("java.lang.ProcessBuilder");  
Object object = clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe"));  
clazz.getMethod("start").invoke(object, null);
// 还有上面命令执行中提到的一种方法
```

不安全的利用链 https://zhuanlan.zhihu.com/p/165273855

反序列化利用链 https://xz.aliyun.com/t/7031

安全应用案例-内存马技术 https://github.com/pen4uin/java-memshell-generator

## 序列化与反序列化

> https://xz.aliyun.com/news/12113

序列化 ID

transient 关键字阻止指定字段序列化

readObject 方法，在反序列化过程中，该方法会在默认的反序列化机制执行之前被调用，允许在对象反序列化时执行一些自定义的逻辑。（重写 readObject 方法）

### 1. 常见的创建的序列化和反序列化协议

• JAVA 内置的 writeObject()/readObject()
• JAVA 内置的 XMLDecoder()/XMLEncoder
• XStream
• SnakeYaml
• FastJson
• Jackson

### 2. 反序列化安全问题

JAVA 内置 writeObject()/readObject() 内置原生写法：

- `writeObject()`：主要用于将 Java 对象序列化为字节流并写入输出流
- `readObject()`：主要用于从输入流中读取字节序列反序列化为 Java 对象
- `FileInputStream`：其主要作用是从文件读取字节数据
- `FileOutputStream`：其主要作用是将字节数据写入文件
- `ObjectInputStream`：用于从输入流中读取对象，实现对象的反序列化操作
- `ObjectOutputStream`：用于将对象并写入输出流的类，实现对象的序列化操作

利用：

• 序列化的对象有没有重写 readObject 方法（危险代码）
• 序列化的对象有没有被输出就会调用 toString 方法（危险代码）
• 其他类的 readObject 或 toString 方法（反序列化类可控）

### 3. 反序列化利用链

- 入口类的 readObject 直接调用危险方法
- 入口参数中包含可控类，该类有危险方法，readObject 时调用
- 入口类参数包含可控类，该类又调用其他有危险方法类，readObject 调用
- 构造函数/静态代码块等类加载时隐式执行

### 4. 反序列化利用条件：

- 可控的输入变量进行了反序列化操作
- 实现了 Serializable 或者 Externalizable 接口的类的对象
- 能找到调用方法的危险代码或间接的利用链引发（依赖链）

![[attachments/20251128.png]]

> https://mp.weixin.qq.com/s/R3c5538ZML2yCF9pYUky6g
> 
> https://mp.weixin.qq.com/s/t8sjv0Zg8_KMjuW4t-bE-w

搞清楚入口类，需要修改的值，需要传递的值

## RMI

远程方法调用，允许在不同的 JVM 之间通讯。

https://paper.seebug.org/1012/

![[attachments/20251120.png]]

> https://paper.seebug.org/1091/
> 
> https://y4er.com/posts/java-rmi/
> 
> https://goodapple.top/archives/321
> 
> https://paper.seebug.org/1251/

## JNDI

![[attachments/20260113.png]]

JNDI 提供了一套标准接口，让 Java 程序可以通过一个**名称**（Name），来查找并获取到实际的**资源**（Object）。主要目的是实现**解耦**（Decoupling）。它将资源的**配置细节**（例如，数据库的 URL、用户名、密码）从应用程序的**核心代码**中分离出来。

> https://blog.csdn.net/dupei/article/details/120534024

JNDI 不仅可以查找本地资源，还可以查找远程服务，例如使用 **LDAP**（轻量级目录访问协议）或 **RMI**（远程方法调用）协议。

> - Log4j https://mp.weixin.qq.com/s/95Jxj3R9q95CFhCn86IiYA
> - Fastjson https://mp.weixin.qq.com/s/EPdNElXPcZd5wEmQqAhFiQ
> - XStream https://mp.weixin.qq.com/s/M_oQyZYQEFu0nbG-IpJt_A
> - Shiro https://mp.weixin.qq.com/s/kmGcrVmaLi0Db_jwKKNXag
> - SnakeYaml https://www.cnblogs.com/F12-blog/p/18151239

## 动态代理

在程序运行时，自动生成一个**代理对象**，这个代理对象会“拦截”你对目标对象的调用，并在调用前后或调用过程中添加额外的逻辑。

```java file:Calculator.java
public interface Calculator {  
    int add(int a, int b);  
    int sub(int a, int b);  
}
```

```java file:RealCalculator.java
public class RealCalculator implements Calculator {  
    @Override  
    public int add(int a, int b) {  
        // 这是核心业务逻辑  
        return a + b;  
    }  
  
    @Override  
    public int sub(int a, int b) {  
        // 这是核心业务逻辑  
        return a - b;  
    }  
}
```

```java file:LogHandler.java
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Method;  
  
public class LogHandler implements InvocationHandler {  
  
    // 持有目标对象（RealCalculator）的引用  
    private Object target;  
  
    public LogHandler(Object target) {  
        this.target = target;  
    }  
  
    /**  
     * @param proxy  自动生成的代理对象实例 (一般不直接使用)  
     * @param method 正在被调用的方法 (如 add, sub)  
     * @param args   方法的参数 (如 a, b)  
     * @return 方法的返回值  
     */  
    @Override  
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {  
  
        // --- 增强逻辑 (前置处理) ---  
        // 在调用目标方法前，先记录日志  
        System.out.println(">>> [Log] 开始调用方法: " + method.getName());  
        System.out.print(">>> [Log] 参数是: ");  
        for (Object arg : args) {  
            System.out.print(arg + " ");  
        }  
        System.out.println();  
  
        // --- 调用目标对象方法 (核心业务) ---  
        // 真正调用 RealCalculator 里的 add 或 sub 方法  
        Object result = method.invoke(target, args);  
  
        // --- 增强逻辑 (后置处理) ---  
        // 在调用目标方法后，再记录日志  
        System.out.println(">>> [Log] 方法执行完毕，结果是: " + result);  
        System.out.println("---");  
  
        return result; // 返回计算结果  
    }  
}
```

```java file:ProxyDemo.java
import java.lang.reflect.Proxy;  
  
public class ProxyDemo {  
    public static void main(String[] args) {  
        // 1. 创建目标对象  
        Calculator realCalculator = new RealCalculator();  
  
        // 2. 创建 InvocationHandler (传入目标对象)  
        LogHandler handler = new LogHandler(realCalculator);  
  
        // 3. 核心步骤：使用 Proxy 类动态生成代理对象  
        Calculator proxyCalculator = (Calculator) Proxy.newProxyInstance(  
                realCalculator.getClass().getClassLoader(), // 类加载器  
                realCalculator.getClass().getInterfaces(),  // 目标对象实现的接口 (代理要实现的接口)  
                handler                                     // 代理逻辑处理器  
        );  
  
        // 4. 使用代理对象调用方法  
        System.out.println("使用动态代理对象调用 add 方法:");  
        int sum = proxyCalculator.add(10, 5);  
        System.out.println("最终结果: " + sum); // 15  
  
        // 5. 调用 sub 方法  
        System.out.println("\n使用动态代理对象调用 sub 方法:");  
        int diff = proxyCalculator.sub(20, 8);  
        System.out.println("最终结果: " + diff); // 12  
    }  
}
```

```txt
使用动态代理对象调用 add 方法: 
>>> [Log] 开始调用方法: add 
>>> [Log] 参数是: 10 5 
>>> [Log] 方法执行完毕，结果是: 15 
--- 
最终结果: 15 

使用动态代理对象调用 sub 方法: 
>>> [Log] 开始调用方法: sub 
>>> [Log] 参数是: 20 8 
>>> [Log] 方法执行完毕，结果是: 12 
--- 
最终结果: 12
```

---

服务器配置修改为： https://start.aliyun.com

