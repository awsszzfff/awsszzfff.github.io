---
title: JPBC
date: 2024-03-16
tags:
  - JPBC
categories:
  - 编程相关
  - Java
---
JPBC 中，双线性群的使用都通过叫 Pairing 的对象来实现。双线性群的初始化在 JPBC 中就是对Pairing 对象的初始化。双线性群有两种初始化方法：通过代码动态产生双线性群；从文件中读取参数而产生群。

## 生成椭圆曲线和群

- 从文件中读取参数而产生群

```java
// a.properties文件jpbc库自带
Pairing bp = PairingFactory.getPairing("a.properties");
```

- 动态产生

指定椭圆曲线的种类、产生椭圆曲线参数、初始化`Pairing`。`Type A`曲线需要两个参数：`rBit`是`Zp`中阶数为`p`的比特长度；`qBit`是`G`中阶数的比特长度。

```java
//  动态产生一般r为160，q取512
int rBits = 160;
int qBits = 512;
TypeACurveGenerator pg = new TypeACurveGenerator(rBits,qBits);
PairingParameters pp = pg.generate();
Pairing bp = PairingFactory.getPairing(pp);
```

## 类型介绍

`Field`类型，群环域类型
取随机数：`newRandomElement()`
取单位元：`newZeroElement()`
群的阶：`getOrder()`等

`Element`类型，群环域上的元素，可以使用特定的有限域，椭圆曲线点群进行实例化
`Element`可以进行加法、除法、乘法、指数运算、求逆元（inver函数）、判断是否为单位元、赋初值、用`Element`做生成元生成群等。
## 功能方法
- `TypeA`（对称质数阶双线性群，此时G1=G2，记为G，即G1XG2->GT=GXG->GT）曲线产生堆积元素

```java
// 随机产生一个Zp群的元素
// Element Zp = bp.getZr()  生成Zp群
Element Zp = bp.getZr().newRandomElement().getImmutable();

// 随机产生一个G1群的元素
Element G1 = bp.getG1().newRandomElement().getImmutable();
// 随机产生一个G2群的元素
Element G2 = bp.getG2().newRandomElement().getImmutable();

// // 随机产生一个GT群的元素
Element GT = bp.getGT().newRandomElement().getImmutable();
```

## 将任意元素哈希到双线性群上

jPBC 支持将 `byte[]` 哈希到双线性群的 Z、G、GT 中。但是，jPBC 说明文档中没有提到的是，`byte[]`数组长度不能太长，如果过长会抛出异常。因此，我建议首先将`byte[]`用一个`SHA256`(Java库自带)或者其他通用哈希函数哈希到固定长度，再用jPBC提供的函数哈希到双线性群上。将任意元素哈希到Z、G、GT群的代码：

```java
// 将byte[] bteArray_Zp哈希到群
Element hash_Zp = pairing.getZr().newElement().setFromHash(byteArray_Zp, 0, byteArray_Zp.length);

// 将byte[] byteArray_G1好戏到G1群
Element hash_G1 = pairing.getG1().newElement().setFromHash(byteArray_G1, 0, byteArray_G1.length);
```

## 群上的运算

1. Java的运算结果都是产生一个新的Element来存储，所以需要把运算结果赋值给一个新的Element；
2. Java在进行相关运算时，参与运算的Element值可能会发生改变。因此，若需要再运算过程中保留参与运算的Element值，在存储时要调用`getImmutable()`。保险期间，防止Element运算的过程中被修改了Element原本的数值，可以使用`Element.duplicate()`方法。该方法返回一个与Element数值完全一样的Element，但是是个新的Element对象。eg：做G1XG1的运算，可以写成：`Element `


### 基本使用

- 创建项目，添加jar包依赖
- 引用库
- 生成Pairing实例
- 验证双线性$\mathrm{e(g^a,g^b)=e(g,g)^{ab}}$


```java
// 一、基于特定椭圆曲线类型生成Pairing实例
// 1.从文件导入椭圆曲线参数
Pairing bp = PairingFactory.getPairing("a.properties");

// 2.自定义曲线参数
// int rBits = 160;
// int qBits = 512;
// TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
// PairingParameters pp = pg.generate();
// Pairing bp = PairingFactory.getPairing(pp);

// 二、选择群上的元素
Field G1 = bp.getG1();
Field Zr = bp.getZr();
Element g = G1.newRandomElement().getImmutable();
Element a = Zr.newRandomElement().getImmutable();
Element b = Zr.newRandomElement().getImmutable();

// 三、计算等式左半部分
Element ga = g.powZn(a);
Element gb = g.powZn(b);
Element egg_ab = bp.pairing(ga,gb);

// 四、计算等式右半部分
Element egg = bp.pairing(g,g).getImmutable();
Element ab = a.mul(b);
Element egg_ab_p = egg.powZn(ab);

if (egg_ab.isEqual(egg_ab_p)) { 
	System.out.println("yes"); 
} else { 
	System.out.println("No"); 
}
```

