---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "JavaLearn"
---
`final`关键字指常量

```java
String seasonName = switch(seasonCode)
{
	case 0 -> "Spring";
	case 1 -> "Summer";
	default -> "???";
};
```

### String类
`substring`提取子串
`join`拼接
`repeat`重复
`equals`检测是否相等，`equalsIgnoreCase`是否相等不区分大小写，`等等号`是判断是否在同一个位置
`length`长度
`format`创建格式化的字符串
### Scanner
`Scanner in = new Scanner(System.in);`
`nextLine`读一行换行结束
`next`读一个单词空格结束
`nextInt`读整数
`nextDouble`读浮点数
`Scanner in = new Scanner(Path.of("myfile.txt"), StandardCharsets.UTF_8);`
`PrintWriter out = new PrintWriter("myfile.txt", StandardCharsets.UTF_8);`

### 枚举类
Size 类型的变量只能存这个类型声明中所列的某个值，或者特殊值null。



`throws`标记可能发生的异常