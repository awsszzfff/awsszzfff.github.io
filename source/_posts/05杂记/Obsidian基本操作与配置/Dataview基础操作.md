---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "Dataview基础操作"
---
## 基本操作

```dataview
TABLE
	价格,
	菜系,
	厨师
FROM #菜品
WHERE 厨师 = "李大嘴"
SORT 价格 DESC
```

## 自定义第一列名

```dataview
TABLE WITHOUT ID
	file.link AS 菜名,
	价格,
	菜系,
	厨师
FROM #菜品
WHERE 厨师 = "李大嘴"
SORT 价格 DESC
```

## 添加约束条件及美化表格

```dataview
TABLE
	"$" + 价格 + "$" AS 价格,
	"=" + 菜系 + "=" AS 菜系,
	"**" + 厨师 + "**" AS 厨师
FROM #菜品
WHERE file.name != "日记模版"
AND 你是傻逼
SORT file.cday
```

## 入链数量最多的文档

```dataview
table without id 
	file.link as 名称,
	length(file.outlinks) as "出链数",
	length(file.inlinks) as "入链数"
sort length(file.inlinks) DESC
limit 5
```

## 出链数量最多的笔记

```dataview
table without id 
	file.link as 名称,
	length(file.outlinks) as "出链数",
	length(file.inlinks) as "入链数"
sort length(file.outlinks) DESC
limit 5
```

## orphan笔记

```dataview
table without id 
	file.link as 名称,
	join(file.etags," ") as 标签
where
		length(file.inlinks) = 0
	and length(file.outlinks) = 0
sort length(file.etags)
```

## 无标签笔记

```dataview
table without id
	file.link as 名称
where length(file.etags) = 0
```

---

## 末尾