---
title: "Re"
date: 2025-07-15
tags:
  - Others
categories:
  - Others
---
```python
# 返回所有满足匹配条件的结果，放在列表里
re.findall(pattern, name_str)


# 只匹配到符合条件的一个字符
# 只要找到第一个匹配然后返回一个包含匹配信息的对象
# 该对象可以调用group()得到匹配的字符串，若没有，则None
re.search(pattern, name_str).group()


# 同search，不过只在字符串开始处进行匹配
re.match(pattern, name_str).group()

# eg:
text = "Hello, world! 123" 
# 匹配以数字开头 
result = re.match(r'\d+', text) 
print(result) # 输出: None # 因为字符串以 'H' 开头，不是数字 


# 以正则的作为分隔符分割字符串
re.split(pattern, string, maxsplit=0, flags=0)
# - maxsplit: 可选参数，指定最大分割次数。如果未提供或设置为 0，则不限制分割次数。
# - flags: 可选参数，标志位用于修改正则表达式的匹配方式（如忽略大小写 `re.IGNORECASE`）。


# 替换，返回替换后的字符串
re.sub(pattern, repl, string, count=0, flags=0)
# - 将匹配到的内容替换成 `repl`


# 基本同上，不过是返回一个元组（new_str, 替换次数）
re.subn(pattern, repl, string, count=0, flags=0)


# 将一个正则表达式字符串编译成一个正则表达式对象（Pattern 对象），这个对象可以被多次用于匹配、搜索、替换等操作
re.compile(pattern, flags=0)
# 配合上面的方法使用

# eg:
pattern = re.compile(r'\b[\w.-]+@[\w.-]+\.\w+\b') 
# 使用 pattern 对象进行各种操作 
text = "联系我 at john@example.com 或 SUPPORT@EXAMPLE.COM" 
# 查找所有匹配项 
emails = pattern.findall(text) 
print(emails) # 输出: ['john@example.com', 'SUPPORT@EXAMPLE.COM'] 
```