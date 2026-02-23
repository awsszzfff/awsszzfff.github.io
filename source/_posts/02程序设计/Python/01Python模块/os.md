---
title: "os"
date: 2025-07-26
tags:
  - Others
categories:
  - Others
---
操作本地文件夹及文件、执行本地命令、路径拼接

```python
import os
# __file__ 当前文件
os.path.dirname(__file__)	# 当前文件夹路径
os.path.abspath(__file__)	# 当前文件所在文件路径
os.path.exists(path=file_name)	# file_name是否存在
os.path.exists(path=file_path)	# 文件夹是否存在
os.path.join(file_name, 'data')	# 路径拼接
os.path.split(file_name)	# 切割路径（前面的路径，最后一个文件名/文件夹）
os.path.basename(file_name)	# 直接获取文件/文件夹结尾路径名

# 判断是否是文件/文件夹
os.path.isfile(file_name)
os.path.isdir(file_path)

os.path.isabs(file_name)	# 是否是绝对路径
os.path.getatime(file_name)	# 当前文件/文件夹最后访问时间
os.path.getctime(file_name)	# 当前文件/文件夹创建时间
os.path.getmtime(file_name)	# 当前文件/文件夹修改时间

os.path.getsize(file_name)	# 当前文件大小

os.makedir(file_path)	# 创建文件夹
os.makedirs(file_paths)	# 创建多级文件夹

os.rmdir(file_path)	# 删除文件夹
os.removedirs(file_path)	# 删除多级文件夹，且每个文件夹中必须是空的
os.remove(file_path)	# 删除指定文件

os.listdir(file_path)	# 列出当前路径下所有的文件名
os.rename(old_path, new_path)	# 重命名

os.stat(file_path)	# 当前文件/文件夹详细信息
os.getcwd()	# 获取当前工作目录
os.chdir(file_path)	# 切换工作目录

# 执行cmd
os.system("ls") 
os.popen('ping www.baidu.com')

os.sep	# 输出操作系统特定的路径分隔符
os.linesep	# 输出当前平台使用的终止符
os.pathsep	# 输出用于分割文件路径的字符串
os.name		# 输出字符串指定当前使用平台

os.getpid()		# 当前进程id
os.getppid()	# 父进程id
```