---
title: "Java环境配置"
date: 2024-11-20
tags:
  - Others
categories:
  - Others
---
系统环境变量配置：

CLASSPATH

```shell
.;%JAVA_HOME%\lib\dt.jar;%JAVA_HOME%\lib\tools.jar;
```

JAVA_HOME

```shell
D:\Professional_Tools\Environment\Java\jdk-17
```


PATH

```shell
%JAVA_HOME%\bin

%JAVA_HOME%\jre\bin
```

快速切换 java 环境：

编写 bat 脚本文件，快速实现 java 环境的切换；需要管理员权限运行；

```shell
@echo off

set JAVA_HOME

echo 1: jdk1.8
echo 2: jdk11
echo 3: jdk17
choice /c 123 /m "please input the number and press enter."

if %ERRORLEVEL%==1 (
  echo "choice JDK8...................."
setx -m JAVA_HOME "D:\Professional_Tools\Environment\Java\jdk-1.8"
)
if %ERRORLEVEL%==2 (
  echo "choice JDK11...................."
  setx -m JAVA_HOME "D:\Professional_Tools\Environment\Java\jdk-11"
)
if %ERRORLEVEL%==3 (
  echo "choice JDK17...................."
  setx -m JAVA_HOME "D:\Professional_Tools\Environment\Java\jdk-17"
)
pause
```


快速切换 java 环境：https://blog.csdn.net/qq_37875329/article/details/128028194