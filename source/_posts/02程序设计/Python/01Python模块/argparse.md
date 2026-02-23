---
title: argparse
date: 2025-12-28
updated: 2025-12-28
tags:
  - Python模块
categories:
  - 程序设计
  - Python
description: None
---
核心四部曲

```python
import argparse  	# 导入模块  
parser = argparse.ArgumentParser()  # 创建解析器对象  
parser.add_argument()  		# 添加参数（告诉程序你想接收什么参数）  
args = parser.parse_args()  	# 解析参数（真正去读取命令行输入的数据）
```

## 简单示例

```python
import argparse

# 1. 创建解析器
parser = argparse.ArgumentParser(description="这是一个打招呼的测试工具")

# 2. 添加一个位置参数（必填）
parser.add_argument("name", help="请输入你的名字")

# 3. 解析参数
args = parser.parse_args()

# 4. 使用参数
print(f"你好, {args.name}!")

# python demo.py shadiao
```

```python
import argparse

parser = argparse.ArgumentParser(description="模拟端口扫描配置")

# 位置参数：目标IP
parser.add_argument("host", help="目标主机的IP地址")

# 可选参数：端口（使用 -p 或 --port）
# type=int 会自动把输入的字符串转为整数
# default=80 如果用户不输入，默认就是80
parser.add_argument("-p", "--port", type=int, default=80, help="目标端口 (默认: 80)")

# 可选参数：简单标记（action="store_true" 表示只要出现了这个参数，就设为 True）
parser.add_argument("-v", "--verbose", action="store_true", help="是否显示详细日志")

args = parser.parse_args()

print(f"[*] 正在准备扫描主机: {args.host}")
print(f"[*] 目标端口: {args.port}")

if args.verbose:
    print("[+] 详细模式已开启，正在初始化原始套接字...")
    
# python scan.py 127.0.0.1
# python scan.py 192.168.1.1 -p 443 -v
```

## 简单模拟

### 自动化漏洞扫描辅助脚本

```python
import argparse
import sys

def main():
    # --- 1. 初始化解析器 ---
    parser = argparse.ArgumentParser(
        prog="SecurityScan", # 程序名称
        description="网络安全实验：自动化端口扫描与服务发现工具",
        epilog="使用示例: python scanner.py 192.168.1.1 -p 80,443 -t 50 -o result.txt"
    )

    # --- 2. 添加各种类型的参数 ---
    
    # 位置参数：目标地址（必须输入）
    parser.add_argument("target", help="扫描目标的 IP 地址或域名")

    # 可选参数：端口范围（设置默认值，限制输入格式）
    parser.add_argument("-p", "--ports", default="1-1024", 
                        help="指定端口范围 (例如: 80,443 或 1-65535, 默认: 1-1024)")

    # 可选参数：线程数（强制转换为整数 type=int）
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="并发线程数量 (默认: 10)")

    # 可选参数：输出文件（用于保存科研实验数据）
    parser.add_argument("-o", "--output", help="将结果保存到指定文件路径")

    # 布尔开关：详细模式（如果输入 -v，则为 True，否则为 False）
    parser.add_argument("-v", "--verbose", action="store_true", help="启用详细日志输出")

    # --- 3. 解析参数 ---
    args = parser.parse_args()

    # --- 4. 逻辑处理（模拟科研场景） ---
    print(f"[*] 正在初始化扫描任务...")
    print(f"[*] 目标主机: {args.target}")
    print(f"[*] 扫描端口: {args.ports}")
    print(f"[*] 线程配置: {args.threads}")

    if args.verbose:
        print("[DEBUG] 正在加载扫描模块...")
        print("[DEBUG] 正在建立原始套接字连接...")

    if args.output:
        print(f"[+] 扫描完成后，结果将保存至: {args.output}")

    # 模拟扫描过程...
    print("\n[!] 扫描已完成。")

if __name__ == "__main__":
    main()
    
# python scanner.py 10.0.0.1 -p 80,443,8080 -t 20 -v -o log.txt
```

## 互斥模式

```python
import argparse

parser = argparse.ArgumentParser(description="安全辅助工具 - 互斥模式演示")

# 创建一个互斥组
group = parser.add_mutually_exclusive_group()

# 向组内添加参数（这两个参数不能同时出现）
group.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
group.add_argument("-q", "--quiet", action="store_true", help="静默模式，仅输出结果")

args = parser.parse_args()

if args.verbose:
    print("[+] 正在扫描... 发现端口 80... 发现端口 443...")
elif args.quiet:
    print("[!] 扫描完成。")
else:
    print("[*] 正常模式运行中...")

# python tool.py -v -q 会报错
```

## 处理子命令

```python
import argparse

def main():
    parser = argparse.ArgumentParser(prog="NetTool", description="科研用网络安全综合工具")
    
    # 1. 创建子命令解析器
    subparsers = parser.add_subparsers(dest="command", help="可选的操作命令")

    # --- 子命令 A: scan ---
    parser_scan = subparsers.add_parser("scan", help="执行端口扫描")
    parser_scan.add_argument("target", help="目标 IP")
    parser_scan.add_argument("--speed", choices=["fast", "slow"], default="fast", help="扫描速度")

    # --- 子命令 B: report ---
    parser_report = subparsers.add_parser("report", help="生成分析报告")
    parser_report.add_argument("-f", "--file", required=True, help="输入日志文件路径")
    parser_report.add_argument("--format", choices=["pdf", "html"], default="html")

    # 2. 解析
    args = parser.parse_args()

    # 3. 根据输入的子命令执行不同逻辑
    if args.command == "scan":
        print(f"[*] 正在对 {args.target} 执行 {args.speed} 扫描...")
    elif args.command == "report":
        print(f"[*] 正在读取文件 {args.file} 并生成 {args.format} 格式报告...")
    else:
        parser.print_help() # 如果没输命令，打印帮助信息

if __name__ == "__main__":
    main()

# python NetTool.py -h	提示有 `scan` 和 `report` 两个命令
# python NetTool.py scan -h	只会显示 `target` 和 `--speed` 相关的参数
```