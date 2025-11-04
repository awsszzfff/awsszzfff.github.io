---
title: "conda对python的一些操作基础"
date: 2024-11-11
tags:
  - Others
categories:
  - Others
---
（base 为在 anaconda shell 中）
查看 cond 中存在的 python 环境（带`*`的表示当前环境）

```shell
conda info --env
```

创建指定的 python 环境

```shell
conda create --name py35 python=3.5  
# 代表创建一个python3.5的环境，并将其命名为py35
```

激活（进入）已经安装的指定的 python 环境

```shell
conda activate py35
```

【切换到对应环境后再进行pip安装，即给对应的环境安装对应的包】

退出当前环境

```shell
conda deactivate
```

删除指定的 python 环境

```shell
conda remove -n py35 --all
```

更新当前 python 版本

```shell
conda update python
```

更新至指定版本

```shell
conda install python=3.xxx
```

清理 Anaconda 缓存

```shell
conda clean --all
```

jupyter

```python
# 安装jupyter	# 这样好像会自动创建jupyter内核，且在当前环境（不确定）
pip install jupyter notebook jupyterlab
# pip install jupyterlab	# 这样好像不会自动创建jupyter内核（不确定）
# 创建jupyter内核 将环境吸入notebook的kernel中	# 这样会创建在默认路径下	eg：C:\\...
python -m ipykernel install --user --name myenv --display-name "Python (myenv)"
# 显示当前所有jupyter内核
jupyter kernelspec list
# 删除kernel环境	（应该和下面那个一样吧~）
jupyter kernelspec remove <环境名>
# 卸载指定jupyter内核
jupyter kernelspec uninstall <内核名>

# 在创建新的虚拟环境时同时加入环境内核【失败】
# eg: conda create -n <env_name> python=<python_version> ipykernel

# 创建环境时没有安装ipykernel，在虚拟环境下创建kernel文件
conda install -n <env_name> ipykernel
# 显示所有存在jupyter的环境（好像只在jupyter中执行才有回显）
where jupyter
# 输出当前解释器
import sys  
print(sys.executable)
```