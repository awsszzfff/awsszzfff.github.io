---
title: "hexo"
date: 2025-03-30
tags:
  - Others
categories:
  - Others
---
安装 Node.js
验证安装（检查版本）：`node -v`
换源：`npm config set registry https://registry.npmmirror.com`

安装 Git
验证安装（检查版本）：`git --version`

安装 Hexo `npm install -g hexo-cli`
验证安装（检查版本）：`hexo -v`

```bash
# 创建一个hexo博客文件夹，名为test
hexo init test

npm i	# 安装依赖
# 在博客文件夹中执行，
# 创建一篇名为test的markdown文章，可在source/_posts下找到
hexo new test

# 将现有_posts中的md文章进行转化，生成对应html格式的文章在public文件夹
hexo generate
# 删除public文件夹
hexo clean
# 利用node来启动服务器，预览博客效果，这需要在hexo generate之后进行
hexo server
# 部署本地博客文章都对应服务器
hexo deploy

hexo cl; hexo g; hexo s
hexo cl; hexo g; hexo d
```

> https://www.cnblogs.com/Jack-artical/p/18812651
> 
> https://www.xmdblog.com/posts/70db7d7c.html





