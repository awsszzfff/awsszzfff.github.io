astro.config.mjs
设置 site: "https://awsszzfff.github.io/",
注释 // base: "/",

title: "Kyle's Blog",
subtitle: "好好学习，天天向上",

banner: {
		enable: true,
		src: "assets/images/18.jpg", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
		position: "center", // Equivalent to object-position, only supports 'top', 'center', 'bottom'. 'center' by default
		credit: {
			enable: true, // Display the credit text of the banner image
			text: "且随疾风前行", // Credit text to be displayed
			url: "", // (Optional) URL link to the original artwork or artist's page
		},
	},

avatar: "assets/images/head_portrait.webp"

---

## GitHub Pages 自动部署配置

### 修改日期
2024-11-05

### 修改目标
配置 GitHub Actions 实现自动部署到 GitHub Pages

### 修改文件清单

#### 1. .github/workflows/deploy.yml（新建）
**修改内容：**
- 创建 GitHub Pages 部署 workflow
- 配置自动触发条件：推送到 main 分支
- 设置权限：pages: write, id-token: write
- 构建和部署步骤完整配置

**影响：**
- 实现推送代码后自动部署
- 网站自动更新到 https://awsszzfff.github.io

### astro.config.mjs 配置说明

**site 字段：** `"https://awsszzfff.github.io/"`
- 网站完整 URL，用于 sitemap 和 RSS
- 用于 Open Graph 链接生成

**base 字段：** 注释掉 `// base: "/"`
- 用户页面（username.github.io）应保持根路径
- 项目页面才需要设置子路径
- **建议：保持注释状态，避免路径错误**