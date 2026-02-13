/**
 * 自定义图片处理插件
 * 支持 img/ 子文件夹结构的图片引用
 */

'use strict';

const path = require('path');
const fs = require('fs');

// 在文章渲染前处理图片路径
hexo.extend.filter.register('before_post_render', function(data) {
  // 只处理 markdown 文件
  if (!data.source.endsWith('.md')) {
    return data;
  }

  // 获取文章的源文件路径信息
  const sourcePath = path.join(hexo.source_dir, data.source);
  const sourceDir = path.dirname(sourcePath);
  const imgDir = path.join(sourceDir, 'img');
  const attachmentsDir = path.join(sourceDir, 'attachments');

  // 检查是否存在 img 或 attachments 文件夹
  const hasImgDir = fs.existsSync(imgDir);
  const hasAttachmentsDir = fs.existsSync(attachmentsDir);
  
  if (!hasImgDir && !hasAttachmentsDir) {
    return data;
  }

  // 处理 markdown 中的图片引用，使用相对路径
  if (hasImgDir) {
    // 处理标准markdown格式：![alt](img/filename)
    data.content = data.content.replace(/!\[([^\]]*)\]\(img\/([^)]+)\)/g, function(match, alt, imgPath) {
      // 直接使用文件名作为相对路径，因为图片会被复制到与HTML同级的目录
      return `![${alt}](${imgPath})`;
    });
    
    // 处理双方括号格式：![[img/filename]]
    data.content = data.content.replace(/!\[\[img\/([^\]]+)\]\]/g, function(match, imgPath) {
      // 提取文件名作为alt文本
      const filename = path.basename(imgPath, path.extname(imgPath));
      return `![${filename}](${imgPath})`;
    });
  }
  
  if (hasAttachmentsDir) {
    // 处理标准markdown格式：![alt](attachments/filename)
    data.content = data.content.replace(/!\[([^\]]*)\]\(attachments\/([^)]+)\)/g, function(match, alt, attachmentPath) {
      // 直接使用文件名作为相对路径，因为图片会被复制到与HTML同级的目录
      return `![${alt}](${attachmentPath})`;
    });
    
    // 处理双方括号格式：![[attachments/filename]]
    data.content = data.content.replace(/!\[\[attachments\/([^\]]+)\]\]/g, function(match, attachmentPath) {
      // 提取文件名作为alt文本
      const filename = path.basename(attachmentPath, path.extname(attachmentPath));
      return `![${filename}](${attachmentPath})`;
    });
  }

  return data;
});

// 在文章渲染后修复HTML中的图片路径
hexo.extend.filter.register('after_post_render', function(data) {
  // 只处理 markdown 文件
  if (!data.source.endsWith('.md')) {
    return data;
  }

  // 获取文章的源文件路径信息
  const sourcePath = path.join(hexo.source_dir, data.source);
  const sourceDir = path.dirname(sourcePath);
  const imgDir = path.join(sourceDir, 'img');
  const attachmentsDir = path.join(sourceDir, 'attachments');

  // 检查是否存在 img 或 attachments 文件夹
  const hasImgDir = fs.existsSync(imgDir);
  const hasAttachmentsDir = fs.existsSync(attachmentsDir);
  
  if (!hasImgDir && !hasAttachmentsDir) {
    return data;
  }

  // 修复HTML中的图片路径，移除前导斜杠
  if (hasImgDir || hasAttachmentsDir) {
    // 将 src="/filename.ext" 转换为 src="filename.ext"
    data.content = data.content.replace(/(<img[^>]*\s+src=")\/([^"\/]+\.(png|jpg|jpeg|gif|webp|svg))"/gi, function(match, prefix, filename, ext) {
      return `${prefix}${filename}"`;
    });
  }

  return data;
});

// 在生成静态文件后复制图片
hexo.extend.filter.register('after_generate', function() {
  const publicDir = hexo.public_dir;
  
  // 遍历所有文章
  hexo.locals.get('posts').forEach(function(post) {
    const sourcePath = path.join(hexo.source_dir, post.source);
    const sourceDir = path.dirname(sourcePath);
    const imgDir = path.join(sourceDir, 'img');
    const attachmentsDir = path.join(sourceDir, 'attachments');
    
    // 获取文章的最终HTML文件路径（与index.html同级）
    const postPath = post.path; // 这是相对于public的路径，如 "2025/04/11/马尔可夫链.../马尔可夫链.../index.html"
    // 如果路径以 / 结尾，说明这是目录路径，需要保持完整路径
    const postDirPath = postPath.endsWith('/') ? postPath.slice(0, -1) : path.dirname(postPath);
    const targetDir = path.join(publicDir, postDirPath);
    

    
    // 确保目标目录存在
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    
    // 复制 img 文件夹
    if (fs.existsSync(imgDir)) {
      try {
        copyImagesRecursively(imgDir, targetDir);
      } catch (error) {
        console.error(`Error copying images for ${post.title}:`, error);
      }
    }
    
    // 复制 attachments 文件夹
    if (fs.existsSync(attachmentsDir)) {
      try {
        copyImagesRecursively(attachmentsDir, targetDir);
      } catch (error) {
        console.error(`Error copying attachments for ${post.title}:`, error);
      }
    }
  });
});

// 递归复制文件夹的辅助函数
function copyImagesRecursively(srcDir, destDir) {
  if (!fs.existsSync(srcDir)) {
    return;
  }
  
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }
  
  const items = fs.readdirSync(srcDir);
  items.forEach(function(item) {
    const srcPath = path.join(srcDir, item);
    const destPath = path.join(destDir, item);
    
    if (fs.statSync(srcPath).isDirectory()) {
      // 递归处理子目录
      copyImagesRecursively(srcPath, destPath);
    } else {
      // 复制文件
      fs.copyFileSync(srcPath, destPath);
      console.log(`Copied image: ${srcPath} -> ${destPath}`);
    }
  });
}