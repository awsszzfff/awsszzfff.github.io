import { visit } from 'unist-util-visit';

/**
 * Remark plugin to convert Obsidian-style image references to standard markdown
 * Converts ![[attachments/image.png]] to ![image.png](attachments/image.png)
 */
export function remarkObsidianImages() {
  return (tree) => {
    visit(tree, 'text', (node, index, parent) => {
      if (!node.value) return;
      
      // 匹配 Obsidian 图片语法: ![[path/to/image.ext]]
      const obsidianImageRegex = /!\[\[([^\]]+\.(png|jpg|jpeg|gif|svg|webp|bmp|ico))\]\]/gi;
      
      if (obsidianImageRegex.test(node.value)) {
        const newNodes = [];
        let lastIndex = 0;
        let match;
        
        // 重置正则表达式的lastIndex
        obsidianImageRegex.lastIndex = 0;
        
        while ((match = obsidianImageRegex.exec(node.value)) !== null) {
          const [fullMatch, imagePath] = match;
          const matchStart = match.index;
          const matchEnd = match.index + fullMatch.length;
          
          // 添加匹配前的文本
          if (matchStart > lastIndex) {
            const beforeText = node.value.slice(lastIndex, matchStart);
            if (beforeText) {
              newNodes.push({
                type: 'text',
                value: beforeText
              });
            }
          }
          
          // 提取文件名作为alt文本
          const fileName = imagePath.split('/').pop() || imagePath;
          const altText = fileName.replace(/\.[^/.]+$/, ""); // 移除扩展名
          
          // 创建标准的markdown图片节点
          newNodes.push({
            type: 'image',
            url: imagePath,
            alt: altText,
            title: null
          });
          
          lastIndex = matchEnd;
        }
        
        // 添加剩余的文本
        if (lastIndex < node.value.length) {
          const remainingText = node.value.slice(lastIndex);
          if (remainingText) {
            newNodes.push({
              type: 'text',
              value: remainingText
            });
          }
        }
        
        // 替换原节点
        if (newNodes.length > 0) {
          parent.children.splice(index, 1, ...newNodes);
          return index + newNodes.length;
        }
      }
    });
  };
}