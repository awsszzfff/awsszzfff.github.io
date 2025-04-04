// 防抖函数优化滚动事件
const debounce = <T extends (...args: any[]) => void>(func: T, wait: number = 100) => {
  let timeout: ReturnType<typeof setTimeout>;
  return function (this: any, ...args: Parameters<T>) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
};

// 主逻辑：检测滚动位置并切换导航栏样式
const initScrollHeader = () => {
  const headerNav = document.getElementById('header-nav');
  const contentDiv = document.getElementById('content');

  if (!headerNav || !contentDiv) {
    console.warn('[Scroll Header] 未找到 #header-nav 或 #content 元素！');
    return;
  }

  const toggleHeader = () => {
    const scrollY = window.scrollY;
    const contentRect = contentDiv.getBoundingClientRect();
    const contentTop = contentRect.top + scrollY; // #content 的绝对顶部位置

    // 触发条件：滚动超过页面高度 50% 或触碰 #content
    // const shouldFix = scrollY > window.innerHeight * 0.5 || scrollY >= contentTop;
    const shouldFix =  scrollY >= contentTop;

    headerNav.classList.toggle('header-nav-scrolled', shouldFix);
    headerNav.classList.toggle('header-nav-fixed', shouldFix);
  };

  // 监听滚动事件（带防抖）
  window.addEventListener('scroll', debounce(toggleHeader));
  toggleHeader(); // 初始化检查
};

// 确保 DOM 加载后执行
document.addEventListener('DOMContentLoaded', initScrollHeader);