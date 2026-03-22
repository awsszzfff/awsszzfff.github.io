---
title: Leetcode-Hot100
date: 2025-12-29
updated: 2025-12-29
tags:
  - 刷题记录
categories:
  - 程序设计
description: Leetcode-Hot100
draft: false
---
## 哈希

### [1. 两数之和](https://leetcode.cn/problems/two-sum/)

`nums[i] + nums[j] = target` -> `nums[j] = target - nums[i]`

哈希表法，枚举右边。

> 枚举右，维护左/寻找左

![[attachments/20251229.png]]

```python
# 枚举 j （枚举右边，即左边信息已知了）
class Solution:
    def twoSum(self, nums: List[int], target: int) -> List[int]:
        idx = dict()
        for j, x in enumerate(nums):
            if target - x in idx:   # 在左边找 nums[i]，满足 nums[i] + x = target
                return [idx[target - x], j]
            idx[x] = j
       
                 
# 枚举 i （需要多一步先遍历操作，因为并不知道右边的信息）
class Solution:
    def twoSum(self, nums: List[int], target: int) -> List[int]:
        idx = {}
        for j, x in enumerate(nums):  # 先将所有的数及下标记录
            idx[x] = j  # 右边的覆盖左边
        for i, x in enumerate(nums):
            if idx[x] == i:  # 右边再没有 x 了，避免重复使用到当前数
                del idx[x]
            if target - x in idx:   # 在右边找 nums[j]，满足 x + nums[j] = target
                return [i, idx[target - x]]
```

### [49. 字母异位词分组](https://leetcode.cn/problems/group-anagrams/)

```python
class Solution:
    def groupAnagrams(self, strs: List[str]) -> List[List[str]]:
        d = defaultdict(list)
        for s in strs:
            sorted_s = ''.join(sorted(s))
            d[sorted_s].append(s)
        return list(d.values())
```

### [128. 最长连续序列](https://leetcode.cn/problems/longest-consecutive-sequence/)

```python
class Solution:
    def longestConsecutive(self, nums: List[int]) -> int:
        st = set(nums)
        ans = 0
        for x in st:
            if x - 1 in st:  # 如果x不是序列的起点，则直接跳过
                continue
            y = x + 1
            while y in st:
                y += 1
            ans = max(ans, y - x)
            # 优化：若当前序列长已经>len(st)/2了，则不可能存在比他更大的序列长度了
            if ans * 2 >= len(st):
                break
        return ans
```

## 双指针

### [283. 移动零](https://leetcode.cn/problems/move-zeroes/description/)

```python

```

### [11. 盛最多水的容器](https://leetcode.cn/problems/container-with-most-water/)

分析题目：高度取当前两条线最小的，宽度取两条线之间的距离。

分类讨论：当前已有的长方形面积，固定当前高的那条线，另一条短线移动

- 若是中间更短的线/一样长的线，即高度/宽度减小，不可能比原来面积大；
- 若是中间有更长的线，则高增大，宽减小，需判断和原面积的大小；

即**若要找到面积更大的，则不可能是和当前的短线组成的**。

```python
class Solution:
    def maxArea(self, height: List[int]) -> int:
        left = 0
        right = len(height) - 1
        ans = 0
        while left < right:
            area = min(height[left], height[right]) * (right - left)
            ans = max(ans, area)
            if height[left] > height[right]:	# 固定当前高的那条线
                right -= 1
            else:
                left += 1
        return ans
```

### [15. 三数之和](https://leetcode.cn/problems/3sum/)

排序，枚举 i，即将问题转换为另外两个数之和的问题；

*不可包含重复的三元组*，先分析什么时候会出现重复的三元组（eg：`[-4, -1, -1, 0, 1, 2]`，前面两个 -1 和后面的数组合会重复）遇见重复跳过即可。

```python
class Solution:
    def threeSum(self, nums: List[int]) -> List[List[int]]:
        nums.sort()
        ans = []
        n = len(nums)
        for i in range(n - 2):
            if i > 0 and nums[i] == nums[i - 1]:
                continue
                
            # 两种优化
            if nums[i] + nums[i + 1] + nums[i + 2] > 0:
                break
            if nums[i] + nums[-1] + nums[-2] < 0:
                continue
            
            j = i + 1
            k = n - 1
            while j < k:
                s = nums[i] + nums[j] + nums[k]
                if s > 0:
                    k -= 1
                elif s < 0:
                    j += 1
                else:
                    # ans.append([nums[i], nums[j], nums[k]])
                    # j += 1
                    # while j < k and nums[j] == nums[j - 1]:
                    #     j += 1
                    # k -= 1
                    # while j < k and nums[k] == nums[k + 1]:
                    #     k -= 1

                    # j == i + 1 表示刚开始双指针，j 左边没有数字
                    # nums[j] != nums[j - 1] 说明与上一轮的三元组不同
                    if j == i + 1 or nums[j] != nums[j - 1]:
                        ans.append([nums[i], nums[j], nums[k]])
                    j += 1
                    k -= 1
        return ans
```

### [42. 接雨水](https://leetcode.cn/problems/trapping-rain-water/)

#### 前后缀分解/动态规划

计算每个单位的水桶可以接多少水，单位水桶左边的高度取决于左边的最大高度，右边取决于右边的最大高度；

则计算前缀最大值数组、后缀最大值数组，即保证当前单位水桶中的水是不会流出去的。

> 对于当前列，只需关注左边最高墙和右边最高墙中较矮的一个即可，三种情况：
> - 较矮墙高度大于当前列，则当前列的水量为 `矮墙高度-当前列高度`；
> - 较矮墙高度小于当前列，则当前列无水；
> - 较矮墙高度等于当前列，则当前列无水。
> 
> 最两端不用考虑，因为一定不会有水。
> 
> [windliang 思路分析及多解](https://leetcode.cn/problems/trapping-rain-water/solutions/9112/xiang-xi-tong-su-de-si-lu-fen-xi-duo-jie-fa-by-w-8/)

```python
class Solution:
    def trap(self, height: List[int]) -> int:
    	# 时间复杂度 O(n)
    	# 空间复杂度 O(n)
        n = len(height)
        
        # 第i列左侧最高墙
        pre_max = [0] * n
        pre_max[0] = height[0]
        for i in range(1, n):
            pre_max[i] = max(pre_max[i - 1], height[i])
            
        # 第i列右侧最高墙
        suf_max = [0] * n
        suf_max[n - 1] = height[n - 1]
        for i in range(n - 2, -1, -1):
            suf_max[i] = max(suf_max[i + 1], height[i])
            
        ans = 0
        for pre, suf, h in zip(pre_max, suf_max, height):
            ans += min(pre, suf) - h
            
        return ans
```

#### 相向双指针

若左侧最大值比右侧最大值小，则当前木桶接水的容量即为左侧最大值，随后向右扩展；反之，同理。

```python
class Solution:
    def trap(self, height: List[int]) -> int:
        # 时间复杂度 O(n)
        # 空间复杂度 O(1)
        n = len(height)
        ans = 0

        left = 0
        right = n - 1

        pre_max = 0
        suf_max = 0

        while left < right:
            pre_max = max(pre_max, height[left])
            suf_max = max(suf_max, height[right])
            if pre_max < suf_max:
                ans += pre_max - height[left]
                left += 1
            else:
                ans += suf_max - height[right]
                right -= 1
                
        return ans
```

#### 单调栈

```python
class Solution:
    def trap(self, height: List[int]) -> int:
        ans = 0
        st = []
        for i, h in enumerate(height):
            while st and h >= height[st[-1]]:
                bottom_h = height[st.pop()]
                if not st:
                    break
                left = st[-1]
                dh = min(height[left], h) - bottom_h
                ans += (i - left - 1) * dh
            st.append(i)
        return ans
```

## 滑动窗口

### [3. 无重复字符的最长子串](https://leetcode.cn/problems/longest-substring-without-repeating-characters/)

```python
class Solution:
    def lengthOfLongestSubstring(self, s: str) -> int:
        # 时间复杂度 O(n)
        # 空间复杂度 O(128) O(1) O(len(set(s)))

        # # 用字符串
        # sub = ""
        # ans = 0
        # left = 0
        # for right, c in enumerate(s):
        #     sub += c
        #     while sub.count(c) > 1:
        #         sub = sub[1:]
        #         left += 1
        #     ans = max(ans, right - left + 1)
        # return ans

        # # 用哈希表
        # ans = 0
        # left = 0
        # cnt = defaultdict(int)
        # for right, c in enumerate(s):
        #     cnt[c] += 1
        #     while cnt[c] > 1:
        #         cnt[s[left]] -= 1
        #         left += 1
        #     ans = max(ans, right - left + 1)
        # return ans

        # 哈希集合
        ans = 0
        left = 0
        window = set()
        for right, c in enumerate(s):
            while c in window:
                window.remove(s[left])
                left += 1
            window.add(c)
            ans = max(ans, right - left + 1)
        return ans
```

### [438. 找到字符串中所有字母异位词](https://leetcode.cn/problems/find-all-anagrams-in-a-string/description/)

```python

```

## 子串

### [560. 和为 K 的子数组](https://leetcode.cn/problems/subarray-sum-equals-k/)

```python

```

### [239. 滑动窗口最大值](https://leetcode.cn/problems/sliding-window-maximum/)

```python
class Solution:
    def maxSlidingWindow(self, nums: List[int], k: int) -> List[int]:
        # 单调队列，队列记录下标
        ans = []
        q = deque()
        for i, x in enumerate(nums):  # x = nums[i]
            # 入队
            while q and nums[q[-1]] <= x:
                q.pop()  # 保证单调性
            q.append(i)
            # 出队
            left = i - k + 1  # 窗口左端点
            if q[0] < left:  # 队首离开窗口
                q.popleft()
            # 保存结果
            if left >= 0:
                ans.append(nums[q[0]])
        return ans
```

### [76. 最小覆盖子串](https://leetcode.cn/problems/minimum-window-substring/)

```python

```

## 普通数组

### [53. 最大子数组和](https://leetcode.cn/problems/maximum-subarray/)

### [56. 合并区间](https://leetcode.cn/problems/merge-intervals/)

### [189. 轮转数组](https://leetcode.cn/problems/rotate-array/)

### [238. 除了自身以外数组的乘积](https://leetcode.cn/problems/product-of-array-except-self/)

### [41. 缺失的第一个正数](https://leetcode.cn/problems/first-missing-positive/)

## 矩阵

### [73. 矩阵置零](https://leetcode.cn/problems/set-matrix-zeroes/)

### [54. 螺旋矩阵](https://leetcode.cn/problems/spiral-matrix/)

### [48. 旋转图像](https://leetcode.cn/problems/rotate-image/)

### [240. 搜索二维矩阵 II](https://leetcode.cn/problems/search-a-2d-matrix-ii/)

## 链表

### [160. 相交链表](https://leetcode.cn/problems/intersection-of-two-linked-lists/)

### [206. 反转链表](https://leetcode.cn/problems/reverse-linked-list/)

```python
class Solution:
    def reverseList(self, head: Optional[ListNode]) -> Optional[ListNode]:
        cur = head
        pre = None
        while cur:
            nxt = cur.next
            cur.next = pre
            pre = cur
            cur = nxt
        return pre
```

### [234. 回文链表](https://leetcode.cn/problems/palindrome-linked-list/)

### [141. 环形链表](https://leetcode.cn/problems/linked-list-cycle/)

### [142. 环形链表 II](https://leetcode.cn/problems/linked-list-cycle-ii/)

### [21. 合并两个有序链表](https://leetcode.cn/problems/merge-two-sorted-lists/)

### [2. 两数相加](https://leetcode.cn/problems/add-two-numbers/)

### [19. 删除链表的倒数第 N 个结点](https://leetcode.cn/problems/remove-nth-node-from-end-of-list/)

```python
class Solution:
    def removeNthFromEnd(self, head: Optional[ListNode], n: int) -> Optional[ListNode]:
        left = right = dummy_head = ListNode(0, head)
        for _ in range(n):
            right = right.next
        while right.next:
            right = right.next
            left = left.next
        left.next = left.next.next
        return dummy_head.next
```

### [24. 两两交换链表中的节点](https://leetcode.cn/problems/swap-nodes-in-pairs/)

### [25. K 个一组翻转链表](https://leetcode.cn/problems/reverse-nodes-in-k-group/)

![[attachments/20260106-1.png]]

```python
class Solution:
    def reverseKGroup(self, head: Optional[ListNode], k: int) -> Optional[ListNode]:
        dummy = ListNode(next=head)

        cur = head
        count = 0
        while cur:
            count += 1
            cur = cur.next
        n = count // k

        p0 = dummy
        pre = None
        cur = p0.next
        for _ in range(n):
            for _ in range(k):
                nxt = cur.next
                cur.next = pre
                pre = cur
                cur = nxt
            nxt = p0.next
            p0.next.next = cur
            p0.next = pre
            p0 = nxt

        return dummy.next
```

### [138. 随机链表的复制](https://leetcode.cn/problems/copy-list-with-random-pointer/)

### [148. 排序链表](https://leetcode.cn/problems/sort-list/)

### [23. 合并 K 个升序链表](https://leetcode.cn/problems/merge-k-sorted-lists/)

### [146. LRU 缓存](https://leetcode.cn/problems/lru-cache/)

> - get：把一本书（key）抽出来，放在最上面。
> - put：放入一本新书。
> 	- 如果已经有这本书 （key），就把它抽出来放在最上面，并替换它的 value。（例如把一本书的第二版替换成第三版）
> 	- 如果没有这本书（key），就放在最上面。
> 	- 如果超过 capacity 本书，就把最下面的书移除。

库函数写法

```python
class LRUCache:

    def __init__(self, capacity: int):
        self.capacity = capacity
        from collections import OrderedDict
        # OrderedDict = dict + 双链表
        self.cache = OrderedDict()

    def get(self, key: int) -> int:
        if key not in self.cache:
            return -1
        # last=False 移到链表头
        self.cache.move_to_end(key, last=False)
        return self.cache[key]

    def put(self, key: int, value: int) -> None:
        self.cache[key] = value  # 添加 key value 或更新 value
        # 移到链表头
        self.cache.move_to_end(key, last=False)
        if len(self.cache) > self.capacity:  # 超出容量
            self.cache.popitem()  # 去掉最后一个
```

双向链表，O(1) 时间复杂度

```python
class Node:
    __slots__ = 'prev', 'next', 'key', 'value'

    def __init__(self, key=0, value=0):
        self.key = key
        self.value = value

    # def __init__(self, key=0, value=0):
    #     self.key = key
    #     self.value = value
    #     self.prev = None
    #     self.next = None


class LRUCache:

    def __init__(self, capacity: int):
        self.capacity = capacity
        self.dummy = Node()  # 哨兵节点
        self.dummy.prev = self.dummy
        self.dummy.next = self.dummy
        self.key_to_node = {}

    # 获取 key 对应的节点，同时吧节点移动到链表头
    def get_node(self, key: int) -> Optional[Node]:
        if key not in self.key_to_node:  # 没有
            return None
        node = self.key_to_node[key]  # 有
        self.remove(node)  # 抽出来
        self.push_front(node)  # 放到最上面
        return node

    def get(self, key: int) -> int:
        node = self.get_node(key)  # 获取并移至头
        return node.value if node else -1

    def put(self, key: int, value: int) -> None:
        node = self.get_node(key)  # 获取并移至头
        if node:  # 有
            node.value = value  # 更新 value
            return
        self.key_to_node[key] = node = Node(key, value)  # 没有，新
        self.push_front(node)  # 移至头
        if len(self.key_to_node) > self.capacity:  # 超出范围
            back_node = self.dummy.prev
            del self.key_to_node[back_node.key]
            self.remove(back_node)  # 移除最后一个

    # 删除一个节点
    def remove(self, x: Node) -> None:
        x.prev.next = x.next
        x.next.prev = x.prev

    # 链表头添加一个节点
    def push_front(self, x: Node) -> None:
        x.next = self.dummy.next
        x.prev = self.dummy
        self.dummy.next = x
        x.next.prev = x
```

## 二叉树

### [94. 二叉树的中序遍历](https://leetcode.cn/problems/binary-tree-inorder-traversal/)

### [104. 二叉树的最大深度](https://leetcode.cn/problems/maximum-depth-of-binary-tree/)

从原问题出发，将原问题分解为更小（相同）的子问题。

![[attachments/20260109.png]]

```python
class Solution:
    def maxDepth(self, root: Optional[TreeNode]) -> int:
        # 把节点传下去
        if root is None:
            return 0
        ldepth = self.maxDepth(root.left)
        rdepth = self.maxDepth(root.right)
        return max(ldepth, rdepth) + 1
```

```python
class Solution:
    def maxDepth(self, root: Optional[TreeNode]) -> int:
        # 把路径上的节点个数传下去
        ans = 0

        def dfs(root, depth):
            if root is None:
                return
                
            depth += 1
            nonlocal ans
            ans = max(ans, depth)
            
            dfs(root.left, depth)
            dfs(root.right, depth)

        dfs(root, 0)

        return ans
```

### [226. 翻转二叉树](https://leetcode.cn/problems/invert-binary-tree/)

```python
class Solution:
    def invertTree(self, root: Optional[TreeNode]) -> Optional[TreeNode]:
        if root is None:
            return None
        self.invertTree(root.left)
        self.invertTree(root.right)
        root.left, root.right = root.right, root.left
        return root
# 另一种方式是先交换左右儿子再递归翻转对应的左右子树
```

### [101. 对称二叉树](https://leetcode.cn/problems/symmetric-tree/)

### [543. 二叉树的直径](https://leetcode.cn/problems/diameter-of-binary-tree/)

```python
class Solution:
    def diameterOfBinaryTree(self, root: Optional[TreeNode]) -> int:
        ans = 0

        def dfs(node):
            if node is None:
                return -1
            l_len = dfs(node.left)
            r_len = dfs(node.right)
            nonlocal ans
            ans = max(ans, l_len + r_len + 2)
            return max(l_len, r_len) + 1

        dfs(root)
        return ans
```

### [102. 二叉树的层序遍历](https://leetcode.cn/problems/binary-tree-level-order-traversal/)

### [108. 将有序数组转换为二叉搜索树](https://leetcode.cn/problems/convert-sorted-array-to-binary-search-tree/)

### [98. 验证二叉搜索树](https://leetcode.cn/problems/validate-binary-search-tree/)

#### 前序遍历

![[attachments/20260110.png]]

范围从上往下传导，左子树的值 `(-∞, root.val)` 右子树的值 `(root.val, +∞)` 。

```python
class Solution:
    def isValidBST(self, root: Optional[TreeNode], left=-inf, right=inf) -> bool:
        if root is None:
            return True
        x = root.val
        return left < x < right and self.isValidBST(root.left, left, x) and self.isValidBST(root.right, x, right)
```

#### 中序遍历

判断整个序列是否是一个严格递增的数组

```python
class Solution:
    pre = -inf

    def isValidBST(self, root: Optional[TreeNode]) -> bool:
        if root is None:
            return True
        if not self.isValidBST(root.left):
            return False
        if self.pre >= root.val:
            return False
        self.pre = root.val
        return self.isValidBST(root.right)
```

#### 后序遍历

![[attachments/20260110-1.png]]

从下向上传导左右子树的最大值和最小值

```python
class Solution:
    def isValidBST(self, root: Optional[TreeNode]) -> bool:
        def dfs(node):
            if node is None:
                return inf, -inf
            l_min, l_max = dfs(node.left)
            r_min, r_max = dfs(node.right)
            x = node.val
            if x <= l_max or x >= r_min:
                return -inf, inf
            return min(x, l_min), max(x, r_max)

        return dfs(root)[1] != inf
```

### [230. 二叉搜索树中第 K 小的元素](https://leetcode.cn/problems/kth-smallest-element-in-a-bst/)

### [199. 二叉树的右视图](https://leetcode.cn/problems/binary-tree-right-side-view/)

> 先遍历右子树，两个问题：
> 
> - 怎么把答案记下来：全局的数组来记录。
> - 如何判断当前节点是否需要记录到答案中：递归时记录每个节点的深度，若深度等于当前记录节点的个数，则说明当前节点为该层的第一个，存入数组中。

```python
class Solution:
    def rightSideView(self, root: Optional[TreeNode]) -> List[int]:
        ans = []

        def dfs(node, depth):
            if node is None:
                return
            if depth == len(ans):
                ans.append(node.val)
            dfs(node.right, depth + 1)
            dfs(node.left, depth + 1)

        dfs(root, 0)

        return ans
```

### [114. 二叉树展开为链表](https://leetcode.cn/problems/flatten-binary-tree-to-linked-list/)

### [105. 从前序与中序遍历序列构造二叉树](https://leetcode.cn/problems/construct-binary-tree-from-preorder-and-inorder-traversal/)

### [437. 路径总和 III](https://leetcode.cn/problems/path-sum-iii/)

### [236. 二叉树的最近公共祖先](https://leetcode.cn/problems/lowest-common-ancestor-of-a-binary-tree/)

![[attachments/20260111.png]]

```python
class Solution:
    def lowestCommonAncestor(self, root: 'TreeNode', p: 'TreeNode', q: 'TreeNode') -> 'TreeNode':
        if root is None or root is p or root is q:
            return root
        left = self.lowestCommonAncestor(root.left, p, q)
        right = self.lowestCommonAncestor(root.right, p, q)
        if left and right:
            return root
        if left:
            return left
        return right
```

### [124. 二叉树中的最大路径和](https://leetcode.cn/problems/binary-tree-maximum-path-sum/)

## 图论

### [200. 岛屿数量](https://leetcode.cn/problems/number-of-islands/)

### [994. 腐烂的橘子](https://leetcode.cn/problems/rotting-oranges/)

### [207. 课程表](https://leetcode.cn/problems/course-schedule/)

### [208. 实现 Trie (前缀树)](https://leetcode.cn/problems/implement-trie-prefix-tree/)

## 回溯

> for 循环是对每个数作为开头的遍历，dfs 递归是对当前数和剩余数组合的搜索，pop 弹出使当前数可以分别和剩余数进行组合。

### [46. 全排列](https://leetcode.cn/problems/permutations/)

```python
class Solution:
    def permute(self, nums: List[int]) -> List[List[int]]:
        n = len(nums)
        ans = []
        path = [0] * n

        def dfs(i, s):
            # i 当前所选数填入的位置，s 剩余可选数的集合
            if i == n:
                ans.append(path.copy())
                return
            for x in s:
                path[i] = x
                dfs(i + 1, s - {x})
        dfs(0, set(nums))
        return ans
```

```python
class Solution:
    def permute(self, nums: List[int]) -> List[List[int]]:
        n = len(nums)
        ans = []
        path = [0] * n
        on_path = [False] * n	# 布尔数组代替集合

        def dfs(i):
            if i == n:
                ans.append(path.copy())
                return
            for j in range(n):
                if on_path[j]:
                    continue
                path[i] = nums[j]
                on_path[j] = True
                dfs(i + 1)
                on_path[j] = False  # 恢复现场

        dfs(0)
        return ans
```

### [78. 子集](https://leetcode.cn/problems/subsets/)

![[attachments/20260122-1.png]]

```python
class Solution:
    def subsets(self, nums: List[int]) -> List[List[int]]:
        n = len(nums)
        ans = []
        path = []

        # 选或不选：讨论 nums[i] 是否加入 path
        def dfs(i):
            if i == n:  # 子集构造完毕
                ans.append(path.copy())
                return

            # 不选 nums[i]
            dfs(i + 1)

            # 选 nums[i]
            path.append(nums[i])
            dfs(i + 1)  # 考虑下一个数 nums[i + 1] 选不选
            path.pop()  # 恢复现场

        dfs(0)
        return ans
```

![[attachments/20260122-2.png]]

```python
class Solution:
    def subsets(self, nums: List[int]) -> List[List[int]]:
        n = len(nums)
        ans = []
        path = []

        # 枚举选哪个：在下标 i 到 n - 1 中选一个数，加到 path 末尾
        def dfs(i):
            ans.append(path.copy())  # 不选，把当前子集加入答案
            for j in range(i, n):  # 选，枚举选择的数字
                path.append(nums[j])
                dfs(j + 1)  # 选 nums[j] i 到 j - 1 都跳过不选，下一个数从 j + 1 开始选
                path.pop()  # 恢复现场

        dfs(0)
        return ans
```

### [17. 电话号码的字母组合](https://leetcode.cn/problems/letter-combinations-of-a-phone-number/)

![[attachments/20260122.png]]

```python
MAPPING = ["", "", "abc", "def", "ghi", "jkl", "mno", "pqrs", "tuv", "wxyz"]


class Solution:
    def letterCombinations(self, digits: str) -> List[str]:
        n = len(digits)
        if n == 0:
            return []

        ans = []
        path = [''] * n

        def dfs(i):
            if i == n:
                ans.append("".join(path))
                return
            for c in MAPPING[int(digits[i])]:
                path[i] = c
                dfs(i + 1)

        dfs(0)
        return ans
```

### [39. 组合总和](https://leetcode.cn/problems/combination-sum/)

### [22. 括号生成](https://leetcode.cn/problems/generate-parentheses/)

### [79. 单词搜索](https://leetcode.cn/problems/word-search/)

### [131. 分割回文串](https://leetcode.cn/problems/palindrome-partitioning/)

![[attachments/20260123.png]]

```python
class Solution:
    def partition(self, s: str) -> List[List[str]]:
        ans = []
        path = []
        n = len(s)

        def dfs(i):
            if i == n:
                ans.append(path.copy())
                return
            for j in range(i, len(s)):
                t = s[i: j + 1]
                if t == t[::-1]:
                    path.append(t)
                    dfs(j + 1)
                    path.pop()

        dfs(0)
        return ans
```

### [51. N 皇后](https://leetcode.cn/problems/n-queens/)

```python
class Solution:
    def solveNQueens(self, n: int) -> List[List[str]]:
        ans = []
        col = [0] * n  # col 记录皇后的位置，下标为行，对应的为列

        def valid(r, c):
            for R in range(r):
                C = col[R]
                if r + c == R + C or r - c == R - C:	# 对角线的两种情况
                    return False
            return True

        def dfs(r, s):
            if r == n:
                ans.append(['.' * c + 'Q' + '.' * (n - 1 - c) for c in col])
                return
            for c in s:
                if valid(r, c):
                    col[r] = c
                    dfs(r + 1, s - {c})

        dfs(0, set(range(n)))
        return ans
```

```python
class Solution:
    def solveNQueens(self, n: int) -> List[List[str]]:
        ans = []
        col = [0] * n  # col 记录皇后的位置，下标为行，对应的为列

        def dfs(r, s):
            if r == n:
                ans.append(['.' * c + 'Q' + '.' * (n - 1 - c) for c in col])
                return
            for c in s:
                if all(r + c != R + col[R] and r - c != R - col[R] for R in range(r)):
                    col[r] = c
                    dfs(r + 1, s - {c})

        dfs(0, set(range(n)))
        return ans
```

```python
class Solution:
    def solveNQueens(self, n: int) -> List[List[str]]:
        ans = []
        col = [0] * n  # col 记录皇后的位置，下标为行，对应的为列
        # r+c r-c用一个布尔数组来记录
        on_path = [False] * n
        diag1 = [False] * (2 * n - 1)
        diag2 = [False] * (2 * n - 1)

        def dfs(r):
            if r == n:
                ans.append(['.' * c + 'Q' + '.' * (n - 1 - c) for c in col])
                return
            for c in range(n):
                if not on_path[c] and not diag1[r + c] and not diag2[r - c + n - 1]:  # + n - 1 避免是负数（python可以不用）
                    col[r] = c
                    on_path[c] = diag1[r + c] = diag2[r - c + n - 1] = True
                    dfs(r + 1)
                    on_path[c] = diag1[r + c] = diag2[r - c + n - 1] = False

        dfs(0)
        return ans
```

## 二分查找

> 区间内的数（下标）都是还未确定与 target 的大小关系的，有的是 < target，有的是 ≥ target；区间外的数（下标）都是确定与 target 的大小关系的。

### [35. 搜索插入位置](https://leetcode.cn/problems/search-insert-position/)

### [74. 搜索二维矩阵](https://leetcode.cn/problems/search-a-2d-matrix/)

### [34. 在排序数组中查找元素的第一个和最后一个位置](https://leetcode.cn/problems/find-first-and-last-position-of-element-in-sorted-array/)

```python
class Solution:
    def lower_bound1(self, nums, target):
        left = 0
        right = len(nums) - 1
        # 闭区间 [left, right]
        while left <= right:  # 区间不为空
            mid = left + (right - left) // 2
            if nums[mid] < target:
                left = mid + 1
            else:
                right = mid - 1
        # 循环结束后 left = right+1
        # 此时 nums[left-1] < target 而 nums[left] = nums[right+1] >= target
        # 所以 left 就是第一个 >= target 的元素下标
        return left

    def lower_bound2(self, nums, target):
        left = 0
        right = len(nums)
        # 左闭右开 [left, right)
        while left < right:  # 区间不为空
            mid = left + (right - left) // 2
            if nums[mid] < target:
                left = mid + 1
            else:
                right = mid
        # 循环结束后 left = right
        # 此时 nums[left-1] < target 而 nums[left] = nums[right] >= target
        # 所以 left 就是第一个 >= target 的元素下标
        return left

    def lower_bound3(self, nums, target):
        left = -1
        right = len(nums)
        # 开区间[left, right]
        while left + 1 < right: # 区间不为空
            mid = left + (right - left) // 2
            if nums[mid] < target:
                left = mid
            else:
                right = mid
        # 循环结束后 left+1 = right
        # 此时 nums[left] < target 而 nums[right] >= target
        # 所以 right 就是第一个 >= target 的元素下标
        return right

    def searchRange(self, nums: List[int], target: int) -> List[int]:
        start = self.lower_bound3(nums, target)
        if start == len(nums) or nums[start] != target:
            return [-1, -1]
        end = self.lower_bound3(nums, target + 1) - 1
        return [start, end]
```

库函数写法

```python
def searchRange(self, nums: List[int], target: int) -> List[int]:
    start = bisect_left(nums, target)
    if start == len(nums) or nums[start] != target:
        return [-1, -1]
    end = bisect_right(nums, target) - 1
    return [start, end]
```

### [33. 搜索旋转排序数组](https://leetcode.cn/problems/search-in-rotated-sorted-array/)

#### 两次二分

先找最小值，再在有序数组中找 target

```python
class Solution:
    def findMin(self, nums):
        left = 0
        right = len(nums)
        while left < right:
            mid = left + (right - left) // 2
            if nums[mid] > nums[-1]:
                left = mid + 1
            else:
                right = mid
        return left

    def lower_bound(self, nums, left, right, target):
        while left < right:
            mid = left + (right - left) // 2
            if nums[mid] < target:
                left = mid + 1
            else:
                right = mid
        return left if nums[left] == target else -1

    def search(self, nums: List[int], target: int) -> int:
        i = self.findMin(nums)
        if target > nums[-1]:
            return self.lower_bound(nums, 0, i, target)
        return self.lower_bound(nums, i, len(nums), target)
```

#### 一次二分

> - 如果 x 和 target 在不同的递增段：
> 	- 如果 target 在第一段，x 在第二段，说明 target 在 x 在左边。
> 	- 如果 x 在第一段，target 在第二段，说明 target 在 x 在右边。
> - 如果 x 和 target 在相同的递增段：
> 	- 和 lowerBound 函数一样，比较 x 和 target 的大小即可。

```python
# 写法一
class Solution:
    def search(self, nums: List[int], target: int) -> int:
        left = 0
        right = len(nums)
        while left < right:
            mid = left + (right - left) // 2
            x = nums[mid]
            if target > nums[-1] >= x:
                right = mid
            elif x > nums[-1] >= target:
                left = mid + 1
            elif x >= target:
                right = mid
            else:
                left = mid + 1
        return left if nums[left] == target else -1
```

> 只讨论 target 在 x 左边，或者 x=target 的情况。其余情况 target 一定在 x 的右边
> 
> - 如果 `x > nums[n−1]`，说明 x 在第一段中，那么 target 也必须在第一段中（否则 target 一定在 x 的右边）且 x 必须大于等于 target。
> 	- 写成代码就是 `target > nums[n - 1] && x >= target`。
> - 如果 `x <= nums[n−1]`，说明 x 在第二段中（或者 nums 只有一段），那么 target 可以在第一段，也可以在第二段。
> 	- 如果 target 在第一段，那么 target 一定在 x 左边。
> 	- 如果 target 在第二段，那么 x 必须大于等于 target。
> 	- 写成代码就是 `target > nums[n - 1] || x >= target`。

```python
# 写法二
class Solution:
    def search(self, nums: List[int], target: int) -> int:
        def check(i):
            x = nums[i]
            if x > nums[-1]:
                return target > nums[-1] and x >= target
            return target > nums[-1] or x >= target

        left, right = 0, len(nums)
        while left < right:
            mid = left + (right - left) // 2
            if check(mid):
                right = mid
            else:
                left = mid + 1
        return left if nums[left] == target else -1
```

### [153. 寻找旋转排序数组中的最小值](https://leetcode.cn/problems/find-minimum-in-rotated-sorted-array/)

> `x=nums[mid]` 判断 x 和数组最小值的位置关系，谁在左边，谁在右边？
> 
> 把 x 与最后一个数 `nums[n−1]` 比大小
> 
> - 如果 `x>nums[n−1]`，那么可以推出以下结论：
> 	- nums 一定被分成左右两个递增段；
> 	- 第一段的所有元素均大于第二段的所有元素；
> 	- x 在第一段。
> 	- 最小值在第二段。
> 	- 所以 x 一定在最小值的左边。
> - 如果 `x <= nums[n−1]`，那么 x 一定在第二段。（或者 nums 就是递增数组，此时只有一段。）
> 	- x 要么是最小值，要么在最小值右边。

> 对于二分来说，代码中的 `if (nums[mid] > nums[-1])` 在 `mid = n − 1` 的时候一定不成立。所以对于左闭右开的写法，right 可以选择从 `n - 1` 处开始

```python
class Solution:
    def findMin(self, nums: List[int]) -> int:
        left = 0
        right = len(nums) - 1
        while left < right:
            mid = left + (right - left) // 2
            if nums[mid] > nums[-1]:
                left = mid + 1
            else:
                right = mid
        return nums[left]
```

### [4. 寻找两个正序数组的中位数](https://leetcode.cn/problems/median-of-two-sorted-arrays/)

## 栈

### [20. 有效的括号](https://leetcode.cn/problems/valid-parentheses/)

### [155. 最小栈](https://leetcode.cn/problems/min-stack/)

### [394. 字符串解码](https://leetcode.cn/problems/decode-string/)

### [739. 每日温度](https://leetcode.cn/problems/daily-temperatures/)

> 去掉无用数据从而保证栈中数据有序

```python
class Solution:
    def dailyTemperatures(self, temperatures: List[int]) -> List[int]:
        n = len(temperatures)
        ans = [0] * n
        st = []
        for i in range(n - 1, -1, -1):
            t = temperatures[i]
            while st and t >= temperatures[st[-1]]:
                st.pop()
            if st:
                ans[i] = st[-1] - i
            st.append(i)
        return ans
```

```python
class Solution:
    def dailyTemperatures(self, temperatures: List[int]) -> List[int]:
        n = len(temperatures)
        ans = [0] * n
        st = []
        for i, t in enumerate(temperatures):
            while st and t > temperatures[st[-1]]:
                j = st.pop()
                ans[j] = i - j
            st.append(i)
        return ans
```

### [84. 柱状图中最大的矩形](https://leetcode.cn/problems/largest-rectangle-in-histogram/)

## 堆

### [215. 数组中的第K个最大元素](https://leetcode.cn/problems/kth-largest-element-in-an-array/)

### [347. 前 K 个高频元素](https://leetcode.cn/problems/top-k-frequent-elements/)

### [295. 数据流的中位数](https://leetcode.cn/problems/find-median-from-data-stream/)

## 贪心算法

### [121. 买卖股票的最佳时机](https://leetcode.cn/problems/best-time-to-buy-and-sell-stock/)

### [55. 跳跃游戏](https://leetcode.cn/problems/jump-game/)

### [45. 跳跃游戏 II](https://leetcode.cn/problems/jump-game-ii/)

### [763. 划分字母区间](https://leetcode.cn/problems/partition-labels/)

## 动态规划

### [70. 爬楼梯](https://leetcode.cn/problems/climbing-stairs/)

### [118. 杨辉三角](https://leetcode.cn/problems/pascals-triangle/)

### [198. 打家劫舍](https://leetcode.cn/problems/house-robber/)

![[attachments/20260214.png]]

```python
class Solution:
    def rob(self, nums: List[int]) -> int:
        n = len(nums)
        # cache = [-1] * n
        @cache
        def dfs(i):
            if i < 0:
                return 0
            # if cache[i] != -1:
            #     return cache[i]
            res = max(dfs(i - 1), dfs(i - 2) + nums[i])
            # cache[i] = res
            return res

        return dfs(n - 1)
```

![[attachments/20260214-1.png]]

```python
class Solution:  
    def rob(self, nums: List[int]) -> int:  
        f = [0] * (len(nums) + 2)  
        for i, x in enumerate(nums):  
            f[i + 2] = max(f[i + 1], f[i] + x)  
        return f[-1]
```

```python
# 空间上进行优化
class Solution:
    def rob(self, nums: List[int]) -> int:
        f0 = f1 = 0
        for x in nums:
            f0, f1 = f1, max(f1, f0 + x)
        return f1
```

### [279. 完全平方数](https://leetcode.cn/problems/perfect-squares/)

### [322. 零钱兑换](https://leetcode.cn/problems/coin-change/)

```python
class Solution:
    def coinChange(self, coins: List[int], amount: int) -> int:
        n = len(coins)

        @cache
        def dfs(i, c):
            if i < 0:
                return 0 if c == 0 else inf
            if c < coins[i]:
                return dfs(i - 1, c)
            return min(dfs(i - 1, c), dfs(i, c - coins[i]) + 1)

        ans = dfs(n - 1, amount)
        return ans if ans < inf else -1
```

```python
class Solution:
    def coinChange(self, coins: List[int], amount: int) -> int:
        n = len(coins)
        # f = [[inf] * (amount + 1) for _ in range(n + 1)]
        f = [[inf] * (amount + 1) for _ in range(2)]
        f[0][0] = 0
        for i, x in enumerate(coins):
            for c in range(amount + 1):
                if c < x:
                    # f[i + 1][c] = f[i][c]
                    f[(i + 1) % 2][c] = f[i % 2][c]
                else:
                    # f[i + 1][c] = min(f[i][c], f[i + 1][c - x] + 1)
                    f[(i + 1) % 2][c] = min(f[i % 2][c], f[(i + 1) % 2][c - x] + 1)
        ans = f[n % 2][amount]
        return ans if ans < inf else -1
```

### [139. 单词拆分](https://leetcode.cn/problems/word-break/)

### [300. 最长递增子序列](https://leetcode.cn/problems/longest-increasing-subsequence/)

```python
class Solution:
    def lengthOfLIS(self, nums: List[int]) -> int:
        n = len(nums)

        @cache
        def dfs(i):
            res = 0
            for j in range(i):
                if nums[j] < nums[i]:
                    res = max(res, dfs(j))
            return res + 1

        ans = 0
        for i in range(n):
            ans = max(ans, dfs(i))
        return ans
        # return max(dfs(i) for i in range(n))
```

```python
class Solution:
    def lengthOfLIS(self, nums: List[int]) -> int:
        n = len(nums)

        f = [0] * n
        for i in range(n):
            for j in range(i):
                if nums[j] < nums[i]:
                    f[i] = max(f[i], f[j])
            f[i] += 1
        return max(f)
```

### [152. 乘积最大子数组](https://leetcode.cn/problems/maximum-product-subarray/)

### [416. 分割等和子集](https://leetcode.cn/problems/partition-equal-subset-sum/)

### [32. 最长有效括号](https://leetcode.cn/problems/longest-valid-parentheses/)

## 多维动态规划

### [62. 不同路径](https://leetcode.cn/problems/unique-paths/)

### [64. 最小路径和](https://leetcode.cn/problems/minimum-path-sum/)

### [5. 最长回文子串](https://leetcode.cn/problems/longest-palindromic-substring/)

### [1143. 最长公共子序列](https://leetcode.cn/problems/longest-common-subsequence/)

```python
class Solution:
    def longestCommonSubsequence(self, text1: str, text2: str) -> int:
        n = len(text1)
        m = len(text2)

        @cache
        def dfs(i, j):
            if i < 0 or j < 0:
                return 0
            if text1[i] == text2[j]:
                return dfs(i - 1, j - 1) + 1
            return max(dfs(i - 1, j), dfs(i, j - 1))

        return dfs(n - 1, m - 1)
```

```python
class Solution:
    def longestCommonSubsequence(self, text1: str, text2: str) -> int:
        n = len(text1)
        m = len(text2)

        # f = [[0] * (m + 1) for _ in range(n + 1)]
        f = [[0] * (m + 1) for _ in range(2)]
        for i in range(n):
            for j in range(m):
                if text1[i] == text2[j]:
                    # f[i + 1][j + 1] = f[i][j] + 1
                    f[(i + 1) % 2][j + 1] = f[i % 2][j] + 1
                else:
                    # f[i + 1][j + 1] = max(f[i][j + 1], f[i + 1][j])
                    f[(i + 1) % 2][j + 1] = max(f[i % 2][j + 1], f[(i + 1) % 2][j])

        return f[n % 2][m]
```

### [72. 编辑距离](https://leetcode.cn/problems/edit-distance/)

```python
class Solution:
    def minDistance(self, word1: str, word2: str) -> int:
        n = len(word1)
        m = len(word2)

        @cache
        def dfs(i, j):
            if i < 0:
                return j + 1
            if j < 0:
                return i + 1
            if word1[i] == word2[j]:
                return dfs(i - 1, j - 1)
            # 这三种情况分别代表 插入，删除，替换
            return min(dfs(i, j - 1), dfs(i - 1, j), dfs(i - 1, j - 1)) + 1

        return dfs(n - 1, m - 1)
```

```python
class Solution:
    def minDistance(self, word1: str, word2: str) -> int:
        n = len(word1)
        m = len(word2)

        # f = [[0] * (m + 1) for _ in range(n + 1)]
        f = [[0] * (m + 1) for _ in range(2)]
        f[0] = list(range(m + 1))
        for i in range(n):
            # f[i + 1][0] = i + 1
            f[(i + 1) % 2][0] = i + 1
            for j in range(m):
                if word1[i] == word2[j]:
                    # f[i + 1][j + 1] = f[i][j]
                    f[(i + 1) % 2][j + 1] = f[i % 2][j]
                else:
                    # f[i + 1][j + 1] = min(f[i][j + 1], f[i + 1][j], f[i][j]) + 1
                    f[(i + 1) % 2][j + 1] = min(f[i % 2][j + 1], f[(i + 1) % 2][j], f[i % 2][j]) + 1
        return f[n % 2][m]
```

## 技巧

### [136. 只出现一次的数字](https://leetcode.cn/problems/single-number/)

### [169. 多数元素](https://leetcode.cn/problems/majority-element/)

### [75. 颜色分类](https://leetcode.cn/problems/sort-colors/)

### [31. 下一个排列](https://leetcode.cn/problems/next-permutation/)

### [287. 寻找重复数](https://leetcode.cn/problems/find-the-duplicate-number/)