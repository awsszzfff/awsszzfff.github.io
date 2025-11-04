---
title: "LeetCode"
date: 2024-09-30
tags:
  - Others
categories:
  - Others
---
## [1. 两数之和](https://leetcode.cn/problems/two-sum/description/)

![[attachments/Pasted image 20240922203529.png]]

### 暴力破解

```python
class Solution:
    # Brute Force
    # N is the size of nums
    # Time Complexity: O(N^2)
    # Space COmplexity: O(1)
    def twoSum(self, nums: List[int], target: int) -> List[int]:
        result = []
        for i in range(len(nums)):
            for j in range(i+1,len(nums)):
                sum = nums[i] + nums[j]
                if sum == target:
                    result.append(i)
                    result.append(j)
                    return result

        return []
```

```java
class Solution {
    public int[] twoSum(int[] nums, int target) {
        int[] result = new int[2];
        for(int i = 0;i<nums.length;i++){
            for(int j = i+1;j<nums.length;j++){
                int sum = nums[i] + nums[j];
                if(sum == target){
                    result[0] = i;
                    result[1] = j;
                    return result;
                }
            }
        }
        return result;
    }
}
```

### 哈希表法

```python
class Solution:
    # Hash Table
    # N is the size of nums
    # Time Complexity: O(N)
    # Space COmplexity: O(N)
    def twoSum(self, nums: List[int], target: int) -> List[int]:
        result = []
        mapping = {}
        for i in range(0, len(nums)):
            mapping[nums[i]] = i
        for j in range(0, len(nums)):
            diff = target - nums[j]
            if (diff in mapping and mapping[diff] != j):
                result.append(j);
                result.append(mapping[diff]);
                return result
        return []
```

```java
class Solution {
    public int[] twoSum(int[] nums, int target) {
        int[] result = new int[2];
        HashMap<Integer, Integer> map = new HashMap<>();
        for (int i = 0; i < nums.length; i++) {
            map.put(nums[i], i);
        }
        for (int j = 0; j < nums.length; j++) {
            int diff = target - nums[j];
            if (map.containsKey(diff) && map.get(diff) != j) {
                result[0] = j;
                result[1] = map.get(diff);
                return result;
            }
        }
        return result;
    }
}
```



![[attachments/Pasted image 20240922203928.png]]
![[attachments/Pasted image 20240922203954.png]]
![[attachments/Pasted image 20240922204023.png]]









