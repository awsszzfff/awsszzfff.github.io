---
date: 2001-01-01
tags:
  - Others
categories:
  - Others
title: "XDUOJ"
---
# P9 计算球体重量

![[attachments/Pasted image 20240829181216.png]]

```c++
#include <stdio.h>

#define PI 3.1415926
#define IRON_W 7.86
#define GOLD_W 19.3
int main(void)
{
    double iron_d, gold_d;
    scanf("%lf %lf", &iron_d, &gold_d);
    double iron_r = iron_d / 2;
    double gold_r = gold_d / 2;
    double iron_m, gold_m;
    iron_m = (4 / 3.0) * PI * iron_r * iron_r * iron_r * IRON_W / 1000;
    gold_m = (4 / 3.0) * PI * gold_r * gold_r * gold_r * GOLD_W / 1000;
    printf("%.3f %.3f", iron_m, gold_m);

    return 0;
}

```

# P10 温度转换

![[attachments/Pasted image 20240829181356.png]]

```c++
#include <stdio.h>

int main(void)
{
    double fahrenheit;
    scanf("%lf", &fahrenheit);
    double centigrade;
    centigrade = (fahrenheit - 32.0) * 5.0 / 9.0;
    printf("%.2f", centigrade);

    return 0;
}

```

# P11 整数简单运算

![[attachments/Pasted image 20240829182147.png]]

```c++
#include <stdio.h>

int main()
{
    int a, b;
    scanf("%d %d", &a, &b);
    int h = a + b;
    int x = a - b;
    int j = a * b;
    int s = a / b;
    printf("%d\n%d\n%d\n%d\n", h, x, j, s);

    return 0;
}
```

# P15 A+B+C

![[attachments/Pasted image 20240829182806.png]]

```c++
#include <stdio.h>

int main()
{
    int a, b, c;
    scanf("%d %d %d", &a, &b, &c);
    int sum = a + b + c;
    printf("%d", sum);

    return 0;
}
```

# P626 就近接人

![[attachments/Pasted image 20240829232952.png]]

```c++
#include <stdio.h>
#include <math.h>

// 函数声明
int findClosest(double *points, int *visited, int currentPosIndex, int n);

int main()
{
    double coords[6];
    int visited[6] = {0}; // 用来标记是否已访问
    double result[6];

    // 读取输入
    for (int i = 0; i < 6; i++)
    {
        scanf("%lf", &coords[i]);
    }

    // 先输出起始点
    result[0] = coords[0];
    visited[0] = 1;

    // 开始接送乘客，依次找到最近的点
    int currentPosIndex = 0;
    for (int i = 1; i < 6; i++)
    {
        int closestIndex = findClosest(coords, visited, currentPosIndex, 6);
        result[i] = coords[closestIndex];
        visited[closestIndex] = 1;
        currentPosIndex = closestIndex;
    }

    // 输出结果
    for (int i = 0; i < 6; i++)
    {
        printf("%.2lf ", result[i]);
    }
    printf("\n");

    return 0;
}

// 找到离当前位置最近的未访问点
int findClosest(double *points, int *visited, int currentPosIndex, int n)
{
    int closestIndex = -1;
    double minDistance = 5000.0; // 初始化为大值
    double currentPos = points[currentPosIndex];

    for (int i = 0; i < n; i++)
    {
        if (!visited[i])
        { // 如果这个点没有访问过
            double distance = fabs(currentPos - points[i]);
            if (distance < minDistance || (distance == minDistance && i < closestIndex))
            {
                minDistance = distance;
                closestIndex = i;
            }
        }
    }

    return closestIndex;
}

```

# P627 伪随机数

![[attachments/Pasted image 20240830165021.png]]
![[attachments/Pasted image 20240830165039.png]]

```c++
#include <stdio.h>

// 生成伪随机数的函数
int generate_random(int num)
{
    long long squared = (long long)num * num; // 计算平方
    int new_num = (squared / 100) % 10000;    // 取出十万、万、千和百位的四个数字

    // 如果生成的数不足四位，用乘以10的幂补足
    if (new_num < 1000)
    {
        new_num *= 10;
    }

    return new_num;
}

int main()
{
    int input_num;

    // 输入一个四位的正整数
    scanf("%d", &input_num);

    // 检查输入是否合法
    if (input_num < 1000 || input_num > 9999)
    {
        printf("输入错误，请输入一个四位的正整数。\n");
        return 1;
    }

    int random_num = input_num;

    // 生成并输出5个伪随机数
    for (int i = 0; i < 5; i++)
    {
        random_num = generate_random(random_num);

        // 检查生成的数字是否全为0
        if (random_num == 0)
        {
            printf("failure\n");
            return 1;
        }

        printf("%04d\n", random_num);
    }

    return 0;
}

```

# P632 求所围面积

![[attachments/Pasted image 20240830171644.png]]

```c++
// 简单实现
#include <stdio.h>

int main()
{
    double y_values[10];
    int count = 0;
    double total_area = 0.0;
    double y_value;
    char input[10];

    // printf("请输入一系列正实数（不超过10个），以空格分隔，以'!'结束：\n");

    // 不断读取输入，直到遇到'!'
    while (1)
    {
        scanf("%s", input);

        // 如果输入是'!'，则结束输入
        if (input[0] == '!')
        {
            break;
        }

        // 将输入的字符串转换为浮点数
        sscanf(input, "%lf", &y_value);

        if (y_value <= 0 || count >= 10)
        {
            // printf("输入错误，请确保输入正实数且不超过10个。\n");
            return 1;
        }

        y_values[count] = y_value;
        count++;
    }

    // 计算总面积
    for (int i = 0; i < count - 1; i++)
    {
        total_area += 0.5 * (y_values[i] + y_values[i + 1]);
    }

    // 输出结果，精确到小数点后两位
    printf("%.2f\n", total_area);

    return 0;
}
```

```c++
// 用内部函数计算
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    double y_values[10];
    int count = 0;
    double total_area = 0.0;
    char input[100];

    // printf("请输入一系列正实数（不超过10个），以空格分隔，以'!'结束：\n");
    // 读取整行输入
    fgets(input, sizeof(input), stdin);

    char *token = strtok(input, " ");

    while (token != NULL)
    {
        if (token[0] == '!')
        {
            break;
        }

        // 将字符串转为浮点数
        double y_value = atof(token);
        // if (y_value <= 0 || count >= 10)
        // {
        //     // printf("输入错误，请确保输入正实数且不超过10个。\n");
        //     return 1;
        // }

        y_values[count] = y_value;
        count++;

        token = strtok(NULL, " ");
    }

    // 计算总面积
    for (int i = 0; i < count - 1; i++)
    {
        total_area += 0.5 * (y_values[i] + y_values[i + 1]);
    }

    // 输出结果，精确到小数点后两位3 2 1 5 !
    printf("%.2f\n", total_area);

    return 0;
}

```

# P634 水仙花数判断

![[attachments/Pasted image 20240830172149.png]]

```c++
#include <stdio.h>

int main()
{
    int num;
    int hundred, ten, one;
    int sum_of_cubes;

    // 输入一个正整数
    // printf("请输入一个三位数的正整数：\n");
    scanf("%d", &num);

    // 判断输入是否为三位数
    if (num < 100 || num > 999)
    {
        printf("-1\n");
        return 0; // 不合法则输出-1并返回
    }

    // 提取百位、十位和个位
    hundred = num / 100;
    ten = (num / 10) % 10;
    one = num % 10;

    // 计算各位数字的立方和
    sum_of_cubes = hundred * hundred * hundred +
                   ten * ten * ten +
                   one * one * one;

    // 判断是否为水仙花数
    if (sum_of_cubes == num)
    {
        printf("YES\n");
    }
    else
    {
        printf("NO\n");
    }

    return 0;
}
```

# P635 数字统计

![[attachments/Pasted image 20240830173521.png]]
![[attachments/Pasted image 20240830173608.png]]

```c++
#include <stdio.h>

int main()
{
    int x1, x2;
    int y1, y2;
    int start, end;
    int count_div3 = 0; // 能被3整除的整数个数
    int count_mod5 = 0; // 除以5余数小于3的整数个数

    // 输入x1和x2的值
    // printf("请输入两个整数 x1 和 x2（范围 -5 到 5）：\n");
    scanf("%d %d", &x1, &x2);

    // 计算y1和y2的值
    y1 = x1 * x1 - 2 * x1 - 3;
    y2 = -x2 * x2 + 5 * x2 + 2;

    // 确定区间的起始和结束值
    if (y1 < y2)
    {
        start = y1;
        end = y2;
    }
    else
    {
        start = y2;
        end = y1;
    }

    // 统计区间内符合条件的整数个数
    for (int i = start; i <= end; i++)
    {
        if (i % 3 == 0)
        {
            count_div3++;
        }
        if (i % 5 < 3)
        {
            count_mod5++;
        }
    }

    // 输出统计结果
    printf("%d %d\n", count_div3, count_mod5);

    return 0;
}

```

# P398 字符串压缩

【未通过】

![[attachments/Pasted image 20240830183341.png]]
![[attachments/Pasted image 20240830183414.png]]

```c++
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *compress(char *src);

char *compress(char *src)
{
    static char compressed[200]; // 用于存储压缩后的字符串
    int len = strlen(src);
    int count = 1; // 用于计数连续字符的出现次数
    int j = 0;     // compressed字符串的索引

    for (int i = 0; i < len; i++)
    {
        if (src[i] == src[i + 1])
        {
            count++;
        }
        else
        {
            compressed[j++] = src[i]; // 存储字符
            if (count >= 3)
            {
                j += sprintf(&compressed[j], "%d", count); // 存储数字部分
            }
            count = 1; // 重置计数器
        }
    }
    compressed[j] = '\0'; // 结束字符串
    return compressed;
}

int main()
{
    char src[100];
    scanf("%s", src);

    char *ps = compress(src);
    puts(ps);

    return 0;
}

```

# P425 猴子爬山

![[attachments/Pasted image 20240830212958.png]]

```c++
#include <stdio.h>

int countWays(int n)
{
    if (n == 0)
        return 1; // 基本情况：如果没有台阶，只有一种方式，不做任何跳跃
    if (n < 0)
        return 0; // 如果台阶数为负数，没有合法的跳跃方式
    if (n == 1 || n == 2)
        return 1; // 基本情况：只有一种跳跃方式
    if (n == 3)
        return 2; // 基本情况：3个台阶有两种跳跃方式：1+1+1 或 直接跳3阶

    // 递归调用
    return countWays(n - 1) + countWays(n - 3);
}

int main()
{
    int n;
    scanf("%d", &n);

    // if (n <= 0 || n >= 50)
    // {
    //     printf("输入错误，N应在 0 < N < 50 的范围内。\n");
    //     return -1;
    // }

    int result = countWays(n);
    printf("%d\n", result);

    return 0;
}

```

# P464 阶乘
【通过一半】
![[attachments/Pasted image 20240830214627.png]]
![[attachments/Pasted image 20240830214648.png]]

```c++
#include <stdio.h>

// 函数用于计算并打印阶乘
void printFactorial(int n)
{
    if (n < 0 || n > 1000)
    {
        printf("Invalid input\n");
        return;
    }

    unsigned long long factorial = 1; // 用于存储阶乘结果

    for (int i = 1; i <= n; i++)
    {
        factorial *= i;
    }

    printf("%llu\n", factorial);
}

int main()
{
    int n;
    scanf("%d", &n);
    printFactorial(n);

    return 0;
}

```

# P688 出现次数最多的数

![[attachments/Pasted image 20240830214943.png]]

```c++
#include <stdio.h>

#define MAX_VALUE 10000 // 最大数字的范围

int main()
{
    int n;
    scanf("%d", &n);

    int frequency[MAX_VALUE + 1] = {0}; // 用于存储每个数字的出现次数
    int num;

    // 读取输入并统计每个数字的出现次数
    for (int i = 0; i < n; i++)
    {
        scanf("%d", &num);
        frequency[num]++;
    }

    // 找出出现次数最多的数字
    int max_frequency = 0;
    int most_frequent_number = MAX_VALUE + 1; // 初始化为一个超过范围的数值

    for (int i = 1; i <= MAX_VALUE; i++)
    {
        if (frequency[i] > max_frequency)
        {
            max_frequency = frequency[i];
            most_frequent_number = i;
        }
        else if (frequency[i] == max_frequency && i < most_frequent_number)
        {
            most_frequent_number = i;
        }
    }

    // 输出结果
    printf("%d\n", most_frequent_number);

    return 0;
}

```

# 
