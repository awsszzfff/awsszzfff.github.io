---
title: pymysql
date: 2025-12-26
updated: 2025-12-26
tags:
  - Python模块
categories:
  - 程序设计
description: None
---
基础

```python
import pymysql
from pymysql.cursors import Cursor, DictCursor

conn = pymysql.connect(
    user="emp",
    password="emp123",
    database="emp_data",
    host="127.0.0.1",
    port=3306,
    # 当前数据库编码格式
    charset="utf8",
    # cursorclass 对返回数据进行进一步处理
    # cursorclass=Cursor    # 返回数据为元组，不带字段名
    cursorclass=DictCursor  # 返回数据为字典，带字段名
)

# 创建一个 cursor 对象来操作数据库
cursor = conn.cursor()
# <pymysql.cursors.DictCursor object at 0x000001EF97ADA7D0>

sql = "select * from emp;"
cursor.execute(sql)
# result = cursor.fetchone()    # 一条数据
result = cursor.fetchall()  # 所有数据
print(result)

```

基本操作（原生模式会存在 sql 注入的情况）

```sql
drop database if exists user_data;
create database user_data;
use user_data;
create table user(
    id int primary key auto_increment ,
    username varchar(32) unique not null, 
    password varchar(32)
);
insert into user(username,password) values("dream","521521"),("hope","369369");
```

```python
import pymysql
from pymysql.cursors import DictCursor, Cursor


class MysqlHandler(object):
    def __init__(self):
        self.conn = pymysql.connect(
            user="user",
            password="user123",
            database="user_data",
            host="127.0.0.1",
            port=3306,
            # 当前数据库编码格式
            charset="utf8",
            # cursorclass 对返回数据进行进一步处理
            # cursorclass=Cursor    # 返回数据为元组，不带字段名
            cursorclass=DictCursor,  # 返回数据为字典，带字段名
            autocommit=False,  # 默认False，需要手动提交事务；True 自动提交事务
        )

        # 创建游标对象
        self.cursor = self.conn.cursor()

    # 查询
    def search_data_option(self):
        # 原生sql
        sql = "select * from user;"
        self.cursor.execute(sql)
        # result = self.cursor.fetchone()   # 一条数据
        # result = self.cursor.fetchall()   # 所有数据
        # result = self.cursor.fetchmany(size=2)  # 获取指定数量的数据

        # 移动"光标" value 移动指定行数 mode 移动模式 relative 相对模式 absolute 绝对模式（相对起始索引）
        # result = self.cursor.scroll(value=1, mode="relative")

        return self.cursor.fetchall()

    # 插入
    def insert_data_option(self):
        # 普通插入
        # sql = f"insert into user(username, password) values ('dream_one', '123456');"
        # self.cursor.execute(sql)

        # 字符串格式化输入语法
        # username = "dream_two"
        # password = "123456"
        # sql = f"insert into user(username, password) values ('{username}', '{password}');"
        # print(sql)

        # 格式化输出语法
        username = "dream_three"
        password = "123456"
        '''
        转换说明符	            解释
        %d、%i	        转换为带符号的十进制数
        %o	            转换为带符号的八进制数
        %x、%X	        转换为带符号的十六进制数
        %e	            转化为科学计数法表示的浮点数（e 小写）
        %E	            转化为科学计数法表示的浮点数（E 小写）
        %f、%F	        转化为十进制浮点数
        %g	            智能选择使用 %f 或 %e 格式
        %G	            智能选择使用 %F 或 %E 格式
        %c	            格式化字符及其ASCII码
        %r	            使用 repr() 函数将表达式转换为字符串
        %s	            使用 str() 函数将表达式转换为字符串
        '''
        # 按照位置传参
        # sql = "insert into user(username, password) values (%s, %s);"
        # self.cursor.execute(sql, [username, password])

        # 按照关键字传参
        sql = 'insert into user(username,password) values(%(name)s,%(pwd)s);'
        self.cursor.execute(sql, {"name": username, "pwd": password})

        # 执行后要提交事务
        self.conn.commit()

    # 更新
    def update_data_option(self):
        # 原生
        # sql = "update user set username='dream_1' where username='dream_one';"
        # self.cursor.execute(sql)

        # 按照位置/关键字传参
        sql = "update user set username=%(new_username)s where username=%(old_username)s;"
        self.cursor.execute(sql, {"new_username": "dream_2", "old_username": "dream_two"})
        self.conn.commit()

    # 删除
    def delete_data_option(self):
        # 原生
        # sql = "delete from user where username='dream_4';"
        # self.cursor.execute(sql)

        # 按照位置/关键字传参
        sql = "delete from user where username=%(del_name)s;"
        self.cursor.execute(sql, {"del_name": "dream_4"})
        self.conn.commit()

    # 批量插入
    def insert_data_batch(self):
        # 原生
        # sql = "insert into user(username, password) values ('dream','521521'),('hope','369369');"
        # self.cursor.execute(sql)

        # 关键字
        # sql = "insert into user(username, password) values (%(username)s, %(password)s);"
        # self.cursor.executemany(sql,[
        #     {"username": "dream_4", "password": "521521"},
        #     {"username": "hope_4", "password": "369369"},
        # ])

        # 位置
        sql = "insert into user(username, password) values (%s, %s);"
        self.cursor.executemany(sql, [
            ("dream_4", "521521"),
            ("hope_4", "369369"),
        ])

        self.conn.commit()

    def __del__(self):
        self.cursor.close()
        self.conn.close()


if __name__ == '__main__':
    handle = MysqlHandler()
    handle.insert_data_option()
    handle.search_data_option()
    handle.update_data_option()
    handle.delete_data_option()
    handle.insert_data_batch()

```