---
title: CatCFT_Welcome
date: 2023-01-10 10:52:21
tags:
- pwn
- c/s
- re
categories: 
- pwn_wp
---

CATCTF中最简单的pwn题，是c/s的题，之前没做过这类的题，现在学习一下。

<!--more-->

查壳可以看到保护全开，远程会起一个server，本地使用client与其进行交互。

这种给了客户端的题通常都是**要修改客户端代码**来帮助cat flag的。

在ida中可以看到，通过`wasd`控制符号`@`移动，走到出题人的`$`下面输入`j`即可使`glod+1`，最多可以加到`100`。

当`glod>100000000`并且在`HRP`的`@`下输入`j`，客户端就会连接客户端并返回flag，但正常情况下`glod`最多只能到100，这里就需要我们修改客户端的文件内容使其能够到100000000。

首先找到给glod赋值的位置：

```c
if ( glod <= 99 )
	++glod;
```

汇编代码中显示如下：

```asm
.text:000000000000920F 8B 05 73 11 20 00             mov     eax, cs:glod
.text:0000000000009215 83 C0 01                      add     eax, 1
.text:0000000000009218 89 05 6A 11 20 00             mov     cs:glod, eax
```

可以看到这里先将`glod`的值`mov`到`eax`，对`eax+1`后再`mov`回`glod`。

如果在此处修改`mov	eax, cs:glod`修改为`mov  eax, 5F5E100h(100000000)`，那么经过这次计算后`glod>100000000`成立，后续就可以通过`if`的判断向服务器端发送消息得到flag。

这里的修改要用到ida中的功能（我的7.7不知道为什么用不了，7.5的倒是可以用），鼠标选中对应的汇编代码后在ida上方的菜单栏中选择`edit -> Patch program -> Assemble`修改其汇编代码为`mov  eax, 5F5E100h`，之后选择`edit -> Patch program -> Apply patches to`应用该修改。

修改后的程序可以绕过判断向服务器发送信息，最后可以得到flag。
