---
title: Sandbox的基础知识
date: 2023-01-02 00:01:20
categories: 
- pwn
tags: 
- pwn
- sandbox
---
Sandbox的基础知识
<!--more-->

## Sandbox

[https://www.cnblogs.com/L0g4n-blog/p/12839171.html]

沙箱(Sandbox)是程序中的一种隔离机制，其目的是**限制不可信进程和不可信代码的访问权限**。

seccomp是内核中的一种安全机制，seccomp可以在程序中**禁用掉一些系统调用**来达到保护系统安全的目的，seccomp规则的设置，可以使用prctl函数和seccomp函数族。

prctl()函数：

prctl是基本的进程管理函数，最原始的沙箱规则就是通过prctl函数来实现的，它可以**决定有哪些系统调用函数可以被调用，哪些系统调用函数不能被调用**。

```c
int prctl(int option,unsigned long argv2,unsigned long argv3,unsigned long argv4，unsigned long argv5)
```

参数option是选项，表示你要干什么，后面的参数都是对该option的辅助。

参数option需要重点关注的有：

- PR_SET_SECCOMP(也就是22):当第一个参数是PR_SET_SECCOMP,第二个参数**argv2为1**的时候，表示允许的系统调用有**read，write，exit和sigereturn**；当**argv2等于2**的时候，表示允许的系统调用**由argv3指向sock_fprog结构体定义**，该结构体成员指向的sock_filter可以定义过滤任意系统调用和系统调用参数。
- PR_SET_NO_NEWPRIVS(也就是38):prctl(38,1,0,0,0)表示禁用系统调用execve()函数，同时，这个选项可以通过fork()函数和clone()函数**继承给子进程**。

## 绕过沙箱

### orw

一般最普通的沙箱都是禁用了`execve`类的函数，这将会导致我们无法使用`one_gadget`和`system("/bin/sh\x00")`来get shell。但是pwn的最终结果并不是要求我们get shell，而是要求我们能拿到flag，所以我们可以面向flag编程，使用`open -> read -> write`来打开，读取最后输出flag。

`orw`过程的实现可以是通过**ROP**链的`orw`，也可以是通过**shellcode**的`orw`，甚至可以使用`shellcraft.cat("./flag\x00")`原理上都是一样的。

```py
shellcode=asm(
    '''
    mov rax, 0x67616c662f
    push rax
    
    push 0x2
    pop rax
    mov rdi, rsp
    mov rdx, 0x440
    xor rsi, rsi
    syscall

    mov rdi, rax
    sub rsp, rdx
    mov rsi, rsp
    xor rax, rax
    syscall

    mov rdx, rax
    push 0x2
    pop rdi
    push 0x1
    pop rax
    syscall 
    
    '''
)
```

### 利用x32ABI

当`orw`的系统调用均不可行时，可以利用64位系统对32位程序的支持来实现`orw`。

`x32 ABI`是ABI (Application Binary Interface)，同样也是linux系统内核接口之一。x32 ABI允许在64位架构下（包括指令集、寄存器等）使用32位指针。

`x32 ABI`与64位下的系统调用方法几乎无异（一样走syscall），只不过系统调用号都是不小于**0x40000000**，并且要求使用32位指针。

部分沙箱会缺少对`X32 ABI`的限制

```sh
 0003: 0x35 0x05 0x00 0x40000000  if (A >= 0x40000000) goto ALLOW # 允许sys_number>=0x40000000
```

具体的调用表可以查看系统头文件中的`/usr/src/linux-headers-$version-generic/arch/x86/include/generated/uapi/asm/unistd_x32.h`，大致如下：

```c
// #define __X32_SYSCALL_BIT	0x40000000

#ifndef _UAPI_ASM_UNISTD_X32_H
#define _UAPI_ASM_UNISTD_X32_H

#define __NR_read (__X32_SYSCALL_BIT + 0)
#define __NR_write (__X32_SYSCALL_BIT + 1)
#define __NR_open (__X32_SYSCALL_BIT + 2)
#define __NR_close (__X32_SYSCALL_BIT + 3)

...

#endif /* _UAPI_ASM_UNISTD_X32_H */
```

因此这里我们就可以利用`0x40000002`的`open`来补上`orw`缺少的`open`。

### 利用32位模式

32位模式即64位系统下运行32位程序的模式，此时**CS寄存器的值为0x23**。在该模式下，程序与在32位系统中运行几乎无异，即只能使用32位寄存器，所有指针必须为32位，指令集为32位指令集等。

与之相对地，**64位模式对应的CS寄存器的值为0x33**。

进入32位模式需要更改CS寄存器为0x23。retf (far return) 指令可以帮助我们做到这一点。retf指令相当于：

```asm
pop ip # 下一条指令
pop cs # 修改cs寄存器
```

需要注意的是，在使用pwntools构造shellcode时，需要指定retf的地址长度，即可以使用retfd和retfq。

因为进入32位模式后，sp, ip寄存器也会变成32位，所以需要将**栈迁移至32位地址上**；利用或构造32位地址的RWX内存段，写入**32位shellcode**；最后在栈上构造fake ip, cs，执行**retf**指令。

利用前提：

- 沙箱中不包含对arch==ARCH_x86_64的检测
- 存在或可构造32位地址的RWX内存段

其中，构造RWX内存段可使用mmap申请新的内存，或使用mprotect使已有的段变为RWX权限。

### 其他

