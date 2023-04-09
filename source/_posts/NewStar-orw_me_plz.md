---
title: orw_me_plz
date: 2023-03-19 21:09:15
categories: 
- pwn_wp
tags: 
- pwn
- ROP
- 栈迁移


---

NewStar CTF Week5的题，

<!--more-->

查壳，保护全开

```sh
[*] '/home/a1ph0nse/PwnPractice/CtfGame/NewStar/orw_me_plz/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

有沙箱

```sh
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x08 0x00 0x40000000  if (A >= 0x40000000) goto 0012
 0004: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0012
 0005: 0x15 0x06 0x00 0x0000009d  if (A == prctl) goto 0012
 0006: 0x15 0x05 0x00 0x00000039  if (A == fork) goto 0012
 0007: 0x15 0x04 0x00 0x0000003a  if (A == vfork) goto 0012
 0008: 0x15 0x03 0x00 0x0000003b  if (A == execve) goto 0012
 0009: 0x15 0x02 0x00 0x00000065  if (A == ptrace) goto 0012
 0010: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

ban掉了`open`和`exec`。

和leak_me_plz有点类似，先给一个libc地址计算libcbase，之后输入一个地址，向该地址写入0x10字节的内容。

```c
void __noreturn vuln()
{
  void *buf[2]; // [rsp+0h] [rbp-10h] BYREF

  buf[1] = (void *)__readfsqword(0x28u);
  buf[0] = 0LL;
  puts("This time you need to orw.");
  printf("Here is your gift: %p\nGood luck!\n", &puts);
  printf("Addr: ");
  read(0, buf, 8uLL);
  printf("Data: ");
  read(0, buf[0], 0x10uLL);
  puts("Did you get that?");
  exit(0);
}
```



