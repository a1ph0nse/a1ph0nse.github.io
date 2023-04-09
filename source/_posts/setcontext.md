---
title: setcontext
date: 2023-01-13 17:37:42
tags: 
- pwn
- setcontext
categories:
- pwn
---

`setcontext`是`libc`中的一个函数，其中的部分代码可以用来给大部分寄存器进行赋值，不仅可以用于**控制寄存器，还能劫持程序流**，通常在**堆利用并且开启沙箱时用来劫持程序流走`orw`**。

<!--more-->

`setcontext`大致可以把2.27，2.29做为两个分界点。在2.27及以前，`setcontext`**以寄存器`rdi`为基准，对寄存器进行赋值，从`setcontext+53`开始**利用；在2.29及以后，`setcontext`**以寄存器`rdx`为基准，对寄存器进行赋值，并且利用的代码有些许区别，在2.31以后从`setcontext+61`开始**利用。

## glibc-2.27及以前

这里以2.27-3ubuntu1.6_amd64为例：

```asm
   0x0000000000052050 <+0>:		push   rdi
   0x0000000000052051 <+1>:		lea    rsi,[rdi+0x128]
   0x0000000000052058 <+8>:		xor    edx,edx
   0x000000000005205a <+10>:	mov    edi,0x2
   0x000000000005205f <+15>:	mov    r10d,0x8
   0x0000000000052065 <+21>:	mov    eax,0xe
   0x000000000005206a <+26>:	syscall 
   0x000000000005206c <+28>:	pop    rdi
   0x000000000005206d <+29>:	cmp    rax,0xfffffffffffff001
   0x0000000000052073 <+35>:	jae    0x520d0 <setcontext+128>
   0x0000000000052075 <+37>:	mov    rcx,QWORD PTR [rdi+0xe0]
   0x000000000005207c <+44>:	fldenv [rcx]
   0x000000000005207e <+46>:	ldmxcsr DWORD PTR [rdi+0x1c0]   # 会造成程序执行时直接 crash
   0x0000000000052085 <+53>:	mov    rsp,QWORD PTR [rdi+0xa0] # 利用从这里开始
   0x000000000005208c <+60>:	mov    rbx,QWORD PTR [rdi+0x80]
   0x0000000000052093 <+67>:	mov    rbp,QWORD PTR [rdi+0x78]
   0x0000000000052097 <+71>:	mov    r12,QWORD PTR [rdi+0x48]
   0x000000000005209b <+75>:	mov    r13,QWORD PTR [rdi+0x50]
   0x000000000005209f <+79>:	mov    r14,QWORD PTR [rdi+0x58]
   0x00000000000520a3 <+83>:	mov    r15,QWORD PTR [rdi+0x60]
   0x00000000000520a7 <+87>:	mov    rcx,QWORD PTR [rdi+0xa8]	
   0x00000000000520ae <+94>:	push   rcx 					   # 这里入栈后ret会ret到该地址
   0x00000000000520af <+95>:	mov    rsi,QWORD PTR [rdi+0x70]
   0x00000000000520b3 <+99>:	mov    rdx,QWORD PTR [rdi+0x88]
   0x00000000000520ba <+106>:	mov    rcx,QWORD PTR [rdi+0x98]
   0x00000000000520c1 <+113>:	mov    r8,QWORD PTR [rdi+0x28]
   0x00000000000520c5 <+117>:	mov    r9,QWORD PTR [rdi+0x30]
   0x00000000000520c9 <+121>:	mov    rdi,QWORD PTR [rdi+0x68]
   0x00000000000520cd <+125>:	xor    eax,eax
   0x00000000000520cf <+127>:	ret    						   # ret 劫持程序流
   0x00000000000520d0 <+128>:	mov    rcx,QWORD PTR [rip+0x398d91]        # 0x3eae68
   0x00000000000520d7 <+135>:	neg    eax
   0x00000000000520d9 <+137>:	mov    DWORD PTR fs:[rcx],eax
   0x00000000000520dc <+140>:	or     rax,0xffffffffffffffff
   0x00000000000520e0 <+144>:	ret 
```

从`<setcontext+53>~<setcontext+127>`都是我们的利用范围，可以看到这部分代码以 **rdi 寄存器里的地址为基准**设置各个寄存器的值，其中**`push rcx`和后面的`ret`会使得`rip=rcx`**，而且`setcontext`最后会**`xor eax, eax`对`eax`进行赋0**。

大部分题目中通过控制 rsp 和 rip 就可以很好地解决堆题不方便直接控制程序的执行流的问题，可以将`setcontext + 53`写进`__free_hook`或`__malloc_hook`中，然后建立或释放一个`chunk`，此时的`rdi`就会是该`chunk`的（`user_data?`）开头，如果我们提前布局好堆，就意味着我们可以控制寄存器并劫持程序流。

如果需要打`IO`流的话，我们可以将`setcontext + 53`写入`vtable`中，后面执行该`IO`函数时，`rdi`就会是`fp`，指向`IO_FILE`，如果我们伪造好了`IO_FILE`，同样可以劫持程序流。

## glibc-2.29及以后

这里以2.31-0ubuntu9.9_amd64为例：

```asm
   0x0000000000054f20 <+0>:		endbr64 
   0x0000000000054f24 <+4>:		push   rdi
   0x0000000000054f25 <+5>:		lea    rsi,[rdi+0x128]
   0x0000000000054f2c <+12>:	xor    edx,edx
   0x0000000000054f2e <+14>:	mov    edi,0x2
   0x0000000000054f33 <+19>:	mov    r10d,0x8
   0x0000000000054f39 <+25>:	mov    eax,0xe
   0x0000000000054f3e <+30>:	syscall 
   0x0000000000054f40 <+32>:	pop    rdx
   0x0000000000054f41 <+33>:	cmp    rax,0xfffffffffffff001
   0x0000000000054f47 <+39>:	jae    0x5506f <setcontext+335>
   0x0000000000054f4d <+45>:	mov    rcx,QWORD PTR [rdx+0xe0]
   0x0000000000054f54 <+52>:	fldenv [rcx]
   0x0000000000054f56 <+54>:	ldmxcsr DWORD PTR [rdx+0x1c0]
   0x0000000000054f5d <+61>:	mov    rsp,QWORD PTR [rdx+0xa0] # 利用从这里开始
   0x0000000000054f64 <+68>:	mov    rbx,QWORD PTR [rdx+0x80]
   0x0000000000054f6b <+75>:	mov    rbp,QWORD PTR [rdx+0x78]
   0x0000000000054f6f <+79>:	mov    r12,QWORD PTR [rdx+0x48]
   0x0000000000054f73 <+83>:	mov    r13,QWORD PTR [rdx+0x50]
   0x0000000000054f77 <+87>:	mov    r14,QWORD PTR [rdx+0x58]
   0x0000000000054f7b <+91>:	mov    r15,QWORD PTR [rdx+0x60]
   0x0000000000054f7f <+95>:	test   DWORD PTR fs:0x48,0x2
   0x0000000000054f8b <+107>:	je     0x55046 <setcontext+294> # 这里会跳转走
   0x0000000000054f91 <+113>:	mov    rsi,QWORD PTR [rdx+0x3a8]
   0x0000000000054f98 <+120>:	mov    rdi,rsi
   0x0000000000054f9b <+123>:	mov    rcx,QWORD PTR [rdx+0x3b0]
   0x0000000000054fa2 <+130>:	cmp    rcx,QWORD PTR fs:0x78
   0x0000000000054fab <+139>:	je     0x54fe5 <setcontext+197>
   0x0000000000054fad <+141>:	mov    rax,QWORD PTR [rsi-0x8]
   0x0000000000054fb1 <+145>:	and    rax,0xfffffffffffffff8
   0x0000000000054fb5 <+149>:	cmp    rax,rsi
   0x0000000000054fb8 <+152>:	je     0x54fc0 <setcontext+160>
   0x0000000000054fba <+154>:	sub    rsi,0x8
   0x0000000000054fbe <+158>:	jmp    0x54fad <setcontext+141>
   0x0000000000054fc0 <+160>:	mov    rax,0x1
   0x0000000000054fc7 <+167>:	incsspq rax
   0x0000000000054fcc <+172>:	rstorssp QWORD PTR [rsi-0x8]
   0x0000000000054fd1 <+177>:	saveprevssp 
   0x0000000000054fd5 <+181>:	mov    rax,QWORD PTR [rdx+0x3b0]
   0x0000000000054fdc <+188>:	mov    QWORD PTR fs:0x78,rax
   0x0000000000054fe5 <+197>:	rdsspq rcx
   0x0000000000054fea <+202>:	sub    rcx,rdi
   0x0000000000054fed <+205>:	je     0x5500c <setcontext+236>
   0x0000000000054fef <+207>:	neg    rcx
   0x0000000000054ff2 <+210>:	shr    rcx,0x3
   0x0000000000054ff6 <+214>:	mov    esi,0xff
   0x0000000000054ffb <+219>:	cmp    rcx,rsi
   0x0000000000054ffe <+222>:	cmovb  rsi,rcx
   0x0000000000055002 <+226>:	incsspq rsi
   0x0000000000055007 <+231>:	sub    rcx,rsi
   0x000000000005500a <+234>:	ja     0x54ffb <setcontext+219>
   0x000000000005500c <+236>:	mov    rsi,QWORD PTR [rdx+0x70]
   0x0000000000055010 <+240>:	mov    rdi,QWORD PTR [rdx+0x68]
   0x0000000000055014 <+244>:	mov    rcx,QWORD PTR [rdx+0x98]
   0x000000000005501b <+251>:	mov    r8,QWORD PTR [rdx+0x28]
   0x000000000005501f <+255>:	mov    r9,QWORD PTR [rdx+0x30]
   0x0000000000055023 <+259>:	mov    r10,QWORD PTR [rdx+0xa8]
   0x000000000005502a <+266>:	mov    rdx,QWORD PTR [rdx+0x88]
   0x0000000000055031 <+273>:	rdsspq rax
   0x0000000000055036 <+278>:	cmp    r10,QWORD PTR [rax]
   0x0000000000055039 <+281>:	mov    eax,0x0
   0x000000000005503e <+286>:	jne    0x55043 <setcontext+291>
   0x0000000000055040 <+288>:	push   r10
   0x0000000000055042 <+290>:	ret    
   0x0000000000055043 <+291>:	jmp    r10
   0x0000000000055046 <+294>:	mov    rcx,QWORD PTR [rdx+0xa8] # 跳转到这里继续
   0x000000000005504d <+301>:	push   rcx					  # 通过push rcx控制rip
   0x000000000005504e <+302>:	mov    rsi,QWORD PTR [rdx+0x70]
   0x0000000000055052 <+306>:	mov    rdi,QWORD PTR [rdx+0x68]
   0x0000000000055056 <+310>:	mov    rcx,QWORD PTR [rdx+0x98]
   0x000000000005505d <+317>:	mov    r8,QWORD PTR [rdx+0x28]
   0x0000000000055061 <+321>:	mov    r9,QWORD PTR [rdx+0x30]
   0x0000000000055065 <+325>:	mov    rdx,QWORD PTR [rdx+0x88]
   0x000000000005506c <+332>:	xor    eax,eax
   0x000000000005506e <+334>:	ret    						  # 劫持程序流
   0x000000000005506f <+335>:	mov    rcx,QWORD PTR [rip+0x196dfa]        # 0x1ebe70
   0x0000000000055076 <+342>:	neg    eax
   0x0000000000055078 <+344>:	mov    DWORD PTR fs:[rcx],eax
   0x000000000005507b <+347>:	or     rax,0xffffffffffffffff
   0x000000000005507f <+351>:	ret 
```

由于2.29以后是以 **rdx 寄存器里的地址为基准**设置各个寄存器的值，而修改`__free_hook`或者`__malloc_hook`时往往只有一个参数，不能稳定地控制`rdx`，因此我们需要找一个`gadget`帮助我们将`rdi`的值赋给`rdx`。

```asm
mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
```

这个`gadget`在2.29和2.31中都有，它会将`rdi + 0x8`指向的内容赋值给`rdx`，最后会`call [rdx + 0x20]`。我们可以将这个`gadget`的地址写到`hook`中，并在`chunk+0x8`处写入`rdx`的值，并在`rdx+0x20`处写入`setcontext`。

如果走`IO_FILE`，利用方法也差不多。不过走`_IO_switch_to_wget_mode `的链可以设置`rdx`，具体看`House of Cat`。

## SigreturnFrame

`SigreturnFrame`是`pwntools`中的一个控制寄存器的工具，常用在SROP中，这个工具实际上就是依靠`setcontext`实现的，我们可以用它来构造`setcontext`中的偏移，只需要在调用`setcontext`前将`rdi`或`rdx`指向`SigreturnFrame`，程序在执行`setcontext`时就会按照定义好的内容控制寄存器，用法如下：

```python
frame = SigreturnFrame()
frame.rsp = xxx
frame.rdi = xxx
frame.rsi = xxx
frame.rdx = xxx
frame.rip = xxx
```
