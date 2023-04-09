---
title: pwn的Misc
date: 2023-01-02 00:01:10
categories: 
- pwn
tags: 
- pwn
---
pwn的一些杂七杂八的命令
<!--more-->

## 杂项

更换libc

```sh
patchelf --set-interpreter /home/a1ph0nse/tools/glibc-all-in-one/libs/2.31-0ubuntu9.7_amd64/ld-2.31.so --set-rpath /home/a1ph0nse/tools/glibc-all-in-one/libs/2.31-0ubuntu9.7_amd64/ filename

# 高版本libc用ld-linux-x86-64.so.2，除此之外还要
sudo cp -r /home/a1ph0nse/tools/glibc-all-in-one/libs/2.35-0ubuntu3.1_amd64/.debug/.build-id/* /usr/lib/debug/.build-id/
```

## exp模板

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename=''
elf=ELF('./'+filename)
#libc=ELF('')
p=process('./'+filename)
#p=process(["qemu-arm","-L","...","-g", "8888", "./"+filename])
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
    

itr()

```

远程脚本

```py
from pwn import *
import base64
#context.log_level = "debug"

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("127.0.0.1", 11451)
#p = process('./run.sh')
try_count = 1
while True:
    p.sendline()
    p.recvuntil("/ $")

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
        count += 1
        log.info("count: " + str(count))

    for i in range(count):
        p.recvuntil("/ $")
    
    p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline("chmod +x /tmp/exploit")
    p.sendline("/tmp/exploit ")
    break

p.interactive()
```

[kernelpwn常用库](./kernelpwn.h)

## kernel指令

```sh
# 打包cpio
find . | cpio -o -H newc > ../core.cpio
# 静态编译exp
gcc ./exp.c -o exp -static -masm=intel
```

## 通用printf_binary

```c
// this is a universal function to print binary data from a char* array
void print_binary(char* buf, int length){
	int index = 0;
	char output_buffer[80];
	memset(output_buffer, '\0', 80);
	memset(output_buffer, ' ', 0x10);
	for(int i=0; i<(length % 16 == 0 ? length / 16 : length / 16 + 1); i++){
		char temp_buffer[0x10];
		memset(temp_buffer, '\0', 0x10);
		sprintf(temp_buffer, "%#5x", index);
		strcpy(output_buffer, temp_buffer);
		output_buffer[5] = ' ';
		output_buffer[6] = '|';
		output_buffer[7] = ' ';
		for(int j=0; j<16; j++){
			if(index+j >= length)
				sprintf(output_buffer+8+3*j, "   ");
			else{
				sprintf(output_buffer+8+3*j, "%02x ", ((int)buf[index+j]) & 0xFF);
				if(!isprint(buf[index+j]))
					output_buffer[58+j] = '.';
				else
					output_buffer[58+j] = buf[index+j];
			}
		}
		output_buffer[55] = ' ';
		output_buffer[56] = '|';
		output_buffer[57] = ' ';
		printf("%s\n", output_buffer);
		memset(output_buffer+58, '\0', 16);
		index += 16;
	}
}
```

## gdb带源码调试

首先下载glibc源代码

在gdb中输入命令`directory /usr/src/glibc/glibc-2.31/...`

使用命令`l # list`可以显示源码，debug界面也能看到。
