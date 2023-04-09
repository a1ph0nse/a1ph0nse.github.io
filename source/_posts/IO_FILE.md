---
title: IO_FILE
date: 2023-01-02 00:01:40
categories: 
- pwn
tags: 
- pwn
- IO_FILE 
---
IO_FILE是linux中的文件流，在堆利用无法使用hook来get shell时，常常通过IO_FILE的方式控制程序流来get shell。
<!-- more -->

在linux中，一切都被当作文件处理，那自然就包括了IO，IO_FILE就是用来描述IO的文件结构体。所有的文件流文件都是_IO_FILE_plus的结构。

```c
struct _IO_FILE_plus
{
    _IO_FILE file; //完整的结构体内容
    const struct _IO_jump_t* vtable; //仅有一个指针
}
```

其中file是文件流，是linux中用于描述文件的结构，包含文件的关键数据，vtable则是一个**虚表（虚拟函数表）**，保存的是各种操作函数的指针，在对文件流进行操作时，实际是调用该虚表中的函数。

为了管理所有的IO流，存在一个**全局变量**\_IO_list_all的指针，这个指针指向**IO_2_1_stderr** 这个IO_FILE结构体，_IO_FILE结构体中会通过指针形成链表连接在一起。

```c
extern struct _IO_FILE_plus* _IO_list_all; 
```

在使用fopen函数打开文件时，会创建一个对应该文件的\_IO_FILE_plus结构体，并将其存放在**堆**中，其**返回值就是其_IO_FILE结构file**。

除了\_IO_2_1_stderr\_（stderr）之外，程序原本还有输入输出流，因此堆中还有\_IO_2_1_stdout\_和\_IO_2_1_stdin\_。在链表中stderr->stdout->stdin。新加入的IO_FILE会从头（_IO_list_all）处链入链表，因此stdin实际上是链表的最后一个，所以他们的对应文件描述符0(stdin),1(stdout),2(stderr)也是有道理的。

因为_IO_FILE存放在堆中（stderr、stdout、stdin除外，他们在libc中），因此许多对IO_FILE的利用都与堆相关。

完整的`_IO_FILE_plus`结构如下：

```c
_IO_FILE_plus = {
	'amd64':{
		0x0:'_flags',
		0x8:'_IO_read_ptr',
		0x10:'_IO_read_end',
		0x18:'_IO_read_base',
		0x20:'_IO_write_base',
		0x28:'_IO_write_ptr',
		0x30:'_IO_write_end',
		0x38:'_IO_buf_base',
		0x40:'_IO_buf_end',
		0x48:'_IO_save_base',
		0x50:'_IO_backup_base',
		0x58:'_IO_save_end',
		0x60:'_markers',
		0x68:'_chain',
		0x70:'_fileno',
		0x74:'_flags2',
		0x78:'_old_offset',
		0x80:'_cur_column',
		0x82:'_vtable_offset',
		0x83:'_shortbuf',
		0x88:'_lock',
		0x90:'_offset',
		0x98:'_codecvt',
		0xa0:'_wide_data',
		0xa8:'_freeres_list',
		0xb0:'_freeres_buf',
		0xb8:'__pad5',
		0xc0:'_mode',
		0xc4:'_unused2',
		0xd8:'vtable'
	}
}
```



## _IO_FILE

其中_IO_FILE的结构如下：

```c
struct _IO_FILE {
  int _flags; /* low-order is flags.*/
#define _IO_file_flags _flags

  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */

  char *_IO_save_base; 
  char *_IO_backup_base; 
  char *_IO_save_end; 
  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;/*指向下一个file结构*/

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; 

[...]
  _IO_lock_t *_lock;
  #ifdef _IO_USE_OLD_IO_FILE //开始宏判断（这段判断结果为否，所以没有定义_IO_FILE_complete，下面还是_IO_FILE）
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif //结束宏判断
[...] 
int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};
```

可以看到_IO_FILE结构中存放着文件的基本信息，比如说：读/写的起始和结束位置，当前读/写位置，缓冲区的起始和结束位置，保存位置等。

比较关键的还有一个\_chain，它指向下一个\_IO_FILE结构，通过该指针将所有_IO_FILE连成一个链表。

```c
struct _IO_FILE *_chain;/*指向下一个file结构*/
```

## _IO_JUMP_t虚表

### 虚表和虚函数

虚表和虚函数在C语言中不常见，甚至不像C++那样有virtual关键字实现虚函数。实际上虚表和虚函数是用于实现**多态**这种特性的，而C语言本身是面向过程的，因此没有virtual也在情理之中。

但实际上，C语言是可以做到面向对象的，通过struct结构体可以实现类似类的结构，**结构体中的数据就相当于是类中的成员变量，结构体中的函数指针就相当于是类中的成员函数**。

但是这种方法本身也有些弊端，每个结构体实例都会包含所有的函数指针，而每个函数指针都要占据空间（即使其没有被使用）。因此在C语言编程中很少会有将函数指针写在结构体内的，而是在结构体外写一个函数，通过参数传入结构体的实例来对结构体进行操作。实际上在C++中，如果没有virtual关键字的话，编译器也会采取类似的方法对成员函数进行处理。

但如果要实现**多态**的话，就不能用这种节省内存的方法了。对于C语言而言，就是将函数指针放在结构体中，每一个结构体实例通过该函数指针指向自己定义的函数，并且通过该函数指针调用它，这样的函数就可以说是虚函数。

那虚表是什么呢？毕竟虚函数的数量可能不止一个，并且和一般的函数有些不一样（存在其他同名函数），为了方便对每个实例的虚函数进行管理，就有了虚表这种结构。**虚表实际上就是虚函数的表，用来管理虚函数**，虚表是从属于该类的，会通过一个指针指向该虚表。

### _IO_JUMP_T结构

_IO_jump_t结构如下:

```c
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);//0
    JUMP_FIELD(size_t, __dummy2);//1 DUMMY
    JUMP_FIELD(_IO_finish_t, __finish);//2 finish
    JUMP_FIELD(_IO_overflow_t, __overflow);//3 overflow
    JUMP_FIELD(_IO_underflow_t, __underflow);//4 underflow
    JUMP_FIELD(_IO_underflow_t, __uflow);//5 uflow
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);//6 pbackfail 
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);//7 xsputn
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);//8 xsgetn
    JUMP_FIELD(_IO_seekoff_t, __seekoff);//9 seekoff
    JUMP_FIELD(_IO_seekpos_t, __seekpos);//10 seekpos
    JUMP_FIELD(_IO_setbuf_t, __setbuf);//11 setbuf
    JUMP_FIELD(_IO_sync_t, __sync);//12 sync
    JUMP_FIELD(_IO_doallocate_t, __doallocate);//13 doallocate
    JUMP_FIELD(_IO_read_t, __read);//14 read
    JUMP_FIELD(_IO_write_t, __write);//15 write
    JUMP_FIELD(_IO_seek_t, __seek);//16 seek
    JUMP_FIELD(_IO_close_t, __close);//17 close
    JUMP_FIELD(_IO_stat_t, __stat);//18 stat
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);//19 showmanyc
    JUMP_FIELD(_IO_imbue_t, __imbue);//20 imbue
#if 0
    get_column;
    set_column;
#endif
};
```

对文件操作的函数都会调用该文件流中vtable中的函数

### 部分文件操作函数简介

#### fread

fread 是标准 IO 库函数，作用是从文件流中读数据，函数原型如下:

```c
size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;
```

fread 的代码位于 /libio/iofread.c 中，函数名为\_IO_fread，但真正的功能实现在子函数\_IO_sgetn 中。在\_IO_sgetn 函数中会取出vtable中的\_IO_XSGETN并调用。

#### fwrite

fwrite 也是标准 IO 库函数，作用是向文件流写入数据，函数原型如下：

```c
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
```

fwrite 的代码位于 / libio/iofwrite.c 中，函数名为\_IO_fwrite。 在\_IO_fwrite 中主要是调用_IO_XSPUTN 来实现写入的功能。调用\_IO_XSPUTN需要首先取出 vtable 中的指针，再跳过去进行调用。

#### fopen

fopen 在标准 IO 库中用于打开文件，函数原型如下:

```c
FILE *fopen(char *filename, *type);
```

首先fopen中会为该文件创建一个FILE结构，由于其内部**使用malloc函数为FILE结构分配空间**，因此该FILE结构在堆上。

之后fopen会初始化vtable的内容，并调用_IO_file_init 对FILE初始化操作。

最后fopen会将该IO_FILE链入_IO_list_all指向的链表中，并调用系统调用open。

```c
//可见_chain指向的是更先创建的IO_FILE，_IO_list_all指向的始终是最后创建的IO_FILE
fp->file._chain = (_IO_FILE *) _IO_list_all;
_IO_list_all = fp;
```

#### fclose

fclose 是标准 IO 库中用于关闭已打开文件的函数，函数原型如下：

```c
int fclose(FILE *stream);
```

fclose和fopen的操作正好相反，fclose首先会调用\_IO_unlink_it 将指定的 FILE 从\_chain 链表中脱链。

之后会调用\_IO_file_close_it 函数，\_IO_file_close_it 会调用系统接口 close 关闭文件。

最后调用 vtable 中的\_IO_FINISH，其对应的是_IO_file_finish 函数，其中会调用 free 函数释放之前分配的 FILE 结构。

#### printf/puts

printf 和 puts 是常用的输出函数，在 printf 的参数是以'\n'结束的纯字符串时，printf 会被优化为 puts 函数并去除换行符。

puts 在源码中实现的函数是\_IO_puts，这个函数的操作与 fwrite 的流程大致相同，函数内部同样会调用 vtable 中的\_IO_sputn，结果会执行_IO_new_file_xsputn，最后会调用到系统接口 write 函数。

printf 的调用栈回溯如下，同样是通过_IO_file_xsputn 实现

```c
vfprintf+11
_IO_file_xsputn
_IO_file_overflow
funlockfile
_IO_file_write
write
```

## IO_FILE利用

### 对fileno的利用

每个文件流都有一个文件描述符`stdin:0, stdout:1, stderr:2`，这个文件描述符保存在`IO_FILE+0x70`的`fileno`字段。

修改该字段能够修改文件处理的位置，本来`fileno==0`表示从标准输入中读取，修改为`3`则表示为从文件描述符为`3`的文件（已经`open`的文件）中读取。

### 伪造 vtable 劫持程序流程(libc2.23及以前)

许多与文件相关的操作都要对IO_FILE进行操作，这就离不开_IO_FILE_plus中的vtable，一些函数会从vtable中取出函数指针进行调用。因此如果能伪造vtable的话，我们就能劫持程序的流程。

伪造vtable一般有两种做法:

1. 直接修改vtable中的函数指针
2. 覆盖vtable指向我们控制的内存，并在其中伪造vtable

### FSOP

FSOP 是 File Stream Oriented Programming 的缩写（面向文件流编程），进程内所有的\_IO_FILE 结构会使用`_chain` 域相互连接形成一个链表，`_IO_list_all` 指向链表头。

FSOP 的核心思想就是**劫持`_IO_list_all` 来伪造链表和其中的\_IO_FILE 项（包括file和vtable）**。只要劫持了`_IO_list_all`并在对应位置伪造_IO_FILE项，就相当于劫持了所有关于文件的数据和操作。

单纯的伪造只是构造了数据，不能达到**劫持程序流程**的目的。FSOP 选择调用`_IO_flush_all_lockp`来劫持程序流，这个函数会刷新`_IO_list_all` 链表中所有项的文件流，相当于对每个 FILE 调用 fflush，也对应着会调用`_IO_FILE_plus.vtable` 中的`_IO_overflow`，最终的效果就是执行`_IO_overflow(fp)`。

因此如果能将`_IO_overflow`修改为`system`，将`file`结构的`flag`修改为`"/bin/sh\x00"`，就可以通过`_IO_overflow(fp)`执行`system("/bin/sh\x00")`

```c
int _IO_flush_all_lockp (int do_lock)
{
  ...
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
  {
       ...
       if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))//伪造的IO_FILE要满足的条件
               && _IO_OVERFLOW (fp, EOF) == EOF) 
           {
               result = EOF;
          }
        ...
       fp=fp->_chain;
  }
  return result;
}
```

从上面代码可以看到，要执行`_IO_overflow(fp)`，伪造的IO_FILE需要满足以下条件：

1. `fp->_mode<=0`
2. `fp->_IO_write_ptr > fp->_IO_write_base`

而_IO_flush_all_lockp 不需要攻击者手动调用，在一些情况下这个函数会被系统调用：

1. 当 libc检测到**内存错误**， 执行 abort 流程时（可以通过malloc等函数触发）（glibc-2.26删除）
2. 当执行 exit 函数时
3. 当执行流从 main 函数返回时

```c
._chain = chunk_addr //伪造_chain
chunk_addr
{
  file = {
    _flags = "/bin/sh\x00", //对应此结构体首地址(fp)
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x1,
      ...
      _mode = 0x0, //一般不用特意设置
      _unused2 = '\000' <repeats 19 times>
  },
  vtable = heap_addr
}
heap_addr
{
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x0,
  __overflow = system_addr,
    ...
}
```



## glibc2.24后的IO_FILE利用

从glibc2.24开始，加入了对vtable的检查，会对vtable的合法性进行检查。glibc中有一段完整的内存存放着各个vtable，`__start___libc_IO_vtables`和`__stop___libc_IO_vtables` 分别指向第一个和最后一个vtable，只有其中的vtable和外部的合法vtable可以通过检查正常使用，否则会引发abort。

```c
/* Check if unknown vtable pointers are permitted; otherwise,
   terminate the process.  */
void _IO_vtable_check (void) attribute_hidden;
/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

这个检查的调用流程如下（IO函数使用宏调用）：

```c
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
 
#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
 
# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS))) //检查在这里
```

在调用vtable中函数时会对其vtable合法性进行检查。

因此我们伪造的`vtable`要在`glibc`的`vtable`段中，从而得以绕过该检查。
目前来说，有四种思路：利用`_IO_str_jumps`中`_IO_str_overflow()`函数和`_IO_str_finish()`函数与利用`_IO_wstr_jumps`中对应的这两种函数。

### _IO_str_jumps的FSOP(2.28及以后失效)

`libc`中不仅仅只有`_IO_file_jumps`这么一个`vtable`，还有一个叫`_IO_str_jumps`的 ，这个`vtable`可以通过对vtable的检查。

```c
const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish), //this
  JUMP_INIT(overflow, _IO_str_overflow), //this
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

下面是一些相关的结构

```c
struct _IO_str_fields
{
 	_IO_alloc_type _allocate_buffer;
 	_IO_free_type _free_buffer;
};

typedef struct _IO_strfile_
{
 	struct _IO_streambuf _sbf;
 	struct _IO_str_fields _s;
} _IO_strfile;

struct _IO_streambuf
{
  FILE _f;
  const struct _IO_jump_t *vtable;
};
```

由于libc中没有_IO_str_jumps的符号，因此需要自己找

```py
# libc.address = libc_base
def get_IO_str_jumps():
    IO_file_jumps_addr = libc.sym['_IO_file_jumps']
    IO_str_underflow_addr = libc.sym['_IO_str_underflow']
    for ref in libc.search(p64(IO_str_underflow_addr-libc.address)):
        possible_IO_str_jumps_addr = ref - 0x20
        if possible_IO_str_jumps_addr > IO_file_jumps_addr:
            return possible_IO_str_jumps_addr
```

如果能设置vtable为``_IO_str_jumps``，那就可以调用其中的函数，如果其中的函数有问题，自然就可以利用。

------

在`_IO_str_jumps`中的`_IO_str_overflow`就有可以利用的地方。

```c
int _IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)// pass
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))// should in 
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */ // pass
    return EOF;
      else
    {
      char *new_buf;
      char *old_buf = fp->_IO_buf_base;
      size_t old_blen = _IO_blen (fp);
      _IO_size_t new_size = 2 * old_blen + 100;
      if (new_size < old_blen)//pass 一般会通过
        return EOF;
      new_buf
        = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);//target [fp+0xe0]
      if (new_buf == NULL)
        {
          /*      __ferror(fp) = 1; */
          return EOF;
        }
      if (old_buf)
        {
          memcpy (new_buf, old_buf, old_blen);
          (*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);
          /* Make sure _IO_setb won't try to delete _IO_buf_base. */
          fp->_IO_buf_base = NULL;
        }
      memset (new_buf + old_blen, '\0', new_size - old_blen);

      _IO_setb (fp, new_buf, new_buf + new_size, 1);
      fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
      fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
      fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
      fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

      fp->_IO_write_base = new_buf;
      fp->_IO_write_end = fp->_IO_buf_end;
    }
    }

  if (!flush_only)
    *fp->_IO_write_ptr++ = (unsigned char) c;
  if (fp->_IO_write_ptr > fp->_IO_read_end)
    fp->_IO_read_end = fp->_IO_write_ptr;
  return c;
}
libc_hidden_def (_IO_str_overflow)
```

利用下面语句可以劫持程序流程：

```c
new_buf= (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
```

思路是绕过前面的检查，并将`fp->_s._allocate_buffer`修改为`system`,将`new_size`修改为`"/bin/sh"`的地址（也可直接改为one_gadget）

具体构造：

1. `fp->_flags & _IO_NO_WRITES`为假
2. `(pos = fp->_IO_write_ptr - fp->_IO_write_base) >= ((fp->_IO_buf_end - fp->_IO_buf_base) + flush_only(1))`
3. `fp->_flags & _IO_USER_BUF(0x01)`为假
4. `2*(fp->_IO_buf_end - fp->_IO_buf_base) + 100 `不能为负数
5. `new_size = 2 * (fp->_IO_buf_end - fp->_IO_buf_base) + 100`; 应当指向/bin/sh字符串对应的地址
6. `fp+0xe0`（`_allocate_buffer`）指向system地址

当然也要绕过 `_IO_flush_all_lockp`的一些条件

1. `fp->_mode<=0`
2. `fp->_IO_write_ptr > fp->_IO_write_base`

```c
._chain => chunk_addr
chunk_addr
{
  file = {
    _flags = 0x0,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x1,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = (bin_sh_addr - 100) // 2,
      ...
      _mode = 0x0, //一般不用特意设置
      _unused2 = '\000' <repeats 19 times>
  },
  vtable = _IO_str_jumps //chunk_addr + 0xd8 ~ +0xe0(glibc2.24之前可以)
}
+0xe0 ~ +0xe8 : system_addr / one_gadget //fp->_s._allocate_buffer
```

------

在`_IO_str_jumps`中的`_IO_str_finish`也可以利用。

```c
void
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);  //[fp+0xe8]
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```

同样也是对其中函数指针的利用

```c
(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);  //[fp+0xe8]
```

绕过条件：

1. _IO_buf_base 不为空
2. _flags & _IO_USER_BUF(0x01) 为假，即flag字段不包含IO_USER_BUF

现在要让程序执行 `_IO_str_finish` ，`fclose(fp)` 是一条路，但似乎有局限。还是回到异常处理的方法，在 `_IO_flush_all_lockp` 函数中是通过 `_IO_OVERFLOW` 执行的 `__GI__IO_str_overflow`，而 `_IO_OVERFLOW` 是根据 `__overflow` 相对于 `_IO_str_jumps` vtable 的偏移找到具体函数的。所以如果我们伪造传递给 `_IO_OVERFLOW(fp)` 的 fp 是 vtable 的地址减去 0x8，那么根据偏移，程序将找到 `_IO_str_finish` 并执行。

也就是说，如果设置的vtable是`_IO_str_jumps-0x8`，那么在`vtable+0x18`的位置就是 `_IO_str_finish`（原本应该是 `_IO_str_overflow`），这样就可以通过 `_IO_flush_all_lockp`执行到 `_IO_str_finish`，而且由于这个vtable在合法范围内，因此能过检测。

不过我们也要绕过 `_IO_flush_all_lockp`的一些条件

1. `fp->_mode<=0`
2. `fp->_IO_write_ptr > fp->_IO_write_base`

构造如下：

```c
._chain => chunk_addr
chunk_addr
{
  file = {
    _flags = 0x0,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x1,
    _IO_write_end = 0x0,
    _IO_buf_base = bin_sh_addr,
      ...
      _mode = 0x0, //一般不用特意设置
      _unused2 = '\000' <repeats 19 times>
  },
  vtable = _IO_str_jumps-8 //chunk_addr + 0xd8 ~ +0xe0 (2.24之前可以)
}
+0xe0 ~ +0xe8 : 0x0
+0xe8 ~ +0xf0 : system_addr / one_gadget //fp->_s._free_buffer
```

而在`libc-2.28`及以后，由于不再使用偏移找`_s._allocate_buffer`和`_s._free_buffer`，而是直接用`malloc`和`free`代替，所以`FSOP`也失效了。

### _IO_wide_data（House of Apple）

`struct _IO_wide_data *_wide_data`在`_IO_FILE`中的偏移为`0xa0`

`_IO_wide_data`的结构如下：

```c
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;    /* Current read pointer */ 			//0x00
  wchar_t *_IO_read_end;    /* End of get area. */				//0x08
  wchar_t *_IO_read_base;    /* Start of putback+get area. */	 //0x10
  wchar_t *_IO_write_base;    /* Start of put area. */			//0x18
  wchar_t *_IO_write_ptr;    /* Current put pointer. */			//0x20
  wchar_t *_IO_write_end;    /* End of put area. */				//0x28
  wchar_t *_IO_buf_base;    /* Start of reserve area. */		//0x30
  wchar_t *_IO_buf_end;        /* End of reserve area. */		//0x38
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;    /* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;    /* Pointer to first valid character of
                   backup area */
  wchar_t *_IO_save_end;    /* Pointer to end of non-current get area. */
 
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable; //_IO_wide_data+0xe0
};
```

伪造`_wide_data`变量，通过`_IO_wstrn_overflow`可以将已知地址空间上的某些值修改为一个已知值。

```c
static wint_t _IO_wstrn_overflow (FILE *fp, wint_t c)
{
  /* When we come to here this means the user supplied buffer is
     filled.  But since we must return the number of characters which
     would have been written in total we must provide a buffer for
     further use.  We can do this by writing on and on in the overflow
     buffer in the _IO_wstrnfile structure.  */
  _IO_wstrnfile *snf = (_IO_wstrnfile *) fp;
 
  if (fp->_wide_data->_IO_buf_base != snf->overflow_buf)
    {
      _IO_wsetb (fp, snf->overflow_buf,
         snf->overflow_buf + (sizeof (snf->overflow_buf)
                      / sizeof (wchar_t)), 0);
 
      fp->_wide_data->_IO_write_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_ptr = snf->overflow_buf;
      fp->_wide_data->_IO_read_end = (snf->overflow_buf
                      + (sizeof (snf->overflow_buf)
                     / sizeof (wchar_t))); //overflow_buf+偏移
    }
 
  fp->_wide_data->_IO_write_ptr = snf->overflow_buf;
  fp->_wide_data->_IO_write_end = snf->overflow_buf;
 
  /* Since we are not really interested in storing the characters
     which do not fit in the buffer we simply ignore it.  */
  return c;
}
```

`_IO_wstrn_overflow`首先将`fp`强制转化为`_IO_wstrnfile *`指针，然后判断`fp->_wide_data->_IO_buf_base != snf->overflow_buf`是否成立（一般肯定是成立的），如果成立则会对`fp->_wide_data`的`_IO_write_base`、`_IO_read_base`、`_IO_read_ptr`和`_IO_read_end`赋值为`snf->overflow_buf`或者与该地址一定范围内偏移的值；最后对`fp->_wide_data`的`_IO_write_ptr`和`_IO_write_end`赋值。

也就是说，只要控制了`fp->_wide_data`，就可以控制从`fp->_wide_data`开始一定范围内的内存的值，也就等同于**任意地址写已知地址**。

这里有时候需要绕过`_IO_wsetb`函数里面的`free`：

```c
void _IO_wsetb (FILE *f, wchar_t *b, wchar_t *eb, int a)
{
  if (f->_wide_data->_IO_buf_base && !(f->_flags2 & _IO_FLAGS2_USER_WBUF))
    free (f->_wide_data->_IO_buf_base); // 其不为0的时候不要执行到这里
  f->_wide_data->_IO_buf_base = b; //overflow_buf
  f->_wide_data->_IO_buf_end = eb; //overflow_buf+偏移
  if (a)
    f->_flags2 &= ~_IO_FLAGS2_USER_WBUF;
  else
    f->_flags2 |= _IO_FLAGS2_USER_WBUF;
}
```

这样也能写入到`f->_wide_data->_IO_buf_base`和`f->_wide_data->_IO_buf_end`

`_IO_wstrnfile`涉及到的结构体如下：

```c
struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer_unused;
  _IO_free_type _free_buffer_unused;
};
 
struct _IO_streambuf
{
  FILE _f;
  const struct _IO_jump_t *vtable;
};
 
typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;
 
typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  char overflow_buf[64];
} _IO_strnfile;
 
 
typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  wchar_t overflow_buf[64]; // overflow_buf相对于_IO_FILE结构体的偏移为0xf0，在vtable后面。
} _IO_wstrnfile;
```

因此如果能在堆上伪造一个`_IO_FILE`结构体，将其`vtable`替换为`_IO_wstrn_jumps`，伪造`_wide_data`并覆盖，并伪造其他字段绕过检测调用`_IO_OVERFLOW`。`exit`函数则会一路调用到`_IO_wstrn_overflow`函数，并将`fake _wide_data`至`fake _wide_data+0x38`的地址区域的内容都替换为`fake_IO_FILE的overflow_buf+0xf0`或者`fake_IO_FILE的overflow_buf + 0x1f0`。

对`_wide_data`的利用是House of Apple的原理。

### IO_FILE中file的读写指针利用

由于伪造的vtable常常都不在合法范围之内，因此很难再利用vtable，不过我们还可以利用file。

IO_FILE结构中包含了关于文件的基本信息，其中就有与文件读写相关的字段，fwrite、fread等操作就需要利用这些信息。

```c
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
```

如果我们能控制以上字段，那就可以控制缓冲区的读写范围，实现任意读写。即使没有打开文件也没有关系，程序本身会创建stdin、stdout、stderr，控制这两个字段后通过sprintf、printf等函数一样可以利用。

#### 利用stdin进行任意写

`scanf`，`fread`，`gets`等读入走`IO`指针（`read`不走），最后都会调用vtable中的`_xsgetn()`。

```c
_IO_size_t _IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
 ...
  if (fp->_IO_buf_base == NULL)
    {
      ...
      //输入缓冲区为空则初始化输入缓冲区
    }
  while (want > 0) //还需要get的字节数
    {
      have = fp->_IO_read_end - fp->_IO_read_ptr;
      if (have > 0)
        {
          ...
          //memcpy
 
        }
      if (fp->_IO_buf_base
          && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
        {
          if (__underflow (fp) == EOF)  // 调用__underflow读入数据
          ...
        }
      ...
  return n - want;
}

int _IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;
  ...
  // 会检查_flags是否包含_IO_NO_READS标志，包含则直接返回。
  // 标志的定义是#define _IO_NO_READS 4，因此_flags不能包含4。
  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  // 如果输入缓冲区里存在数据，则直接返回
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
  ...
  // 调用_IO_SYSREAD函数最终执行系统调用读取数据
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
               fp->_IO_buf_end - fp->_IO_buf_base);
  ...
}
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)
```

如果`_IO_buf_base`为空，则会初始化缓冲区。

之后会判断`_IO_read_ptr`对应的空间是否有剩余，如果有则**直接复制到目的地址(传入的data)**。

如果`_IO_read_ptr`中的内容没有或不够，则调用`__underflow`函数**执行系统调用读取数据**（`SYS_read`）到从`_IO_buf_base`开始到`_IO_buf_end`的位置，默认`0x400`字节。

此时若实际读入了`n`个字节的数据，则`_IO_read_end = _IO_buf_base + n`（即`_IO_read_end`指向实际读入的最后一个字节的数据），之后再将`_IO_read_ptr`中的数据复制到目的地址(传入的data)。

综上，为了做到**任意写**，满足如下条件，即可进行利用：

1. 设置`_IO_read_end`等于`_IO_read_ptr`（使得`_IO_read_ptr`没有剩余数据，从而可以通过`SYS_read`读入数据）。
2. 设置`_flag &~ _IO_NO_READS`即`_flag &~ 0x4`（一般不用特意设置）。
3.  设置`_fileno`为`0`（一般不用特意设置）。
4.  设置`_IO_buf_base`为`write_start`，`_IO_ buf_end`为`write_end`（我们目标写的起始地址是`write_start`，写结束地址为`write_end`），且使得`_IO_buf_end-_IO_buf_base`大于要写入的数据长度。

#### 利用stdout进行任意读/写

`printf`，`fwrite`，`puts`等输出走`IO`指针（`write`不走），最后会调用vtable中的`_xsputn()`

```c
IO_size_t _IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;
  if (n <= 0)
    return 0;
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    { //如果是行缓冲模式...
      count = f->_IO_buf_end - f->_IO_write_ptr; //判断输出缓冲区还有多少空间
      if (count >= n)
        {
          const char *p;
          for (p = s + n; p > s; )
            {
              if (*--p == '\n') //最后一个换行符\n为截断符，且需要刷新输出缓冲区
                {
                  count = p - s + 1;
                  must_flush = 1; //标志为真：需要刷新输出缓冲区
                  break;
                }
            }
        }
    }
  else if (f->_IO_write_end > f->_IO_write_ptr) //判断输出缓冲区还有多少空间（全缓冲模式）
    count = f->_IO_write_end - f->_IO_write_ptr;
  if (count > 0) //输出缓冲区余下空间>0
    {
      //如果输出缓冲区有空间，则先把数据拷贝至输出缓冲区
      if (count > to_do)
      	count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count); //全部复制到write_ptr
      														//控制write_ptr实现任意写
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0) //任意读的利用
    {
      _IO_size_t block_size, do_write;
      if (_IO_OVERFLOW (f, EOF) == EOF) //调用_IO_OVERFLOW
        return to_do == 0 ? EOF : n - to_do;
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);
      if (do_write)
        {
          count = new_do_write (f, s, do_write);
          to_do -= count;
          if (count < do_write)
            return n - to_do;
        }
      if (to_do)
        to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
  return n - to_do;
}
libc_hidden_ver (_IO_new_file_xsputn, _IO_file_xsputn)
```

在`_IO_2_1_stdout_`中，`_IO_buf_base`和`_IO_buf_end`为输出缓冲区起始位置（默认大小为`0x400`），在输出的过程中，会先将需要输出的数据从目标地址拷贝到输出缓冲区，再从输出缓冲区输出给用户。
缓冲区建立函数`_IO_doallocbuf`会建立输出缓冲区，并把基地址保存在`_IO_buf_base`中，结束地址保存在`_IO_buf_end`中，在建立了输出缓冲区后，会将基址赋值给`_IO_write_base`。

若是设置的是**全缓冲模式**`_IO_FULL_BUF`（一次接收所有输入），则会将结束地址给`_IO_write_end`，若是设置的是**行缓冲模式**`_IO_LINE_BUF`（一次接收一行），则`_IO_write_end`中存的是`_IO_buf_base`。

此外，`_IO_write_ptr`表示输出缓冲区中已经使用到的地址，`_IO_write_base`到`_IO_write_ptr`之间的空间是已经使用的缓冲区，`_IO_write_ptr`到`_IO_write_end`之间为剩余的输出缓冲区。

（1）任意写

在行缓冲模式下，判断输出缓冲区还有多少空间，用的是`count = f->_IO_buf_end - f->_IO_write_ptr`，而在全缓冲模式下，用的是`count = f->_IO_write_end - f->_IO_write_ptr`。

如果还有空间剩余，则会将要输出的`count`长度的数据复制到`_IO_write_ptr`，因此可通过这一点来实现任意地址写的功能。
**利用方式**：只需将`_IO_write_ptr`指向`write_start`，`_IO_write_end`指向`write_end`即可。
这里需要注意的是，有宏定义`#define _IO_LINE_BUF 0x0200`，`flag & _IO_LINE_BUF`为真，则表示`flag`中包含了`_IO_LINE_BUF`标识，即开启了行缓冲模式（可用`setvbuf(stdout,0,_IOLBF,1024)`开启），若要构造`flag`包含`_IO_LINE_BUF`标识，则`flag |= 0x200`即可。

（2）任意读

任意读利用了` if (to_do + must_flush > 0) `成立分支的部分

`to_do`表明还有多少字节没有读入，因此一定是非负数。`must_flush`表明输出缓冲区是否需要刷新，当在行缓冲模式下检测到有换行符`\n`的时候被赋值为1，因此当输出内容中有`\n`且为**行缓冲模式**时就会执行该分支的内容，如用`puts`函数输出就一定会执行。
若`to_do`大于`0`，也就是还有字符没有读入，也会执行该分支中的内容。因此，当 **输出缓冲区未建立** 或者 **输出缓冲区没有剩余空间** 或者 **输出缓冲区剩余的空间不够一次性将目标地址中的数据完全复制过来** 的时候，也会执行该`if`分支中的内容。
`if`分支中主要调用了`_IO_OVERFLOW()`来刷新输出缓冲区，而在此过程中会调用`_IO_do_write()`输出我们想要的数据。

```c
int _IO_new_file_overflow (_IO_FILE *f, int ch)
{
  // 判断标志位是否包含_IO_NO_WRITES => _flags需要不包含_IO_NO_WRITES
  if (f->_flags & _IO_NO_WRITES)
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  // 判断输出缓冲区是否为空 以及 是否不包含_IO_CURRENTLY_PUTTING标志位
  // 为了不执行该if分支以免出错，最好定义 _flags 包含 _IO_CURRENTLY_PUTTING
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      ...
    }
  // 调用_IO_do_write 输出 输出缓冲区
  // 从_IO_write_base开始，输出(_IO_write_ptr - f->_IO_write_base)个字节的数据
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
             f->_IO_write_ptr - f->_IO_write_base);
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
    
static _IO_size_t new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  ...
  _IO_size_t count;
  // 为了不执行else if分支中的内容以产生错误，可构造_flags包含_IO_IS_APPENDING 或 设置_IO_read_end等于_IO_write_base
  if (fp->_flags & _IO_IS_APPENDING)
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
    = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
    return 0;
      fp->_offset = new_pos;
    }
  // 调用函数输出输出缓冲区
  count = _IO_SYSWRITE (fp, data, to_do);
  ...
  return count;
}
```

综上，为了做到**任意读**，需要满足如下条件：
(1) 设置`_flag &~ _IO_NO_WRITES`，即`_flag &~ 0x8`；
(2) 设置`_flag & _IO_CURRENTLY_PUTTING`，即`_flag | 0x800`；
(3) 设置`_fileno`为`1`(stdout)；
(4) 设置`_IO_write_base`指向想要泄露的地方，`_IO_write_ptr`指向泄露结束的地址；
(5) 设置`_IO_read_end`等于`_IO_write_base` 或 设置`_flag & _IO_IS_APPENDING`即，`_flag | 0x1000`。
此外，有一个**大前提**：需要调用`_IO_OVERFLOW()`才行，因此**需使得需要输出的内容中含有`\n`换行符 或 设置`_IO_write_end`等于`_IO_write_ptr`**（输出缓冲区无剩余空间）等。
一般来说，经常利用`puts`函数加上述`stdout`任意读的方式泄露`libc`。

flag的构造如下：

```c
_flags = 0xfbad0000 
_flags & = ~_IO_NO_WRITES // _flags = 0xfbad0000
_flags | = _IO_CURRENTLY_PUTTING // _flags = 0xfbad0800
_flags | = _IO_IS_APPENDING // _flags = 0xfbad1800
```

例如在`libc-2.27`下，构造`fakefile = p64(0xfbad1800) + p64(0)*3 + b'\x58'`（`\x58`覆盖`write_base`的低位），泄露出的第一个地址即为`_IO_file_jumps`的地址。
