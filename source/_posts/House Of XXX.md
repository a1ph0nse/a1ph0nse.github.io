---
title: House of XXX
date: 2023-01-02 00:01:30
categories: 
- pwn
tags: 
- pwn
- heap 
- house_of_xxx
---
堆的进阶利用，各种House层出不穷，但都是在基本的attck的基础上进行的。
<!--more-->

### House of Spirit

House of Spirit是一种针对fast bin的利用，通过在目标位置**伪造**fastbin chunk，并让其被释放，从而达到**申请指定地址内存**的目的。

需要做的就是让目标位置能够被当作一个chunk释放，重点在于**修改指定地址前后的内容使其能绕过free的检测**。

需要的绕过：

- fake chunk的**ISMMAP位不能为1**，因为 free 时，如果是mmap的chunk，会单独处理。
- fake chunk**地址需要对齐**。
- fake chunk的**size大小需要满足对应的fastbin** 的需求，同时也得**对齐**。
- fake chunk的next chunk的大小**不能小于2 * SIZE_SZ**，同时也**不能大于av->system_mem** 。
- fake chunk对应的fastbin**链表头部不能是该fake chunk**，即不能构成double free的情况。

### House of Force

House of Force是一种针对**top chunk**的利用，当bin中所有的free chunk都不能满足需求时，就会从top chunk中切割，只要切割后top chunk size> MINSIZE，那么就可以切割top chunk分配。

如果我们能通过一些方法**控制top chunk的size和我们申请的chunk的大小**，那么只要将**top chunk size修改为一个足够大的值**(如-1,unsigned long的最大值)，那么无论多大的size，我们都能分配到，由此实现**任意地址分配**。

利用条件：

- 可以控制top chunk的size
- 可以控制申请chunk的大小

### House of Einherjar

House of Einherjar是一种针对**后向合并**操作的利用。当一个chunk被释放时，free会首先会利用prev_inuse位检查其物理低地址的chunk是否空闲，如果空闲则会将这两个chunk合并，**利用当前chunk P的指针、prev_size字段和size字段得到新的chunk的地址以及其大小**。

因此如果我们能**控制prev_size字段和prev_inuse位**，那么我们就可以将新的chunk指向几乎任何位置。而堆溢出、off by one(null)都可以达到这个条件。

值得注意的是，在合并取出前一个chunk的时候会用到**unlink**，因此需要提前构造好fake chunk来绕过unlink的检查。

在这里unlink的检查中主要要注意的是：

```c
//检查prev_size和size是否一致
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size");     

//检查fd和bk
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  

```

由于unlink中是利用要取出的chunk P进行验证，因此之后构造fake chunk的next chunk的prev_size即可绕过第一个检查。

不过无论什么情况，第二个检查则需要构造一下。

在利用unlink的时候，我们的绕过方式是：

```c
*(fakeFD+0x18)==P==*(fakeBK+0x10)
//等价于(64bit)
P->fd=&P-0x18
P->bk=&P-0x10
```

但在这里我们可能不能获取到P的地址，所以我们换个方式:

```c
P->fd=P
P->bk=P
```

同样可以绕过unlink的检查。

值得注意的地方：

- 需要有溢出漏洞可以写物理相邻的高地址的 prev_size 与 PREV_INUSE 部分。
- 我们需要计算目的 chunk 与 p1 地址之间的差，所以需要泄漏地址。
- 我们需要在目的 chunk 附近构造相应的 fake chunk，从而绕过 unlink 的检测。

### House of Lore

House of Lore好像没什么例子，可能比较少见吧。House of Lore可以实现分配任意指定位置的chunk，从而修改任意地址的内存。利用的前提是需要**控制Small Bin Chunk的bk指针**，并且**控制指定位置chunk的fd指针**。

主要利用的是small bin中的漏洞。

```c
// 获取 small bin 中倒数第二个 chunk 。
bck = victim->bk;
// 检查 bck->fd 是不是 victim，防止伪造
if (__glibc_unlikely(bck->fd != victim)) {
  errstr = "malloc(): smallbin double linked list corrupted";
  goto errout;
  
// 设置 victim 对应的 inuse 位
set_inuse_bit_at_offset(victim, nb);
// 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
bin->bk = bck;
bck->fd = bin;
```

当malloc的时候，如果申请的范围在small bin chunk内，且需要从small bin获取空闲的chunk时，会执行上面的语句。我们可以发现，如果我们能控制一个small bin chunk的bk指针指向fake chunk，并控制**fake chunk的fd指向该small bin chunk**来绕过检查，那么就可以将这个fake chunk放入small bin，下一次申请就可以申请到fake chunk1。

### House of Orange

House of Orange核心就是**通过漏洞利用获得free的效果**（在没有free的程序中）。

原理是当前堆的**top chunk尺寸不足**以满足申请分配的大小的时候，**原来的top chunk会被释放并被置入unsorted bin中**，通过这一点可以在没有free函数情况下获取到 unsorted bins。此时会**执行sysmalloc来向系统申请更多的空间**。但是对于堆来说有mmap和brk两种分配方式，我们需要**让堆以brk的形式拓展**，之后原有的top chunk会被置于unsorted bin中。

为了达到目的，我们伪造top chunk size绕过一些检查。

- 伪造的 size 必须要对齐到内存页(0x1000)
- size 要大于 MINSIZE(0x10)
- size 要小于之后申请的 chunk size + MINSIZE(0x10)
- size 的 prev inuse 位必须为 1

当然malloc申请的size也有要求：malloc 的尺寸不能大于mmp_.mmap_threshold（默认128K）

top chunk size的对齐，top chunk addr + top chunk size后是一个4K对齐的地址（默认页面大小为4K，以4K对齐），因此伪造的top chunk size也要满足此条件，因此只能在原来的基础上增减4K的倍数。

House of Orange的进一步利用与IO_FILE有关，后续再说。

### House of Roman

House of Roman是fast bin attack和unsorted bin attack的结合。该技术用于bypass ALSR（即使有PIE也依旧有效），利用12-bit的爆破来达到获取shell的目的。且仅仅只需要**一个UAF漏洞以及能创建任意大小的chunk**的情况下就能完成利用。常用在没有泄露的程序中。

主要步骤为：

1. 利用unsorted bin进行低地址覆盖，利用fastbin attack将fd指向malloc_hook-0x23来获取__malloc_hook（爆破）

2. 利用unsorted bin attack修改malloc_hook为main_arena

3. 利用之前获得的malloc_hook进行低位覆盖，修改malloc_hook为one_gadget

### House of Rabbit

一种在fast bin中伪造堆块的技术。其利用的是在进行malloc_consolidate时，fast bin中的堆块合并的过程中没有检查size。

在chunk释放后，通过修改size构造fake chunk或修改fd指向fake chunk，之后通过malloc一个很大的内存，触发malloc_consolidate，由于这个过程中没有对size进行检查，因此fast bin中的chunk会放到对应的small bin中，伪造的fake chunk就变得合法了，由此可以实现overlapping

不过需要伪造一下next chunk的prev_inuse=1和next next chunk的prev_inuse=1。

### House of Corrosion

House of Corrosion利用了**`global_max_fast`**这个libc中的全局变量，`global_max_fast`表示最大的fastbin chunk的大小，默认为`0x80`，在没有初始化堆的情况下为`0`。改写`globla_max_fast`可以让程序将更大的chunk视作fast bin chunk，在malloc和free的时候将作为fast bin chunk处理。

`fastbinsY`中有10个元素，存放大小从`0x20~0xb0`的chunk，当超出该范围的chunk进入`fastbinsY`时，就会发生**数组越界**。利用此方法我们可以向`fastbinsY`后面的内存中写入一个堆地址（通过free），也可以取出后面内存中指针指向的chunk（如果可以malloc该size的话）。

偏移和要处理的`chunk size`可以用此式子计算：`chunk size = (address-fastbinsY)* 2 + 0x20`（这个size包括了`header`），其中`chunk size`是处理的`chunk`的`size`，`address`是会写入或`malloc`的地址，`fastbinsY`为`fastbinsY`的地址。

1. `free`的利用：

    利用`free`将`chunk`放入`fastbinsY`时的数组越界。当`global_max_fast`被修改变大后，更大的`chunk`被视为`fast bin chunk`，会被放入`fastbinsY`，如果大小超出`0xb0`，就会将后面对应的内存视作`fastbinsY`的一项放入，表现出的结果就是**将释放的`chunk`的堆地址写入该内存**。

    值得注意的是，本质上这次写入是`fast bin chunk`进入`fast bin`的结果，因此该`chunk`的**`fd`位置会保存该内存处原有的指针，`chunk`的内容会被清空**。

2. `malloc`的利用：

    `malloc`时更大的`chunk`被视作`fast bin`，因此首先在`fastbinsY`中对应的`fast bin`中取出`chunk`，如果大小超出`0xb0`，自然就会越界，在后面的内存中取出`chunk`。取出时，会**判断后面内存中指针对应的`chunk`的`size`字段是否符合该`fast bin`的大小，如果符合则可以取出**。

### House of  Storm

House_of_storm 可以**在任意地址写出chunk地址,进而把这个地址的高位当作size,可以进行任意地址分配chunk**，也就是可以造成任意地址写。House_of_storm 虽然危害之大，但是其条件也是非常的苛刻。

条件：

1. glibc版本小于2.30,因为2.30之后加入了检查
2. 需要攻击者在 large_bin 和 unsorted_bin 中分别布置一个chunk 这两个chunk需要在**归位之后处于同一个 largebin 的index中且 unsorted_bin 中的chunk要比 large_bin 中的大**
3. unsorted bin中的bk指针要可控
4. large bin中的bk和bk_nextsize指针要可控

漏洞发生在unsorted bin chunk放入large bin的过程中。

```c
//unsorted bin attack
//我们控制unsorted_chunk->bk = fake_chunk

//unsorted_chunks(av)->bk = fake_chunk
unsorted_chunks(av)->bk = unsorted_chunk->bk;
//fake_chunk+0x10 = unsorted_bin
bck->fd = unsorted_chunks(av);

//放入fast bin的过程中
            else 
            {
                /*
                	如果unsorted_chunk->size 大于 largbin_chunk->size，
                	把unsorted_chunk加入到纵向链表中
                	我们控制
                	large_chunk->bk = fake_chunk+0x8 
                	large_chunk->bk_nextsize=fake_chunk-0x18-5	
                  -5是因为堆地址常常是0x55或者0x56开头的，-5后可以将其写入size位，而0x56的size可以绕过malloc的检查申请出来
                */
                
                 
                unsorted_chunk->fd_nextsize = largbin_chunk;
                
                //unsorted_chunk->bk_nextsize = fake_chunk-0x18-5
                unsorted_chunk->bk_nextsize = largbin_chunk->bk_nextsize;
                
                largbin_chunk->bk_nextsize = unsorted_chunk;
                
                //fake_chunk+0x3 = unsorted_chunk
                unsorted_chunk->bk_nextsize->fd_nextsize = unsorted_chunk;
            }
            //bck  = fake_chunk+0x8
            bck = largbin_chunk->bk;
        }
    } 

mark_bin(av, unsorted_chunk_index); //把unsorted_chunk加入到的bin的表示为非空
//把unsorted_chunk加入到large bin的链表中

unsorted_chunk->bk = bck;
unsorted_chunk->fd = largbin_chunk;
largbin_chunk->bk = unsorted_chunk;
//fake_chunk+0x18 = unsorted_chunk
bck->fd = unsorted_chunk;
```

具体利用：

1. 将unsorted bin chunk的bk指向为fake chunk
2. 将large bin中的bk指针指向fake chunk+0x8，bk_nextsize指向fake chunk-0x18-5（如果target为要写入的目标地址，则fake chunk为target-0x20），来实现victim->bk_nextsize->fd_nextsize=victim(实现fake chunk+3=victim) 
3. 通过malloc(0x48)获得fake chunk,借此可以修改target处的内容

```c
unsorted_bin_chunk->bk=fake_chunk
large_bin_chunk->bk=fake_chunk+0x8
large_bin_chunk->bk_nextsize=fake_chunk-0x18-5
```

其原理相当于利用large bin将一个堆地址写入任意地址，通过堆地址高位的0x56绕过检测，并将该fake chunk链入unsorted bin，从而实现任意地址malloc。

### House of Kiwi





### House of Emma



### House of Pig

House of Pig 是一个将 Tcache Statsh Unlink+ Attack 和 FSOP 结合的攻击，同时使用到了 Largebin Attack 进行辅助。主要适用于 libc 2.31 及以后的新版本 libc 并且程序中仅有 calloc 时。

需要存在 UAF。能执行 abort 流程或程序显式调用 exit 或程序能通过主函数返回。

利用流程为

1. 进行一个 Tcache Stash Unlink+ 攻击，把地址 __free_hook - 0x10 写入 tcache_pthread_struct。由于该攻击要求__free_hook - 0x8 处存储一个指向可写内存的指针，所以在此之前需要进行一次 large bin attack。

2. 再进行一个 large bin attack，修改 _IO_list_all 为一个堆地址，然后在该处伪造 _IO_FILE 结构体。

3. 通过伪造的结构体触发 _IO_str_overflow getshell。

### House of Banana

从glibc 2.28开始，_int_malloc中增加了对unsorted bin的bk的校验，使得unsorted bin attack变得不可行。此时，我们可以考虑使用large bin attack，使用house of strom实现任意地址分配；然而，从glibc2.29开始，检查变得更加严格，house of strom不能用了。不过large bin attack仍可以使用，然而从glibc 2.30开始，常规large bin attack方法也被封堵，不过也能使用。

### House of  Apple

House of Apple在仅使用一次`largebin attack`并限制读写次数的条件下进行`FSOP`利用，前提均是已经泄露出`libc`地址和`heap`地址。

使用`house of apple`的条件为：

1. 程序从`main`函数返回或能调用`exit`函数（触发调用链`exit->fcloseall->_IO_cleanup->_IO_flush_all_lockp->_IO_OVERFLOW`)
2. 能泄露出`heap`地址和`libc`地址
3. 能使用一次`largebin attack`（FSOP劫持`_IO_list_all`到伪造的`IO_FILE`结构体)

在劫持IO后我们仍可以继续利用某些`IO`流函数去修改其他地方的值。就离不开`IO_FILE`的一个成员`_wide_data`的利用，其在`IO_FILE`中的偏移是`0xa0`。通过对伪造`_wide_data`并将vtable修改为`_IO_wstrn_jumps`，通过exit函数触发调用链`exit->fcloseall->_IO_cleanup->_IO_flush_all_lockp->_IO_OVERFLOW`，实现任意地址写已知（堆）地址（详情见IO_FILE）。

House of Apple有四种利用思路：

1. 修改tcache线程变量为已知值，控制tcache bin的分配。
2. 修改`mp_.tcache_bins`为很大的值，使得很大的`chunk`也通过`tcachebin`去管理。
3. 修改`tls`结构体`pointer_guard`的值为已知值，走House of emma。
4. 修改`global_max_fast`全局变量，让大的chunk也能被认为是fast bin chunk。

可以看到House of Apple主要还是利用`_wide_data`和`_IO_wstrn_jumps`中的`_IO_OVRFLOW`实现**任意地址写已知地址**，用以辅助其他方法劫持程序流。

### House of  Apple2

House of Apple2也是基于劫持`_wide_data`的利用，与House of Apple的区别在只劫持`_wide_data`的条件能控制程序的执行流。

使用`house of apple2`的条件为：

- 已知`heap`地址和`glibc`地址
- 能控制程序执行`IO`操作，包括但不限于：从`main`函数返回、调用`exit`函数、通过`__malloc_assert`触发
- 能控制`_IO_FILE`的`vtable`和`_wide_data`，一般使用`largebin attack`去控制

这次主要利用的是`_IO_wide_data`中的`_wide_vtable`，这也是一个虚表，某些函数的执行会调用到其中的函数，调用过程如下：

```c
#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)
 
#define WJUMP1(FUNC, THIS, X1) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
 
#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)
 
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```

可以看到这里并**没有对vtable的合法性进行检测**。因此，我们可以劫持`IO_FILE`的`vtable`为`_IO_wfile_jumps`，控制`_wide_data`为可控的堆地址空间，进而控制`_wide_data->_wide_vtable`为可控的堆地址空间。控制程序执行`IO`流函数调用，最终调用到`_IO_Wxxxxx`函数即可控制程序的执行流。

利用思路：

目前在`glibc`源码中搜索到的`_IO_WXXXXX`系列函数的调用只有`_IO_WSETBUF`、`_IO_WUNDERFLOW`、`_IO_WDOALLOCATE`和`_IO_WOVERFLOW`。其中`_IO_WSETBUF`和`_IO_WUNDERFLOW`目前无法利用或利用困难，其余的均可构造合适的`_IO_FILE`进行利用。

（1）利用`_IO_wfile_overflow`控制程序执行流（走`_IO_WDOALLOCATE`）

以下利用的前提是要从`_IO_flush_all_lockp`执行`_IO_overflow(fp)`，因此伪造的IO_FILE需要满足以下条件：

1. `fp->_mode<=0`
2. `fp->_IO_write_ptr > fp->_IO_write_base`

调用链如下：

```c
_IO_wfile_overflow
    _IO_wdoallocbuf
        _IO_WDOALLOCATE
            *(fp->_wide_data->_wide_vtable + 0x68)(fp)
```

在`_IO_wfile_overflow`中需要绕过一些检测，使其成功调用`_IO_wdoallocbuf`。

```c
wint_t _IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
    {
      _IO_wdoallocbuf (f);// 需要走到这里
      // ......
    }
    }
}
```

需要满足`_flags & _IO_NO_WRITES==0`，`_flags & _IO_CURRENTLY_PUTTING==0`和`_wide_data->_IO_write_base == 0`。

在`_IO_wdoallocbuf`函数中需要使其调用

```c
void _IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)// _IO_WXXXX调用，需要走到这里
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
             fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)
```

需要满足`_wide_data->_IO_buf_base==0`和`_flags & _IO_UNBUFFERED==0`。

综上需要对伪造的IO_FILE进行一下设置：

- `_flags`设置为`~(2 | 0x8 | 0x800)`，如果不需要控制`rdi`，设置为`0`即可；如果需要获得`shell`，可设置为`  sh;`，注意前面有两个空格
- `vtable`设置为`_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_overflow`即可
- `fp->_mode<=0`
- `fp->_IO_write_ptr > fp->_IO_write_base`
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_write_base`设置为`0`，即满足`*(A + 0x18) = 0`
- `_wide_data->_IO_buf_base`设置为`0`，即满足`*(A + 0x30) = 0`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->doallocate`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x68) = C`

（2）利用`_IO_wfile_underflow_mmap`控制程序执行流（走`_IO_WDOALLOCATE`）

调用链如下：

```c
_IO_wfile_underflow_mmap
    _IO_wdoallocbuf
        _IO_WDOALLOCATE
            *(fp->_wide_data->_wide_vtable + 0x68)(fp)
```

在`_IO_wfile_underflow_mmap`中需要绕过一些检测，使其成功调用`_IO_wdoallocbuf`。

```c
static wint_t _IO_wfile_underflow_mmap (FILE *fp)
{
  struct _IO_codecvt *cd;
  const char *read_stop;
 
  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;
 
  cd = fp->_codecvt;
 
  /* Maybe there is something left in the external buffer.  */
  if (fp->_IO_read_ptr >= fp->_IO_read_end
      /* No.  But maybe the read buffer is not fully set up.  */
      && _IO_file_underflow_mmap (fp) == EOF)
    /* Nothing available.  _IO_file_underflow_mmap has set the EOF or error
       flags as appropriate.  */
    return WEOF;
 
  /* There is more in the external.  Convert it.  */
  read_stop = (const char *) fp->_IO_read_ptr;
 
  if (fp->_wide_data->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_wide_data->_IO_save_base != NULL)
    {
      free (fp->_wide_data->_IO_save_base);
      fp->_flags &= ~_IO_IN_BACKUP;
    }
      _IO_wdoallocbuf (fp);// 需要走到这里
    }
    //......
}
```

需要满足`_flags & _IO_NO_READS == 0`，`_wide_data->_IO_read_ptr >= _wide_data->_IO_read_end`和`_IO_read_ptr < _IO_read_end`绕过前面的return。设置`_wide_data->_IO_buf_base == NULL`和`_wide_data->_IO_save_base == NULL`调用`_IO_wdoallocbuf (fp)`。

综上需要对伪造的IO_FILE进行一下设置：

- `_flags`设置为`~4`，如果不需要控制`rdi`，设置为`0`即可；如果需要获得`shell`，可设置为`sh;`，注意前面有个空格
- `vtable`设置为`_IO_wfile_jumps_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_underflow_mmap`即可
- `_IO_read_ptr < _IO_read_end`，即满足`*(fp + 8) < *(fp + 0x10)`
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_read_ptr >= _wide_data->_IO_read_end`，即满足`*A >= *(A + 8)`
- `_wide_data->_IO_buf_base`设置为`0`，即满足`*(A + 0x30) = 0`
- `_wide_data->_IO_save_base`设置为`0`或者合法的可被`free`的地址，即满足`*(A + 0x40) = 0`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->doallocate`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x68) = C`

（3）利用`_IO_wdefault_xsgetn`控制程序执行流（走`_IO_WOVERFLOW`）

```c
_IO_wdefault_xsgetn
    __wunderflow
        _IO_switch_to_wget_mode
            _IO_WOVERFLOW
                *(fp->_wide_data->_wide_vtable + 0x18)(fp)
```

在`_IO_wdefault_xsgetn`中需要绕过一些检测，使其成功调用`__wunderflow`。

```c
size_t _IO_wdefault_xsgetn (FILE *fp, void *data, size_t n)
{
  size_t more = n;
  wchar_t *s = (wchar_t*) data;
  for (;;)
    {
      /* Data available. */
      ssize_t count = (fp->_wide_data->_IO_read_end
                       - fp->_wide_data->_IO_read_ptr);
      if (count > 0)
    {
      if ((size_t) count > more)
        count = more;
      if (count > 20)
        {
          s = __wmempcpy (s, fp->_wide_data->_IO_read_ptr, count);
          fp->_wide_data->_IO_read_ptr += count;
        }
      else if (count <= 0)
        count = 0;
      else
        {
          wchar_t *p = fp->_wide_data->_IO_read_ptr;
          int i = (int) count;
          while (--i >= 0)
        *s++ = *p++;
          fp->_wide_data->_IO_read_ptr = p;
            }
            more -= count;
        }
      if (more == 0 || __wunderflow (fp) == WEOF) //进入这里
    break;
    }
  return n - more;
}
libc_hidden_def (_IO_wdefault_xsgetn)
```

需要满足`_wide_data->_IO_read_end - _wide_data->_IO_read_ptr== 0`不进入第一个if。之后需要`mode!=0`调用`__wunderflow(fp)`。

之后要进入`_IO_switch_to_wget_mode`

```c
wint_t __wunderflow (FILE *fp)
{
  if (fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))
    return WEOF;
 
  if (fp->_mode == 0)
    _IO_fwide (fp, 1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_wget_mode (fp) == EOF) //进入这里
      return WEOF;
    // ......
}
```

需要满足`mode>0`（前面已经让mode!=0）绕过第一个if。之后需要`_flags & _IO_CURRENTLY_PUTTING != 0`，调用`_IO_switch_to_wget_mode`。

最后真正进入`_IO_WXXXX`

```c
int _IO_switch_to_wget_mode (FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF) // 需要走到这里
      return EOF;
    // .....
}
```

需要满足`_wide_data->_IO_write_ptr > _wide_data->_IO_write_base`调用`_IO_WOVERFLOW`。

综上需要对伪造的IO_FILE进行一下设置：

- `_flags`设置为`0x800`
- `vtable`设置为`_IO_wstrn_jumps/_IO_wmem_jumps/_IO_wstr_jumps`地址（加减偏移），使其能成功调用`_IO_wdefault_xsgetn`即可
- `_mode`设置为大于`0`，即满足`*(fp + 0xc0) > 0`
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_read_end == _wide_data->_IO_read_ptr`设置为`0`，即满足`*(A + 8) = *A`
- `_wide_data->_IO_write_ptr > _wide_data->_IO_write_base`，即满足`*(A + 0x20) > *(A + 0x18)`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->overflow`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x18) = C`

### House of Cat

House of Cat利用了**_IO_wfile_jumps**中的**_IO_wfile_seekoff**函数，最后**_IO_switch_to_wget_mode**函数中来攻击，在**FSOP**的情况下也是可行的，只需修改虚表指针的偏移来调用**_IO_wfile_seekoff**即可（通常是结合**__malloc_assert**，改vtable为**_IO_wfile_jumps+0x10**）。

调用链：`_IO_wfile_seekoff -> _IO_switch_to_wget_mode -> _IO_WOVERFLOW`

`_IO_wfile_seekoff`如下：

```c
off64_t _IO_wfile_seekoff (FILE *fp, off64_t offset, int dir, int mode)
{
  off64_t result;
  off64_t delta, new_offset;
  long int count;
 
  if (mode == 0)
    return do_ftell_wide (fp);
  int must_be_exact = ((fp->_wide_data->_IO_read_base
            == fp->_wide_data->_IO_read_end)
               && (fp->_wide_data->_IO_write_base
               == fp->_wide_data->_IO_write_ptr));
#需要绕过was_writing的检测
  bool was_writing = ((fp->_wide_data->_IO_write_ptr
               > fp->_wide_data->_IO_write_base)
              || _IO_in_put_mode (fp));
 
  if (was_writing && _IO_switch_to_wget_mode (fp)) //进入_IO_switch_to_wget_mode
    return WEOF;
......
}
```

`_IO_switch_to_wget_mode`如下：

```c
int _IO_switch_to_wget_mode (FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF) // 需要走到这里
      return EOF;
    // .....
}
```

如果要利用`_IO_WOVERFLOW`，我们将其设置为`system`或者`one_gadget`，调用到这里就可以`get shell`。不过如果遇到了**开启沙箱**的情况，这种方法就不可行了，我们就要考虑其他方式。

先看看`_IO_switch_to_wget_mode`调用`_IO_WOVERFLOW`的汇编代码：

```asm
0x7f4cae745d34 <_IO_switch_to_wget_mode+4>     mov    rax, qword ptr [rdi + 0xa0] 
;rdi==fp
;rax=fp+0xa0==wide_data
0x7f4cae745d3f <_IO_switch_to_wget_mode+15>    mov    rdx, qword ptr [rax + 0x20]
;rdx=wide_data->_IO_write_ptr
0x7f4cae745d49 <_IO_switch_to_wget_mode+25>    mov    rax, qword ptr [rax + 0xe0] ;rax=wide_data+0xe0==wide_data->vtable
0x7f4cae745d55 <_IO_switch_to_wget_mode+37>    call   qword ptr [rax + 0x18] 
;call wide_data->vtable+0x18==_IO_WOVERFLOW
```

可以看到这个过程通过将`fp`传入寄存器`rdi`，并通过对寄存器`rdi`进行操作，从中取出`wide_data中的_IO_write_ptr`和`wide_data中的vtable`，最后调用`vtable中的_IO_WOVERFLOW`。

可以看到`wide_data中的_IO_write_ptr`被放入`rdx`，`wide_data中的vtable`被放入`rax`，通过` call   qword ptr [rax + 0x18] `调用`_IO_WOVERFLOW`，而这个`vtable`也是通过`rdi`的偏移再间址访问再偏移取得的。由于`IO_FILE`结构已经被我们劫持，因此寄存器`rdi`中的值是我们伪造的`IO_FILE`，是可以被我们所控制的，因此`rdx`和`rax`都是可以被我们控制的，所以**除了可以控制`rax`为伪造的`_IO_WOVERFLOW`之外，我们还可以控制寄存器`rdx`**。

这样我们就可以**利用`setcontext`来控制程序流程**了，后面无论是走`ROP的orw`还是走`shellcode的orw`都可以得到flag了。

`House of Cat`的模板如下：（具体情况还需要调试修改）

```py
fake_io_addr=heapbase+0xb00 # 伪造的fake_IO结构体的地址
next_chain = 0
fake_IO_FILE=p64(rdi)         #_flags=rdi
fake_IO_FILE+=p64(0)*7
fake_IO_FILE +=p64(1)+p64(2) # rcx!=0(FSOP)
fake_IO_FILE +=p64(fake_io_addr+0xb0)#_IO_backup_base=伪造rdx的值 
fake_IO_FILE +=p64(call_addr)#_IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x68, '\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x88, '\x00')
fake_IO_FILE += p64(heapbase+0x1000)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0xa0, '\x00')
fake_IO_FILE +=p64(fake_io_addr+0x30)#_wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xc0, '\x00')
fake_IO_FILE += p64(1) #mode=1
fake_IO_FILE = fake_IO_FILE.ljust(0xd8, '\x00')
fake_IO_FILE += p64(libcbase+0x2160c0+0x10)  # vtable=IO_wfile_jumps+0x10 or ...
fake_IO_FILE +=p64(0)*6
fake_IO_FILE += p64(fake_io_addr+0x40)  # rax2_addr,wide_data->vtable
```

### House of Kiwi

https://www.anquanke.com/post/id/235598
