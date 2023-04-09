---
title: Heap Operation
date: 2023-01-02 00:01:00
categories: 
- pwn
tags: 
- pwn
- heap 
---
这部分是对堆的一些操作（函数）的分析

<!-- more -->
### unlink

unlink的作用**是将一个chunk从bin中取出**，在malloc、free、malloc_consolidate、realloc等函数中会用到。

**值得注意的是：由于对fast bin和small bin的malloc没有用到unlink，因此经常会有漏洞在此处**

#### 古老的unlink

古老的unlink没有什么检查，只是单纯地把chunk从双向链表中取出，主要操作为：

```c
//P是要取出的chunk
FD=P->fd;//FD为P的下一个chunk
BK=P->bk;//BK为P的前一个chunk

//在fd和bk的双向链表中去掉P
FD->bk=BK;
BK->fd=FD;

//下面是针对large bin中nextsize字段的处理
// 如果P->fd_nextsize为 NULL，表明 P 未插入到 nextsize 链表中。
// 那么其实也就没有必要对 nextsize 字段进行修改了。
// 这里没有去判断 bk_nextsize 字段，可能会出问题。
if (!in_smallbin_range (chunksize_nomask (P)) &&  __builtin_expect (P->fd_nextsize != NULL, 0)) {                      
    //类似于小的 chunk 的检查思路                                             

    //如果FD没有在nextsize链表中，说明FD大小与P一样
    if (FD->fd_nextsize == NULL) 
    {                                      
        //如果nextsize串起来的双链表只有P本身，那就直接拿走P
        // 令 FD 为 nextsize 串起来的
        if (P->fd_nextsize == P)                                      
            FD->fd_nextsize = FD->bk_nextsize = FD;                      
        else 
        {                                                              
            //否则我们需要将FD插入到nextsize形成的双链表中
            FD->fd_nextsize = P->fd_nextsize;                              
            FD->bk_nextsize = P->bk_nextsize;                              
            P->fd_nextsize->bk_nextsize = FD;                              
            P->bk_nextsize->fd_nextsize = FD;                              
        }                                                              
    } 
    else 
    {                                                              
        //如果在的话，说明FD比P小，直接拿走P即可
        P->fd_nextsize->bk_nextsize = P->bk_nextsize;                      
        P->bk_nextsize->fd_nextsize = P->fd_nextsize;                      
    }                                                                      
} 

```

#### 现在的unlink

现在的unlink加入了一些检查

```c

//在最开始处
// 由于 P 已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致(size检查)
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size");               

//在赋值FD和BK之前
// 检查 fd 和 bk 指针(双向链表完整性检查)
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  

//在判断知道是large bin之后
// largebin 中 next_size 双向链表完整性检查 
if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    
              malloc_printerr (check_action, "corrupted double-linked list (not small)",P, AV);

```

即使在加了检查之后，unlink仍然存在可以利用的地方，这些之后再说。

### malloc_consolidate

malloc_consolidate主要进行**合并整理**堆空间的操作，减少堆中的碎片，用于将 fastbin 中的空闲 chunk 合并整理到 unsorted_bin 中以及进行初始化堆的工作，在 malloc() 以及 free() 中均有可能调用 malloc_consolidate() 函数。

若在调用malloc_consolidate()时，堆未初始化，则初始化堆。

若已经初始化，则清空标志位，遍历fast bin中的chunk尝试合并。在合并时，首先考虑与**低地址的相邻chunk**合并，之后再考虑和**高地址的相邻chunk**合并，合并后加入到unsorted bin中（如果与top chunk合并则不用加入）。

malloc_consolidate()的调用情况：

1. malloc一个**large bin chunk**的时候，会**首先调用一次malloc_consolidate()**对fast bin进行整理，之后会将unsorted bin中的chunk分配到对应的bin中。
2. 如果malloc时要切割top chunk且**top chunk也不够切割**，那么会调用malloc_consolidate()对fast bin进行整理。

一种特殊的consolidate:

当切割chunk产生last remainder的时候，会触发consolidate对unsorted bin进行整理，但**并不会对fast bin进行整理**。

### malloc

[大佬的malloc源码分析](https://blog.csdn.net/qq_41453285/article/details/99005759)

[大佬的malloc源码分析](https://www.cnblogs.com/luoleqi/p/12731875.html#malloc)

使用malloc函数申请内存块时，真正调用的其实是_libc_malloc函数，而_libc_malloc函数主要是对_int_malloc函数的封装，主要的工作在_int_malloc函数中完成。

#### _libc_malloc

_libc_malloc主要的功能是对_int_malloc的调用，寻找一个arena并尝试利用_int_malloc()分配内存，如果失败了则重新寻找arena。

值得注意的是，**_libc_malloc()中会有一个叫做__malloc_hook的函数指针，如果有值就会执行其指向的函数，利用这点，我们可以修改__malloc_hook的值来get shell**。

除此之外，**在进入_libc_malloc()之后，size就变成了无符号整数，所以malloc(负数)会申请一个很大的内存，如果够的话**。

#### _int_malloc

_int_malloc是真正执行内存分配的部分，其核心思想是**最佳适配**。

大致流程：

1. 根据申请的chunk大小，到对应的bin中寻找有无合适的chunk
    1. 对于fast bin chunk，通过fd进行查找，将离头结点**最近**的chunk取出，若空则在small bin中找。
    2. 对于small bin chunk，通过bk进行查找，将离头结点**最远**的chunk取出。
    3. 对于large bin chunk或者**fast bin和small bin中都无刚好满足的chunk**，即在large bin中查找
2. 如果需要在large bin中找chunk，那么首先会执行malloc_consolidate()整理fast bin，整理后放入unsorted bin
3. 通过**bk指针**，对unsorted bin中的chunk进行遍历，如果大小正好则取出返回，否则**先将chunk放入对应的bin**中，**切割比需求大的最小**chunk返回，last remainer会放入unsorted bin（如果大于等于MIN_SIZE）。**如果分配成功，则将unsorted bin中的free chunk放到对应的bin中**。
4. 如果没有满足需求的，则在large bin中查找正好合适的chunk取出返回，如果没有但有比他大的large bin chunk，则切割该chunk后取出返回。**(large bin 中切割产生的last remainder 如果小于MIN_SIZE，则会一起交给malloc使用，而不是放入unsorted bin)**
5. 如果仍没有满足需求，则从top chunk中切割。
6. 如果top chunk中也不够，则会执行一次malloc_consolidate()，并将unsorted bin中free chunk放到对应bin，再查找一次是否有能够分配的。
7. 最后实在没办法就只能调用sysmalloc()进行分配。

### free

[大佬的free源码分析](https://blog.csdn.net/qq_41453285/article/details/99071778)

[大佬的free源码分析](https://www.cnblogs.com/luoleqi/p/12822833.html)

与malloc类似，free调用的也是_libc_free，实际上起主要作用的也是其中的_int_free。

#### _libc_free

主要功能：

1. 检查有没有__free_hook，有则调用（**类似__malloc_hook，可以修改来get shell**）
2. 如果chunk为NULL，则啥也不干
3. 如果是mmap的chunk，则调用munmmap来free
4. 调用_int_free()释放chunk

#### _int_free

对chunk进行释放，将其放入fast bin或unsorted bin，如果放入unsorted bin则考虑进行合并。

主要流程：

1. 进行安全检查，chunk的指针地址不能溢出，chunk的大小必须是按是按 2*SIZE_SZ 对齐的且大于等于MINSIZE
2. 如果该chunk是fast bin chunk，则检查下一个chunk的size是否合法，之后**检查当前free的chunk是否是fast bin头结点连接的chunk**（防止直接的double free），之后将该chunk加入到对应大小的fast bin头（**不会清空prev_inuse**），释放结束
3. 如果该chunk不是fast bin chunk，则考虑加入unosrted bin，先进行检查，保证当前chunk不能是top chunk，并且下一个chunk的size要合法（大于等于MIN_SIZE且小于该arena的内存总量）
4. 之后考虑进行合并，先考虑与**前一个**free chunk进行合并，再考虑与**后一个不是top chunk的（如果下一个是top chunk则会并入top chunk）**free chunk进行合并,如果不能合并，则会清除后一个chunk的prev_inuse位，合并后将chunk加入到unsorted bin中。（large bin chunk 的fd_nextsize和bk_nextsize会赋NULL）
5. 如果合并后的 chunk 大小大于 64KB，并且 fast bins 中存在空闲 chunk，调用 malloc_consolidate()函数合并 fast bins 中的空闲 chunk 到 unsorted bin 中。
6. 判断是否需要对heap收缩，如果需要则收缩。

注意：

1. 释放chunk大小要2*SIZE_EZ对其，大小大于等于MIN_SIZE且没有地址溢出
2. 释放fast bin，会检查bin头指向的chunk与该chunk是否一致，防止double free(**如果隔一个仍能实现fast bin double free**)
3. 释放chunk的时候，chunk不能为top chunk，next chunk的地址不能超过当前分配区结束的地址，以及next chunk中chunk的prev_inuse标志位需置1(**构造house of spirit**)
4. 当前 free 的 chunk 的下一个相邻 chunk 的大小需要大于 2*SIZE_SZ 且小于分配区所分配区的内存总量(**构造house of spirit**)
5. 释放的chunk通过unlink脱链，注意unlink的检查(**也许会有对unlink的利用**)