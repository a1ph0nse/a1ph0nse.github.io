---
title: musl pwn
date: 2023-03-26 15:25:10
categories: 
- pwn
tags: 
- pwn
- musl
- heap

---

musl而非glibc的堆，据说1.2.1和glibc很像，但从1.2.2之后和glibc差别很大，所以来看看1.2.2之后的。
<!--more-->

## 基本数据结构

在free或者malloc chunk的时候从chunk到group再到meta**从小到大索引**

### chunk

```c
struct chunk{
 char prev_user_data[];
    uint8_t idx;  //低5bit为idx第几个chunk
    uint16_t offset; //与第一个chunk起始地址的偏移，实际地址偏移为offset * UNIT,详细请看get_meta源码中得到group地址的而过程！ UNIT=0x10
    char data[];
};
```

在释放后 chunk 头的 **idx会变成0xff offset 会清零**

和glibc 的chunk 类似 glibc chunk 可以占用下一个chunk 的prev_size 空间

而musl 可以使用 下一个chunk 头的**低4B** 来储存数据

### group

```c
#define UNIT 16
#define IB 4
struct group {
    struct meta *meta;
    unsigned char active_idx:5; //低5bit
    char pad[UNIT - sizeof(struct meta *) - 1];//padding=0x10B UNIT=0x10
    unsigned char storage[];// chunks
};
```

- 在musl 中**同一类**大小的chunk 都是被分配到 **同一个**group 中进行管理
- musl 是通过 **chunk addr 和chunk 头对应的 offset** 来索引到 group 地址的
- 整体作为一个 group，其中开头的0x10我们当作group 头，这里的group头涵盖了第一个chunk的头数据，第一个chunk在这之后开始
- group开头的**8个字节**存的 meta 的地址，**后面8个字节**存了**第一个chunk 的头数据 和 active_idx**
- 这里active_idx 代表**能存下**的多少个可以用的同类型chunk（**[0,active_idx]，即active_idx+1个**）

从`chunk`索引到`group`：`group_addr = chunk_addr - 0x10 * offset - 0x10`

### meta

```c
struct meta {
    struct meta *prev, *next;//双向链表
    struct group *mem;// 这里指向管理的group 地址
    volatile int avail_mask, freed_mask;
    uintptr_t last_idx:5;
    uintptr_t freeable:1;
    uintptr_t sizeclass:6;
    uintptr_t maplen:8*sizeof(uintptr_t)-12;
};
```

其中如果这个meta 前后都没有，那么它的prev next 就**指向它自己**

**avail_mask，freed_mask** 是**bitmap**的形式体现 chunk 的状态

- 在 avail_mask 中 2 进制的**0表示不可分配1表示可分配**，顺序是**从后到前，最前面那个0不算，只是为了对齐**
- avail代表还**未被分配**出去，freed代表已经**被分配但是被释放**了
- 如01111000 中最后的 3个0 ， 表示第1、2、3个 chunk 是不可分配的 前面4个chunk 是可以分配的
- 在 free_mask 中的 **1表示已经被释放**

**last_idx**可以表示最多**可用堆块的数量**，最多数量**=last_idx+1**(因为是从[0,last_idx])

**freeable=1**代表meta否**可以被回收**，freeable=0代表**不可以**

**sizeclass**表示由哪个group进行管理这一类的大小的chunk

**maplen>= 1**表示这个meta里的group是新mmap出来的，长度为`meta->maplen = (needed+4095)/4096`，并且这个group **不在size_classes里**

**maplen=0**表示group 不是新mmap出来的**在size_classes里**

**tips:**

- **meta 一般申请的是堆空间brk 分配的，有可能是mmap 映射的，而group 都是使用的mmap 的空间**
- **由于bitmap的限制, 因此一个group中最多只能有32个chunk**

### meta_arena

```c
struct meta_area {
    uint64_t check;
    struct meta_area *next;
    int nslots;
    struct meta slots[]; //管理的meta的地址
};
```

meta_area 是管理meta的合集，meta_area以**页**为单位分配 所以计算地址如下：

`const struct meta_area *area = (void* )((uintptr_t)meta & -4096)`

**check**:是个校验数字 保护meta_area 里的meta，**防止meta被伪造**

**meta_area \*next** 指向下一个meta_area 如果没有就**默认为0**

**nslots**: meta槽的**数量**

**细节**:在这个meta_area 页被使用的时候 上一个临近的页 会被设置为不可写

### malloc_context

```c
struct malloc_context {
    uint64_t secret;// 和meta_area 头的check 是同一个值 就是校验值
#ifndef PAGESIZE
    size_t pagesize;
#endif
    int init_done;//是否初始化标记
    unsigned mmap_counter;// 记录有多少mmap 的内存的数量
    struct meta *free_meta_head;// 被free的meta头 这里meta管理使用了队列和双向循环链表
    struct meta *avail_meta;//指向可用meta数组
    size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;
    struct meta_area *meta_area_head, *meta_area_tail;
    unsigned char *avail_meta_areas;
    struct meta *active[48];// 记录着可用的meta
    size_t u sage_by_class[48];
    uint8_t unmap_seq[32], bounces[32];
    uint8_t seq;
    uintptr_t brk;
};
```

## 内存分配与释放

### 分配

1. 若申请的chunk 没超过阈值 就从active 队列找管理对应size大小的meta

2. 关于找对应size的meta 这里有两种情况:

    - 如果active 对应size的meta 位置上为空，没找到那么尝试先找size更大的meta

    - 如果active 对应size的meta位置上有对应的meta，尝试从这个meta中的group找到可用的chunk(这里malloc 那个循环:`for (;;)`，

        - 如果通过循环里，通过meta->avail_mask 判断当前group 中是否有空闲chunk
            - 有，就直接修改meta->avail_mask，然后利用enframe(g, idx, n, ctr);// 从对应meta 中的group 取出 第idx号chunk分配
            - 无，break 跳出循环

        - 跳出循环后执行`idx = alloc_slot(sc, n);alloc_slot`有三种分配方式:

            - **使用group中被free的chunk**

            - **从队列中其他meta的group 中找**

            - 如果都不行就重新分配一个新的group 对应一个新的meta

3. enframe(g, idx, n, ctr) 取出 对应meta 中对应idx 的chunk

### 释放

1. 通过get_meta(p)得到meta (get_meta 是通过chunk 对应的offset 索引到对应的group 再索引到meta) 

2. 通过get_slot_index(p)得到对应chunk的 idx ``-``> 通过get_nominal_size(p, end) 算出真实大小

3. 重置idx 和 offset idx 被置为``0xff` `标记chunk

4. 修改freed_mask标记chunk被释放

5. 最后调用nontrivial_free完成关于meta一些剩余操作 (注意进入nontrivial_free 是在``for``循环外 还未设置)

**注意**

1. 释放chunk的时候，先只会修改freed_mask,不会修改avail_mask，说明chunk 在释放后，不会立即被复用
2. 注意进入nontrivial_free 是在``for``循环外 还未设置freed_mask 跳出循环的条件是  `if (!freed || mask+self==all) break;`

3. free中chunk的起始位置可以通过chunk的idx定位
