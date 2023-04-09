---
title: Heap Struct
date: 2023-01-02 00:00:40
categories: 
- pwn
tags: 
- pwn
- heap 
---
堆是由操作系统内核或堆管理器**动态**分配的，只有在程序需要时才会被分配。
在程序运行过程中，堆可以提供动态分配的内存，允许程序申请**大小未知**的内存。堆其实就是程序虚拟地址空间的一块**连续的线性**区域，它由**低地址向高地址**方向增长。

堆通常由堆管理器ptmalloc2来管理，堆管理器位于内核层和用户层之间，会响应用户的请求并管理堆。系统调用开销巨大，只有堆管理器不能满足需求时，才会调用系统内核进行操作。

需要注意的是，在内存分配与使用的过程中，Linux有这样的一个基本内存管理思想，**只有当真正访问一个地址的时候，系统才会建立虚拟页面与物理页面的映射关系**。 所以虽然操作系统已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存。只有当用户使用到相应的内存时，系统才会真正分配物理页面给用户使用。
<!--more-->
## 堆的微观结构

### chunk

```c
struct malloc_chunk
{
    //当物理地址上的前一个chunk在使用时，prev_size用于存放前一个chunk的数据，否则，如果前一个chunk被释放了，则存放前一个chunk的大小
    INTERNAL_SIZE_T prev_size;  
    //存放当前chunk的实际大小（包含prev_size和size字段），chunk的大小都为2*SIZE_SZ(SIZE_SZ 32bit为4byte，64bit为8byte)的整数倍，因此size的后面3位都不会用上，被用于作为标志位。
    //最低位为prev_inuse，用于指示前一个chunk是否释放，prev_inuse==1为使用，==0为释放
    //第二位指示是否为memory_mapped分配的内存，1表示是，0 表示是 heap
    //第三位指示是否是主分配区main_arena分配的内存，1表示不是，0表示是
    INTERNAL_SIZE_T size;
    
    //下面为user data部分，用户申请到的指针指向的是下面的部分，若chunk被使用则下面的内存全部用于存放数据，否则才会有下面的结构

    //fd和bk用于bin中链表连接，fd指向下一个，bk指向前一个。
    struct malloc_chunk* fd;
    struct malloc_chunk* bk;

    //fd_nextsize和bk_nextsize用于large bin，分别指向前一个或后一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针（因为large bin中同一头结点下的chunk的大小不一定相同，large bin允许有一定的公差）
    struct malloc_chunk* fd_nextsize;
    struct malloc_chunk* bk_nextsize;
}
```

### bin

为了减少开销，释放chunk的时候，堆管理器不会马上返回给内核，而是用bin对chunk进行暂时的管理。这样，当再次用户再次申请内存的时候，先从chunk中查找是否有正好满足的，如果有则直接取出，达到减少系统调用的次数的目的。

为了方便管理，堆管理器按照chunk的大小，将bin分为4类，分别管理不同大小的chunk，分别为fast bins,small bins,large bins和unsorted bin。除了unsorted bin之外，其他的每种bin都会维护多个链表，根据chunk的大小再进行细分。**fast bin由fastbinY数组管理，其余的unsorted bin,small bin,large bin则由一个bin数组管理。**

### fast bins

fast bin是所有bin中操作最快的，也是最常用的，通常存放0x10到0x80的chunk，当在fast bins范围内的chunk被释放时，会**直接**被放到fast bins中。fastbinY这个数组用于实现fast bin，这个数组保存了fast bin的头结点，每一个头结点都指向同一大小的fast bin chunk，**头结点的prev_size和size字段被省去**。

fast bin中采用**单向链表**对chunk进行组织,**即仅使用fd指针**，并且遵循**LIFO(先进后出)**的原则，fast bin的**头结点会指向最后一个**加入该fast bin的chunk。加入chunk时，先让chunk指向头结点指向的chunk，再让头结点指向该chunk；取出chunk的时候通过头结点取出最后加入的chunk。

fast bin中的chunk大小都比较小，因为小的内存经常会用到，但如果释放后就被合并，那么下次申请时就会再需要分割，fast bin会减少这种合并，**fast bin chunk的prev_inuse位都为1，用于防止合并**。

fast bin特性：

1. fast bin使用fd，通过单向链表对chunk进行组织
2. fast bin遵循LIFO的规则
3. fast bin chunk prev_inuse位为1，不会被合并
4. fast bin中fd指向的是prev_size位置，也就是chunk的开头位置
5. 大小在fast bin范围内的chunk被释放时会直接放入fast bin(如果没有tcache或tcache满了)

### unsorted bin

unsorted bin中存放的是**不符合fast bin大小且不与top chunk相邻**的chunk，当这样的chunk会释放的时候，**首先**会被放入unsorted bin,作为放入small bin和large bin的**缓冲**，**unsorted bin的头结点中的pre_size和size都被省去，只有fd和bk有作用**。

unsorted bin 处于bin[1]处，因此unsorted bin 只有一个链表。unsorted bin 中的空闲 chunk 处于**乱序**状态，主要有两个来源：

（1）当一个较大的 chunk 被**分割**成两半后，如果剩下的部分**大于MINSIZE(chunk的最小大小)**，就会被放到 unsorted bin 中。

（2）释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。

unsorted Bin 在使用的过程中，采用的遍历顺序是 **FIFO** ，并且使用fd和bk通过**双向链表**进行连接。**当unsorted chunk中只有一个chunk的时候，那一个chunk的fd和bk都会指向的unsorted bin的头结点**。

unsorted bin的特性：

1. unsorted bin只有一个
2. unsorted bin遵循FIFO的规则
3. unsorted bin使用fd和bk，通过双向链表连接chunk
4. 当unsorted bin只有一个chunk的时候，chunk的fd和bk都会指向unsorted bin的头结点（通常是main_arena+88高版本可能会+96）
5. 不属于fast bin且不与top chunk相邻的chunk被释放时会放入unsorted bin
6. 被分割后剩下的chunk如果大于chunk的最小大小，则会加入unsorted bin

### small bins

small bins在bin中从bin[2]一直到bin[63],存放的是小于512B的chunk，**工作范围包含了fast bins**,small bins 中每个 chunk 的大小与其所在的 bin 的 index 的关系为：chunk_size = 2 * SIZE_SZ *index

small bins中一共有62个循环双向链表，每个链表中存储的chunk**大小都一致**。此外，small bins中遵循**FIFO**的规则，所以同一个链表中先被释放的chunk会先被分配出去，bin的头结点指向**最后被释放的chunk**，也就是说，**离bin头结点最远的chunk最先被分配**。


small bins的特性：

1. small bins在bin中的index从2到63，共62个
2. 一个bin中的chunk的大小都相等，chunk_size=2 * SIZE_SZ * index
3. small bins遵循FIFO的规则
4. small bins使用fd和bk，通过双向链表连接chunk

### large bins

large bins在bin中从bin[64]一直到bin[126],存放的是大于512B的chunk。bin中的每个chunk的**大小不一定相同**，但都是**在一定范围之内**。此外，63个bin被分为6类，每类bin中chunk的**公差一致**，第一类有32个，公差为64B，第二类有16个，公差为512B，第三类有8个，公差为4096B，第四类有4个，公差为32768B，第五类有2个，公差为262144B，第六类有1个，公差不限制。

large bins采用双向链表进行连接，除了fd和bk的双向链表连接同一个large bin中前后的chunk之外，**large bin中还会利用fd_nextsize和bk_nextsize进行连接**。

large bin中的chunk按照**大小顺序**排列，**最大的接在头结点后**，最小的接在尾部。

fd_nextsize和bk_nextsize用于连接同一个large bin下不同大小的chunk，**fd_nextsize会连接下一个比当前小的chunk，bk_nextsize会链接前一个比当前大的chunk**，对相同大小的chunk，只有**第一个**chunk的fd_nextsize和bk_nextsize会指向，其余的都会赋0。

fd_nextsize和bk_nextsize也构成了一个**双向的循环链表**，如果large bin中chunk的大小都相同，那么第一个chunk的fd_nextsize和bk_nextsize都会指向自己。

large bins的特性：

1. large bins在bin中的index从64到126,共63个
2. 一个large bin中的chunk的大小不一定相同，但都在一定范围（公差）内
3. 63个large bin中被分为6类，每类的公差相同
4. large bin中的chunk按由大到小的顺序排布，头结点接的是最大的chunk
5. large bin使用fd和bk，通过双向链表连接
6. large bin利用fd_nextsize和bk_nextsize，指向比当前小和比当前大的chunk，构成双向循环链表
7. large bin取出时会首先取出离头结点最近的（LIFO）


### top chunk

top chunk 就是处于当前堆的物理地址最高的chunk。程序第一次进行malloc的时候，heap会被分为两块，低地址的一块给用户，剩下的那块就是top chunk。

top chunk虽然没被使用，但是不属于任何一个bin，当bin中的chunk不能满足用户需要时，就会**从top chunk中分割新的chunk**，余下的部分将作为新的top chunk。

当释放的chunk与top chunk相邻且不在fast bin的范围内，那么这个chunk会被**合并**到top chunk中。因此，top chunk的**prev_inuse位始终为1**，否则前一个chunk就会被合并。

### last remainder

在用户使用 malloc 请求分配内存时，ptmalloc2 找到的 chunk 可能并不和申请的内存大小一致，这时候就将**分割之后的剩余部分**称之为last remainder chunk，unsort bin 也会存这一块。top chunk 分割剩下的部分不会作为last remainder.

### tcache

在glibc2.26之后引入的新技术，提高了性能，但是由于**舍弃了许多安全检查**，带来了不小的风险。

tcache的结构与fast bin有些类似，都是利用**fd通过单向链表**将**相同大小**的chunk链起来，且**prev_inuse==1**，但不同的是tcache中**fd指向的是user data而不是chunk_addr**。

具体结构：

每个线程都会维护一个tcache_perthread_struct，是整个tcache的管理结构，一共有TCACHE_MAX_BINS个计数器和TCACHE_MAX_BINS个tcache_entry。

```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

# define TCACHE_MAX_BINS                64
```

**tcache_entry就相当于是fast bin的头结点**，后面连接大小相同的chunk;其中的count记录了tcache_entry连接的free chunk的个数，一般最多为**7**个，**超过7个则放入其他的bin**。

`tcache_perthread_struct`本身也是一个堆块，大小为0x250，位于堆的开头。（**因此可以被劫持**）

tcache与fast bin类似，是采用LIFO的单链表，每个bin内存在的堆块大小相同，大小从24~1032字节，一般每个bin最多存放7个。

工作方式：

在free的时候，会**优先考虑放入tcache中**，tcache中没有空位才会加入fast bin或者unsorted bin。与fast bin类似，tcache中chunk的**prev_inuse位为1**。

在malloc的时候，也会**优先从tcache中取出chunk（如果size在tcache范围0x408内）**，如果tcache是空的，但fast bin、smalll bin中有对应size的chunk的话，则会**将对应头结点下的其他chunk**移到tcache的对应tcache_entry处，直到tcache被填满或bin被清空。如果是unsorted bin的话，则会将**所有chunk**移到tcache中继续处理。

tcache采用tcache_put()和tcache_get()对chunk进行存取，这两个操作几乎没有安全保护，这是让tcache_entry[idx]指向新放入的chunk或取出tcache_entry[idx]指向的chunk，再修改count，并且不会修改prev_inuse。

