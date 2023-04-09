---
title: QWNT-webheap
date: 2023-03-20 14:05:16
categories: 
- pwn_wp
tags: 
- pwn
- heap


---

强网拟态，C++ pwn

<!-- more -->



```c
struct note{
    QWORD choose;
    QWORD idx;
    QWORD size;
    QWORD* content;
}
```





```py
payload=p8(0xb9)+p8(0x5)+p8(choose_type)+pxx(choose)+p8(idx_type)+pxx(idx)+p8(0xBD)+p8(size_type)+pxx(len(content))+content

# idx size
# 1byte:0x80
# 2byte:0x81
# 4byte:0x82
# 8byte:0x83

# choose 
# 1byte:0x84
# 2byte:0x85
# 4byte:0x86




```

