---
title: NewStar calc
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- python

---

NewStarCTF，随机生成出一个计算题，连续做对100题就能get shell。

随机生成出一个计算题，连续做对100题就能get shell。

原本以为是要改seed来控制随机，结果发现改不了，而且自己写程序模拟也没有，因为他是按照当前时间来作为种子随机的。

后面出了wp才发现，原来可以直接利用python的eval()函数自动计算。

<!-- more -->

eval()函数会自动识别字符串为数学表达式，并返回计算结果，根据这个可以直接把结果输出。


```python
from pwn import*
elf=ELF("./pwn")
p=process("./pwn")
#p=remote()

for i in range(100):
    p.recvuntil('answer?')
    n = p.recvline().decode()
    print(n)
    
    #strip()返回删除前导和尾随空格的字符串副本
    #split('=')是以'='为分隔符分割字符串，分割后的不同部分放在一个列表中。
    question = n.strip().split('=')[0]
  
  
    if 'x' in question:
        question = question.replace('x','*')
  
  
    answer = str(eval(question))
  
  
    p.sendline(answer)
p.interactive()
```
