---
title: closed
date: 2023-01-02 19:54:26
categories: 
- pwn_wp
tags: 
- pwn
- linux_trick

---

NewStarCTF，考察linux重定向机制
<!-- more -->

这题没必要查壳了，运行后会执行close(1)、close(2)，之后就会执行system("/bin/sh")

文件描述符0、1、2分别表示标准输入(stdin)、标准输出(stdout)和报错(stderr)，执行close()之后，对应的信息将不会显示出来。

在此题中关闭了输出和报错这两个文件，因此我们即使得到了shell，由于stdout的文件关闭了，命令执行结果无法写入stdout，屏幕上自然不会有输出结果显示。

不过如果把输出重定向，改变，就可以有输出结果显示了。

**linux重定向机制**

重定向就是**改变数据的流向**。重定向分为**输入重定向**和**输出重定向**，分别是改变输入数据和输出数据的流向，分别用<、<<,>,>>来表示。

输入重定向，顾名思义是改变输入数据的流向（来源）。

```
command < filename  //通过这条命令，可以修改输入数据的来源，由键盘输入的缓冲区(stdin)修改为其他文件
command << identifier(标识符)   //通过这条命令，可以修改键盘输入的结束符，由换行符修改为自定义的标识符
```

输出重定向，顾名思义是改变输出数据的流向（去向）。

```
command > filename  //通过这条命令，可以修改执行结果的去向，由显示器的缓冲区(stdout)修改为其他文件，会覆盖文件中原有的数据
command >> filename //通过这条命令，可以修改执行结果的去向，由显示器的缓冲区(stdout)修改为其他文件，不会覆盖文件中原有的数据，而是在原有数据的末尾追加
command 2 > filename    //将错误输出到文件中，2是stderr的文件描述符
command 2 > &1  //将错误输出到标准输出的位置，1是stdout的文件描述符，其他同理
```

exp：

```python

from pwn import*
p=remote()
p.sendline("exec 1>&0")
p.interactive()

```