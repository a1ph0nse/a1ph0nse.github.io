---
title: ArmPwn
date: 2023-01-07 10:53:26
categories: 
- pwn
tags: 
- pwn
- arm

---

Arm架构下的pwn与x86类似，只是用的是RISC的处理器架构，指令集会与x86有较大的差别。Arm广泛地使用在许多嵌入式系统设计。由于节能的特点，ARM处理器非常适用于移动通讯领域，符合其主要设计目标为低耗电的特性。因此我们常用的手机、平板等移动设备都是采用ARM体系架构的，因此CTF中不可避免也会出现ARM架构的pwn题，但是相比x86会简单许多，通常都是普通的栈溢出。
<!-- more -->

## 环境搭建

本地的机器大多都是`x86`架构的，无法运行`ARM`架构的程序，需要我们通过`qemu`来运行。

### 32位

采用命令`qemu-arm prog_name`运行。

```sh
qemu-arm -L /usr/arm-linux-gnueabi/ ./prog # 不是hf的
qemu-arm -L /usr/arm-linux-gnueabihf/ ./prog # hf的
```

### 64位

采用命令`qemu-aarch64 ./prog`运行。

但对于**动态链接**的程序还是无法正常运行，此时需要安装对应架构的动态链接库才行：（`arm64`和`aarch64`是同一个架构的不同名称）

```sh
sudo apt search "libc6" | grep arm
sudo apt install libc6-dbg-arm64-cross # 或其他的库
```

安装完成后在`/usr`目录下会出现`aarch64-linux-gnu`这个文件夹，该文件夹即对应刚安装好的arm64位libc库，之后我们使用下面的命令指定arm程序的动态链接器，即可运行程序，32位类似。

通过`-L `指定libc`qemu-aarch64 -L /usr/aarch64-linux-gnu/ ./prog`

`armel`和`armhf`，这主要是针对浮点计算来区分的，其中`armel (arm eabi little endian)`使用fpu浮点运算单元，但传参还是用**普通寄存器**；`armhf (arm hard float)`也使用fpu浮点运算单元，同时使用fpu中的**浮点寄存器**传参。

`arm64`默认用的是`armhf`，所以也就没有这个后缀，因此**有这个后缀区分的都是指的是32位arm架构**。

### 大端序的arm

采用命令`qemu-armeb`运行。

### 调试

在`qemu`启动程序时通过`-g`指定端口：

```sh
# qemu-arch -g port -L /usr/arch-lib-dir/ ./prog
qemu-arm -g 8888 ./typo
```

利用`gdb-multiarch`连上端口进行调试：

```sh
$ gdb-multiarch
......
......
pwndbg> set architecture arm
The target architecture is assumed to be arm
pwndbg> target remote localhost:8888
```

在`pwntools`中调试的话需要修改下代码：

```py
 p = process(["qemu-arm", "-g", "8888", "./typo"])
```

如果32位遇见这个报错的话：`/lib/ld-linux-armhf.so.3: No such file or directory`

输入命令`sudo apt-get install libc6-armhf-cross`

如果遇见这个报错的话：`Invalid ELF image for this architecture`

说明用的`qemu`架构不对

## 基础知识

### 寄存器

```
32位：
R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15...
64位：
X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15...
```

#### 32位

![arm](./ArmPwn/arm32register)

- `R0~R3`主要用于子程序之间的**参数传递**，剩下的参数**从右向左**依次入栈， 被调用者实现栈平衡，函数的**返回值保存在 `R0`** 中
- `R4~R11`主要用于**保存局部变量**，但在 Thumb 程序中，通常只能使用`R4~R7`来保存局部变量
- `R12`用作子程序间scratch 寄存器，即 ip 寄存器
- `R13`为`SP`，即栈指针。在物理上实际上有两个栈指针：主栈指针(MSP)和进程栈指针(PSP)，一般的进程只有一个栈指针可见。这个也好理解，就好比在x86-64系统中，内核的栈指针和用户进程的栈指针不同一样。
- `R14`为链接寄存器`LR`，用于保存函数或子程序调用时**返回地址**。在x86-64系统中，函数调用的返回值是保存在子函数栈帧的上面，即`rbp+8`的位置，在ARM系统中，函数调用同样需要将返回地址保存到栈中，因为`LR`在函数返回时会进行自动更新，如果栈中没有返回地址，那么`LR`就不知道要更新成什么值了。
- `PC`为程序计数器。`PC`的最低有效位（LSB）是一个控制结构，为1时表示进入Thumb状态。当有些时候程序跳转更新PC时需要将新PC值的LSB置1，否则会触发错误异常。这也可以看做是一种程序恶意跳转的保护机制。有时还会将`PC`作为基址访问数据。

除了这些寄存器之外，还有一些特殊寄存器，他们未经过存储器映射,可以使用MSR和MRS等特殊寄存器访问指令来进行访问。

 程序状态寄存器包括以下三个状态寄存器：

- 应用PSR（APSR）
- 执行PSR（EPSR）
- 中断PSR（IPSR）

中断/异常屏蔽寄存器：

- PRIMASK
- FAULTMASK
- BASEPRI
- 只有特权状态才可以操作三个寄存器（非特权状态下的写操作会被忽略，读操作返回0）。三个寄存器默认值为0，即屏蔽（禁止异常/中断）不起作用。

CONTROL寄存器

另外，在x86-64架构和ARM架构中都有很多的**浮点数**寄存器，用于进行浮点数计算。在ARM架构中，浮点数寄存器有32个32位寄存器`S0~S31`，其中可以两两组合访问为`D0~D15`，如`S0`和`S1`组合为`D0`。

#### 64位

ARMv8有31个通用寄存器`X0-X30`, 还有`SP`、`PC`、`XZR`等寄存器

- `X0-X7` 用于**参数传递**
- `X9-X15` 在子函数中使用这些寄存器时，直接使用即可, 无需save/restore. 在汇编代码中x9-x15出现的频率极低
- `X19-X29` 在callee子函数中使用这些寄存器时，需要**先save**这些寄存器，在退出子函数时再resotre
- `X8, X16-X18, X29, X30` 这些都是特殊用途的寄存器
    - `X8`： 用于**返回结果**
    - `X16`、`X17 `：进程内临时寄存器
    - `X18` ：resrved for ABI
    - `X29` ：`FP`（frame pointer register）
    - `X30` ：`LR`，用于保存函数或子程序调用时**返回地址**。

### 指令集

**指令、伪指令**

（汇编）指令： 是机器码的**助记符**，经过汇编器编译后，由CPU执行。

（汇编）伪指令：用来**指导**指令执行，是汇编器的产物，**最终不会生成机器码**。

**有两种不同风格的ARM指令**

1. ARM官方的ARM汇编风格：指令一般用大写。

2. GNU风格的ARM汇编：指令一般用小写。

ARM的指令集和x86-64有一些相似之处，但也有一些不同，需要注意的是，**ARM的立即数前面需要加上#标识**，如#0x12345678。下面的指令均为32位系统下的指令。

#### 寄存器与寄存器（立即数）之间的数据传送（`MOV`系列指令）

```asm
MOV/MOVS reg1, <reg2/imm8>：赋值reg1为reg2/imm8
MOVW <reg32>, <imm16>：赋值reg32的低16位为imm16
MOVT <reg32>, <imm16>：赋值reg32的高16位为imm16
MVN reg1, <reg2>：将reg2的值取反之后赋值给reg1
LDR <reg32>, =<imm32>：赋值reg32为imm32
```

#### 存储器传送数据（`LDR`和`STR`系列指令）

ARM使用单独的指令集进行寄存器和内存空间的数据交换，其中基址可以选择任意一个通用寄存器或PC寄存器，变址也可以使用任意一个通用寄存器，较x86更加灵活：

`LDR`：加载某一地址的内容到寄存器

`STR`：存储寄存器的内容到某一地址

```asm
LDRB/LDRH/LDR reg1, [<reg2/PC>, <imm32>]<!>：赋值8/16/32位reg2+imm32地址的数据到reg1，如果指令后面有叹号，表示指令执行后reg2值更新为reg2+imm32，有叹号可等同于 LDRB/LDRH/LDR reg1, [<reg2>], <imm32>，这种形式称为后序指令。
LDRD reg1, <reg2>, [<reg3/PC>, <imm32>]<!>：赋值64位reg3+imm32地址的数据到reg1和reg2，有叹号可等同于 LDRD reg1, <reg2>, [reg3], <imm32>
LDRSB/LDRSH reg1, [<reg2/PC>, <imm32>]<!>：有符号传送8/16位reg2+imm32地址的数据到reg1，目标寄存器会进行32位有符号扩展，有叹号可等同于 LDRSB/LDRSH reg1, [<reg2>], <imm32>
STRB/STRH/STR reg1, [<reg2>, <imm32>]<!>：保存寄存器reg1的8/16/32位值到reg2+imm32地址，有叹号可等同于 STRB/STRH/STR reg1, [<reg2>], <imm32>
STRD reg1, <reg2>, [reg3, <imm32>]<!>：保存寄存器reg1和reg2的64位值值到reg3+imm32地址，有叹号可等同于 STRD reg1, <reg2>, [reg3], <imm32>
LDRB/LDRH/LDR reg1, [<reg2/PC>, reg3{, LSL <imm>}]：赋值寄存器reg1的值为reg2/PC+(reg3{<<imm})地址处的8/16/32位值
LDRD reg1, <reg2>, [<reg3/PC>, <reg4-32>{, LSL <imm>}]：赋值寄存器reg1和reg2的值为reg3/PC+(reg4-32{<<imm})地址处的64位值
STRB/STRH/STR reg1, [<reg2>, reg3{, LSL <imm>}]：保存寄存器reg1的8/16/32位值到reg2+(reg3{<<imm})地址
LDMIA/LDMDB reg1<!>, <reg-list>：将reg1地址的值按照顺序保存到reg-list中的寄存器中，如果reg1后有叹号，则在保存值后自动增加（LDMIA）或减少（LDMDB）reg1。如LDMIA R0, {R1-R5}，LDMIA R0, {R1, R3, R6-R9}
STMIA/STMDB reg1<!>, <reg-list>：向reg1地址存入寄存器组中的多个字。如果reg1后有叹号，则在保存值后自动增加（STMIA）或减少（STMDB）reg1。
```

注意：后序指令不能使用PC寻址。

#### 入栈出栈

虽然ARM与x86都使用push和pop指令进行入栈和出栈，但ARM可以实现一条指令多次出入栈。

```asm
PUSH <reg-list>：将寄存器组中的寄存器值依次入栈，reg-list中可以有PC、LR寄存器。
POP <reg-list>：将出栈的值依次存入寄存器组中的寄存器，reg-list中可以有PC、LR寄存器。
```



#### 算术运算

不同于x86指令的大多数算术运算使用两个寄存器，ARM指令的算数运算指令**通常包含3个寄存器**，实现运算后的自由赋值而不是x86中必须赋值给目标寄存器且目标寄存器必须参与运算。

第一个操作数用于**保存运算结果**，第二个操作数作**被**加/减/乘/除数，第三个操作数作加/减/乘/除数。

`ADD/C`加/进位加、`SUB/SBC`减/借位减、`MUL`乘、`U/SDIV`无/有符号除法...

```asm
ADD/SUB reg1, <reg2>, <reg3/imm32>：计算<reg2>(+/-)<reg3/imm32>将结果保存到reg3
ADC/SBC reg1, <reg2>, reg3：计算<reg2>(+/-)reg3+(进位/借位)将结果保存到reg3
ADC <reg32>, <imm32>：计算reg32+imm32+进位将结果保存到reg32
SBC reg1, <reg2>, <imm32>：计算<reg2>-imm32-借位将结果保存到reg1
RSB reg1, <reg2>, <reg3/imm32>：计算<reg3/imm>-<reg2>将结果保存到reg1
MUL reg1, <reg2>, reg3：计算<reg2>*reg3将结果保存到reg1
UDIV/SDIV reg1, <reg2>, reg3：计算<reg2>/reg3（无符号/有符号）将结果保存到reg1，如果除以0，则结果为0
MLA reg1, <reg2>, reg3, <reg4-32>：计算reg1=<reg2>*reg3+<reg4-32>
MLS reg1, <reg2>, reg3, <reg4-32>：计算reg1=-<reg2>*reg3-<reg4-32>
```

#### 移位运算

`ASR`算术右移（补充符号位）、`LSL`逻辑左移、`LSR`逻辑右移、`ROR`循环右移。

如果有两个操作数：第一个操作数用于**保存运算结果**，也是**被移位的数**，第二个操作数是**移动的位数**

如果有三个操作数：第一个操作数用于**保存运算结果**，第二个操作数是**被移位的数**，第三个操作数是**移动的位数**

```asm
ASR/LSL/LSR reg1, <reg2>{, <reg3/imm32>}：如果reg3/imm存在，则表示reg1=<reg2>(>>/<<)<reg3/imm32>，否则表示reg1=reg1(>>/<<)<reg2>（算数右移、逻辑左移、逻辑右移）
ROR reg1, <reg2>{, reg3}：如果reg3存在，则表示reg1=<reg2>(>>)reg3，否则表示reg1=reg1(>>)<reg2>（循环右移）
```

#### 数据取反

将寄存器中的值按字节进行取反。

```asm
REV reg1, reg2：将reg2中的4字节数据按字节反转后赋值给reg1（reg2值不变），原先第0，1，2，3字节的内容被换到了第3，2，1，0字节。
REV16 reg1, reg2：将reg2中的4字节以字单位分为高字和低字分别进行反转后赋值给reg1（reg2值不变），原先第0，1，2，3字节的内容被换到了第1，0，3，2字节。
REVSH reg1, reg2：将reg2中的低2字节反转后有符号扩展赋值给reg1
REVH reg1, reg2：REV指令的16位表示，只反转低2字节。
```

#### 位域操作
位域操作允许机器指令对寄存器中的特定位进行处理，在x86中好像是也有这样的指令，只是使用频率太低。

```asm
BFD reg1, #lsb, #width：将reg1中从第lsb位开始的连续width位清零。
BFI reg1, reg2, #lsb, #width：将reg2中最低width位复制到reg1中从lsb位开始的连续width位。
CLZ reg1, reg2：计算reg2中高位0的个数并赋值给reg1，多用于浮点数计算。
RBIT reg1, reg2：反转reg2寄存器中的所有位并赋值给reg1。
SBFX/UBFX reg1, reg2, #lsb, #width：取reg2中从第lsb位开始的连续width位并有/无符号扩展，赋值给reg1。
```

#### 比较和测试指令
与x86使用cmp指令和test指令相似，ARM也有关于比较和测试的指令，且实现原理基本相同。

```asm
CMP reg1, reg2/imm：比较两个寄存器或寄存器与立即数，更新标志位APSR。
CMN reg1, reg2/imm：比较reg1和-reg2或-imm，更新标志位APSR。
TST reg1, reg2/imm：参照x86的test指令，相与测试，更新N（负数位）和Z（零）标志
TEQ reg1, reg2/imm：异或测试，更新N和Z标志
```

#### 跳转指令

`B`系列的位跳转指令，`BL`相当于`call`。

```asm
B/B.W <label>：无条件跳转到指定位置，B.W跳转范围更大。
BX reg：寄存器跳转。
BL <label> / BLX reg：跳转到指定位置/寄存器值，且将返回地址保存到LR寄存器中，类比x86的call指令。一般在函数开头都会首先将BL寄存器的值保存到栈中便于返回时获取。
条件跳转指令族：类比x86指令：
BEQ == je
BNE == jne
BCS/BHS == jc（进位标志为1，可表示无符号大于等于）
BCC/BLO == jnc（进位标志为0，可表示无符号小于）
BMI == js（负数标志为1）
BPL == jns（负数标志为0）
BVS == jo（溢出标志为1）
BVC == jno（溢出标志为0）
BHI == ja（无符号大于）
BLS == jbe（无符号小于等于）
BGE == jge（有符号大于等于）
BLE == jle（有符号小于等于）
BGT == jg（有符号大于）
BLT == jl（有符号小于）
CBZ/CBNZ reg, <label>：比较寄存器的值为0/不为0时跳转（只支持前向跳转）
```

## 解题技巧

1. arm pwn程序在IDA反汇编后通常都是一大堆sub函数，有许多常用的函数都没有符号，这时**不要硬逆**。arm程序逻辑较为简单，可通过**运行**大致猜测是什么函数。**（三分逆，七分猜**
1. 栈溢出时覆盖`LR`在栈上的位置，并通过劫持`PC`不断控制执行流。
1. 在面对静态链接的程序，IDA打开之后会发现里面有几百个函数，而且也搜不到main函数，在这种情况下，可以利用搜**索关键字符串，通过关键字符串去找主函数**。



