---
title: FearWell
date: 2023-03-18 13:42:16
categories: 
- pwn_wp
tags: 
- pwn
- kernel

---

NewStar CTF 的kernel，预期解就是非预期解。

<!--more-->

启动脚本如下：

```sh
#!/bin/sh

qemu-system-x86_64  \
-m 128M \
-kernel ./bzImage \
-initrd ./rootfs.cpio \
-cpu kvm64,+smep,+smap \
-append "root=/dev/ram console=ttyS0 oops=panic quiet panic=1 kaslr" \
-nographic \
-no-reboot 

```

可以看到没有`-monitor`选项将监视器重定向到主机设备`/dev/null`，因此我们可以通过`ctrl a + c`进入`qemu`的`monitor`模式，之后通过`migrate "exec: cat rootfs.cpio 1>&2"`查看`rootfs.cpio`文件，在其中找`flag`。