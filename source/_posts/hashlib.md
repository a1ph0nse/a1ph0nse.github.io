---
title: hashlib
date: 2023-03-16 10:49:42
categories: 
- crypto
tags: 
- crypto
 

---

hashlib是一个提供了一些流行的hash(摘要)算法的Python标准库．其中所包括的算法有 md5, sha1, sha224, sha256, sha384, sha512等
摘要算法又称hash算法、散列算法。它通过一个函数，把任意长度的数据转换为一个长度固定的数据串（通常用16进制的字符串表示）。

```py
hashlib.algorithms
#列出所有加密算法

h.digest_size
#产生的散列字节大小。

h.block_size
#哈希内部块的大小
```



<!--more-->

### 选择加密算法

```py
# 导入hashlib
import hashlib
# 创建md5对象，其他算法也类似
md5=hashlib.md5()
```

### 传入明文数据

```py
# 使用update函数传入明文数据，需要设置编码方式
md5.update('...'.encode(encoding='...'))
# 多次使用update传输与一次传输完是一样的
md5.update('.'.encode(encoding='...'))
md5.update('.'.encode(encoding='...'))
md5.update('.'.encode(encoding='...'))
```

### 获取加密密文

```py
# 返回摘要，作为二进制数据字符串值
res=md5.digest()
# 返回摘要，作为十六进制数据字符串值
res=md5.hexdigest()

# 可使用以下方法获取二进制串
b''
str.encode()
bytes()
```

### 其他

```py
# 复制
hash.copy()
```

