---
title: Docker的使用
date: 2023-01-02 00:02:00
categories: 
- pwn
tags: 
- docker
- pwn
---
Docker是一种容器，与虚拟机有所不同。虚拟机在宿主机上建立一层虚拟层，在虚拟层上运行新的os，而容器没有建立虚拟层，直接调用原生os的资源。因此虚拟机的隔离性更好，当然消耗资源也会更高，而容器的隔离性没有这么好，属于原生os的一个进程。

<!--more-->

## Docker的基本概念

Docker中有三个基本的概念，分别是**镜像(Image)、容器(Container)和仓库(repository)**。镜像是容器运行的前提，仓库是存放容器的场所，镜像是Docker的核心。

镜像可以看作是一个**特殊的文件系统**，除了提供容器运行时所需的程序、库、资源、配置等文件外，还包含了一些为运行时准备的一些配置参数（如匿名卷、环境变量、用户等）。镜像不包含任何动态数据，其内容在构建之后也不会被改变。

容器 (container) 的定义和镜像 (image) 几乎一模一样，也是一堆层的统一视角，唯一区别在于容器的最上面那一层是可读可写的。实际上，**容器 = 镜像 + 读写层**。

仓库是集中存放镜像文件的场所。镜像构建完成后，可以很容易的在当前宿主上运行，但是， 如果需要在其它服务器上使用这个镜像，我们就需要一个集中的存储、分发镜像的服务，Docker Registry (仓库注册服务器)就是这样的服务。有时候会把仓库(Repository) 和仓库注册服务器 (Registry) 混为一谈，并不严格区分。Docker 仓库的概念跟 Git 类似，注册服务器可以理解为 GitHub 这样的托管服务。实际上，一个 Docker Registry 中可以包含多个仓库 (Repository) ，每个仓库可以包含多个标签 (Tag)，每个标签对应着一个镜像。所以说，**镜像仓库是 Docker 用来集中存放镜像文件的地方**类似于我们之前常用的代码仓库。

通常，一个仓库会包含同一个软件不同版本的镜像，而标签就常用于对应该软件的各个版本 。我们可以通过 **<仓库名>:<标签>的格式**来指定具体是这个软件哪个版本的镜像。如果不给出标签，将以 latest 作为默认标签。

## Docker常用命令

```sh
docker -help //获取帮助手册
docker pull image_name //拉取名字为image_name的镜像
docker images //查看本地的镜像
docker ps -a //查看哪些容器运行过
docker ps //查看哪些容器正在运行
docker start container_name/container_id //启动容器
docker restart container_name/container_id //重启容器
docker stop container_name/container_id //关闭容器
docker attach container_name/container_id //进入容器

//运行容器
docker run --name image_name -d -p port repo_name/image_name:tag //-p指定该容器的端口号 -d表示后台运行
docker run -t -i container_name/container_id /bin/bash // -t 终端、-i 交互式操作

docker search image_name //查找镜像
docker rm container_name/container_id //删除容器
docker rmi image_name //删除镜像
```

## Dockerfile

Dockerfile是一个用来构建镜像的文本文件，文本内容包含了一条条构建镜像所需的指令和说明，用户可以使用 Dockerfile 快速创建自定义的镜像。

一般来说，我们可以将 Dockerfile 分为四个部分：

1. 基础镜像(父镜像)信息指令 FROM
2. 维护者信息指令 MAINTAINER
3. 镜像操作指令 RUN 、 EVN 、 ADD 和 WORKDIR 等
4. 容器启动指令 CMD 、 ENTRYPOINT 和 USER 等

我们可以通过build命令使用Dockerfile创建镜像：

```shell
docker build -t repo_name/image_name:tag dockerfile_relative_path //-t 是为新镜像设置仓库和名称 dockerfile_relative_path表示Dockerfile的相对路径
```


### Dockerfile常用指令

由于 Dockerfile 中所有的命令都是以下格式：INSTRUCTION argument ，指令 (INSTRUCTION) 不分大小写，但是**推荐大写**。

#### FROM

定制的镜像往往是基于一个原有的镜像进行的，Docker中的From命令就是用于**指定基础镜像**。一般格式为：

```docker
FROM image_name/image_name:tag
```

FROM 以后的所有指令都会在 FROM 的基础上进行创建镜像。可以在同一个 Dockerfile 中多次使用 FROM 命令用于创建多个镜像。

#### MAINTAINER（将被删除）

MAINTAINER 是用于指定镜像创建者和联系方式。一般格式为：

```docker
MAINTAINER name <email>
```

#### COPY

COPY 是用于**复制本地主机的资源**\<src>(为 Dockerfile 所在目录的相对路径)到容器中的\<dest>。一般格式为：

```docker
COPY src dest
```

#### ADD

ADD命令的功能与COPY类似，都是在容器中新增一个资源，但不同的是ADD可以从网络中获取资源，并且如果源文件为.tar的话，ADD命令可以自动解压缩到目标路径。

但是在不解压的前提下，无法复制 tar 压缩文件。这会令镜像构建缓存失效，从而可能会令镜像构建变得比较缓慢。

一般格式：

```docker
ADD src dest
```

#### WORKDIR

WORKDIR 用于配合 RUN，CMD，ENTRYPOINT 命令**设置当前工作路径**。可以设置多次，如果是相对路径，则**相对前一个 WORKDIR 命令**，默认路径为/。

一般格式为:

```docker
WORKDIR relative_path
```

#### RUN

RUN 用于容器内部执行命令。每个RUN命令相当于在原有的镜像基础上添加了一个改动层，原有的镜像不会有变化。一般格式为:

```docker
RUN command
```

#### EXPOSE

EXPOSE 命令用来指定对外开放的端口（实际情况下不一定会打开）。一般格式为:

```docker
EXPOSE port/[port,...]
```

#### ENTRYPOINT

ENTRYPOINT 可以让你的容器表现得像一个可执行程序一样。一个 Dockerfile 中只能有一个 ENTRYPOINT，如果有多个，则最后一个生效。

ENTRYPOINT命令有两种格式：

```docker
ENTRYPOINT ["executable", "param1", "param2"] //推荐使用的 exec形式(直接调用对应命令)
ENTRYPOINT command param1 param2 //shell 形式(通过shell执行命令，如果没有shell则不行)
```

#### CMD

CMD 命令用于**启动容器时默认执行的命令**，CMD 命令可以包含可执行文件，也可以不包含可执行文件。不包含可执行文件的情况下就要用 ENTRYPOINT 指定一个，然后**CMD命令的参数就会作为ENTRYPOINT的参数**。

CMD命令有三种格式：

```docker
CMD ["executable","param1","param2"] //推荐使用的 exec 形式(直接调用对应命令)
CMD ["param1","param2"] //无可执行程序形式
CMD command param1 param2 //shell 形式(通过shell执行命令，如果没有shell则不行)
```

#### VOLUME 

VOLUME命令用于挂载一个目录，即**建立一个容器和宿主机的目录的映射**，其中的内容是共享的，一处改变另一处也会改变。可以在docker build中使用-v指令指定宿主机映射的目录，如果没有则默认映射到/docker/value/.../data。

一般格式为：

```docker
VOLUME directory_name
```

#### USER

USER命令用于指定执行后续命令的用户或用户主，一般格式为：

```docker
USER user_name[:user_group]
```

#### ARG

ARG命令用于设置一个dockerfile中的变量，一般格式为:

```docker
ARG key = value
```

#### ENV

ENV命令用于设置环境变量，一般格式为：

```docker
ENV key = value
```

### Docker特权设置

docker容器本质上仍是一个使用当前系统资源运行的进程。因此，即使在容器中有了root权限，有些操作仍然不能进行（因为会对系统的资源进行更改）。如果想要容器拥有这些权限，我们需要手动设置。

docker使用--privileged, --cap-add, --cap-drop 来对容器本身的能力进行开放或限制，使用 --cap-add, --cap-drop 可以**添加**或**禁用**特定的权限，--privileged可以开放所有的权限。

```docker
docker run -it --cap-add SYS_TIME --rm --name centos /bin/sh //开放了SYS_TIME的权限
//--rm代表运行完自动删除
```

### 缓存清理

当镜像太多的时候，会占用不少的空间，此时可以清理缓存让自己多点空间可用。在使用build新建容器的时候，为了减少之后build所需的时间，部分内容会存入cache当中，如果空间太大了可以手动清空一下缓存：

```docker
docker builder prune
```

清除所有镜像（慎用）

```docker
docker image prune
```

清除所有网络、容器、镜像和缓存（慎用）

```docker
docker system prune
```

## Docker Compose

Compose 是用于定义和运行多容器 Docker 应用程序的工具。通过 Compose，您可以使用 YML 文件来**配置应用程序需要的所有服务**。然后，使用一个命令，就可以从 YML 文件配置中创建并启动所有服务。

### YAML

YAML 的语法和其他高级语言类似，并且可以简单表达清单、散列表，标量等数据形态。它使用空白符号缩进和大量依赖外观的特色，特别适合用来表达或编辑数据结构、各种配置文件、倾印调试内容、文件大纲（例如：许多电子邮件标题格式和YAML非常接近）。YAML 的配置文件后缀为 .yml

基本语法:

- 大小写敏感
- 使用缩进表示层级关系
- 缩进不允许使用tab，只允许空格
- 缩进的空格数不重要，只要相同层级的元素左对齐即可
- '#'表示注释

#### YAML对象

对象键值对使用冒号结构表示 key: value，**冒号后面要加一个空格**。

对象之间可以嵌套，使用缩进表示层级关系。

```YAML
key: 
    child_key1: value1
    child_key2: value2
```

如果有复杂的对象，可以使用?加空格表示复杂的key，使用:加空格表示value。

```YAML
? 
    - key1
    - key2
: 
    - value1
    - value2
```

#### YAML数组

用- 开头的行表示一个数组

```YAML
- A
- B
- C
```

表示数组[A,B,C]

可以支持多维数组：

```YAML
- 
 - A
 - B
 - C
```

表示[[A,B,C]]

数组也可以使用流式(flow)的方式表示：

```YAML
companies: [{id: 1,name: company1,price: 200W},{id: 2,name: company2,price: 500W}]
```

数组和对象可以构成复合结构。

#### 纯量

最基本的不可再分的值，包括：字符串（可以拆成多行，每一行会被转化成一个空格）、布尔值、整数、浮点数、Null、时间（使用ISO 8601格式，时间和日期之间使用T连接，最后使用+代表时区）、日期（必须使用ISO 8601格式，即yyyy-MM-dd）。


#### 锚点和引用

用&表示建立锚点，用*表示引用锚点。

```YAML
defaults: &defaults
  adapter:  postgres
  host:     localhost

development:
  database: myapp_development
  <<: *defaults
```

相当于:

```YAML
defaults:
  adapter:  postgres
  host:     localhost

development:
  database: myapp_development
  adapter:  postgres
  host:     localhost
```

<<表示合并到当前数据。

### 本次出题

```docker
docker build -t "problem_name" .
docker run -d -p "0.0.0.0:pub_port:9999" -h "hostname" --name="container_name" problem_name
```

编译

```sh
# NX保护机制：
-z execstack / -z noexecstack  # (关闭 / 开启) 堆栈不可执行

# Canary：(关闭 / 开启 / 全开启) 栈里插入cookie信息
# !开canary好像会造成栈中局部变量的顺序有所改变
-fno-stack-protector /-fstack-protector / -fstack-protector-all 

# ASLR和PIE：
-no-pie / -pie   # (关闭 / 开启) 地址随机化，另外打开后会有get_pc_thunk

# RELRO：
-z norelro / -z lazy / -z now   # (关闭 / 部分开启 / 完全开启) 对GOT表具有写权限

-s   # 去除符号表

```

