---
layout: post
title:  "2019.4.4 playing with morden protected bufferoverflow"
tags: [bufferoverflow, pwn, linux, morden]
date: 2019-04-01
comments: true
---

# linux的防护机制下的bufferoverflow

## 最普通的bufferoverflow

CTF中，pwn类入门题目中最简单便属stackoverflow了吧。如hitcon training中的 lab3-ret2sc。

![5ca60f25271e9](https://i.loli.net/2019/04/04/5ca60f25271e9.png)

![5ca60f728c4d5](https://i.loli.net/2019/04/04/5ca60f728c4d5.png)

题目很简单，也没有开启canary。先输入一个name，然后调用了gets()这个危险函数，便导致了bufferoverflow，可以overflow到栈上保存的返回地址，覆盖它为name的地址。同时在name中存上我们的shellcode即可。

函数最后的return也没有很复杂的操作，只是简单的leave ret。

---

## 在虚拟机下编译一个32bit的bufferoverflow

这里我使用虚拟机是backbox，基于ubuntu16.04

我们首先来编译一个看起来很简单的bufferoverflow challenge。

![5ca61448166a7](https://i.loli.net/2019/04/04/5ca61448166a7.png)

正常的编译一下。

![5ca614ba8d86a](https://i.loli.net/2019/04/04/5ca614ba8d86a.png)

同样使用到了gets()函数，一样的套路？只要输入超过长度限制的字符，溢出到栈上的a变量，它的值便会改变。然后就执行了cat flag？

但在实际操作之前，我们还是先看一下它的保护情况。

![5ca6150790914](https://i.loli.net/2019/04/04/5ca6150790914.png)

开启了Canary，因为是32bit，所以Canary的长度为3个字节，因为它的最低位永远为0。因此每次运行程序Canary的值都有$256^3$=16777216种可能。

如果无视Canary强行overflow，程序执行stack_check__fail时便会检查到异常，直接退出。4

绕过Canary，也许可以通过爆破的方法？运气好的话是可以撞到。

可以看出，单单一个Canary保护，便让漏洞利用变得如此困难。

既然如此，我们不妨先放下Canary，假设我们知道了程序每一次运行时的Canary，看看我们利用它，能不能达成这个漏洞的利用。

使用gdb调试，在stack_check__fail处下断点，然后执行command，set ip为通过检查后的指令位置即可。

![5ca618f2ee8aa](https://i.loli.net/2019/04/04/5ca618f2ee8aa.png)

这样的话，理论上来说，我们输入足够多的字符，便可以溢出到a的位置，然后执行system了？

来尝试一下。

![5ca61a39a17b9](https://i.loli.net/2019/04/04/5ca61a39a17b9.png)

结果并非如此。

反而我们得到了一个Stopped reason: SIGSEGV？看样子ESP被改变为了类似我们输入的字符串？

查看一下主函数的汇编指令，找一找哪里出了问题。

![5ca61ac0aff04](https://i.loli.net/2019/04/04/5ca61ac0aff04.png)

在main+36这个地方，我们发现数值0也就是变量a，被存在了ebp-0x50这个地方。

而我们的输入的buffer，则是从ebp-4c开始的。大概是这样的画风。

![5ca61cbe97f1f](https://i.loli.net/2019/04/04/5ca61cbe97f1f.png)

我们知道，我们输入的buffer是从低地址向高地址延伸的，而a的位置比buffer起始位置低，这便说明，我们输入的buffer不可能溢出到变量a。

但是，能不能通过溢出到返回地址，让其返回到执行system的地方呢?gcc编译默认是没有开启pie的，它的代码段地址是固定的。

实际上是不可以的。

仔细一点的话，可以看到上面报了 Invaild $SP address : 0x4141413d，EIP的指向却是正常的。

也就是说，输入了那么多个A，并没有能够成功的修改ip劫持控制流,反而把esp给搞坏了。这也说明，真正栈的样子,并没有上图那么简单。

让我们仔细看一下汇编，问题出在main+125，它将ecx - 0x4找个位置的值赋给了esp。

这个ecx是ebp-0x4中存的值。看起来好像有点迷糊。还是用gdb跟踪一下栈把。

![5ca62035bd4e1](https://i.loli.net/2019/04/04/5ca62035bd4e1.png)

可以看到，栈顶存放着call main的下一条命令的地址，这是正常的。

接着ecx中存了esp+0x4这个地址。 

![5ca62102ac849](https://i.loli.net/2019/04/04/5ca62102ac849.png)

接着esp对齐到上方的位置。

![5ca6223fe0cb5](https://i.loli.net/2019/04/04/5ca6223fe0cb5.png)

接着ecx-0x4指向的数据入栈，也就是返回地址入栈了。

![5ca6228b6c1f4](https://i.loli.net/2019/04/04/5ca6228b6c1f4.png)

紧接着是正常的push ebp;mov ebp,esp;sub esp,0x64...开辟了栈帧。

可以看到，在普通的开辟新栈帧之前，程序做了一些事，而就是这些事，最终导致了我们的失败。

现在再来看一下函数结束之后，程序是如何获得ip的。

![5ca623e0d4478](https://i.loli.net/2019/04/04/5ca623e0d4478.png)

首先把ebp-0x4也就是0xffffd534这个位置的值给了ecx，而这个值是之前开辟完栈帧后保存的ecx的值。这一步是恢复ecx。

![5ca6255a162f2](https://i.loli.net/2019/04/04/5ca6255a162f2.png)

然后leave: mov esp,ebp;pop ebp;

到这里都很正常。

之后可以发现，程序并没有直接ret，而是又把ecx-0x4这个位置当作esp，接着才ret掉。

ecx-0x4正是0xffffd54c，也就是esp又回到了刚刚call进来的样子。

不难发现，之前push的返回地址并没有起到作用。真正的返回地址是从ecx-0x4中取得。

而ecx的值又是从ebp-0x4处取来，注意，这个值是位于栈上的。是会被我们的buffer覆盖的!

也就是说，我们的buffer溢出到了ebp-0x4的位置(这个位置存放着正确的ecx值)。导致esp的值因为我们的输入而被破坏了，从而没法执行下一条ret指令，也就是为什么没得到一个返回地址无效错误，而是得到了一个esp无效值错误。

整个栈如下图

![5ca62a63a7ec6](https://i.loli.net/2019/04/05/5ca62a63a7ec6.png)

看起来很糟糕，溢出返回地址的方法看似也走不通了。

但是，仍然有其他方法。

通过观察。发现正确的ecx值实际上是栈上不远处的一个地址。

也就是说如果我们只改变它的最低位，而不把它全部覆盖的话 ，以上面的为例子。

ecx=0xffffd550

我们如果能将他改写为

ecx=0xffffd500

那么esp最后得到的值为0xffffd500-4 = 0xffffd4fc。

这个值，是指向我们的buffer区域的！

如果我们在buffer区域填满执行system的地址，并且将ecx最后一位覆盖为0，esp就有可能恰巧指向正确的system地址，从而执行ret，返回到我们想要的地方！

如何将ecx最低位覆盖为0呢？只要填满上图canary与ecx之前的空隙，因为gets()函数自动会将输入的字符串尾部写为\x00.

这样 我们就控制程序执行流了。但是 这一切是在知道canary的前提下进行的。

来测试一下上面的想法。

我迅速写了一个c程序，内容跟上面的程序类似，只不过每次运行它都会打印出Canary的值。

它的漏洞利用脚本如下。

```python
#!/usr/bin/env python
# -*- coding=utf8 -*-
"""
# Author: le3d1ng
# Created Time : 2019年04月04日 星期四 19时10分52秒
# File Name: exp.py
# Description:
"""
from pwn import *

io = process('./play2final')

context.log_level = 'debug'

io.recvuntil(' ?  ')
canary = int(io.recv()[0:10],16) # get canary

target = 0x08048592 # call system

payload = p32(target)*16+p32(canary) + "AAAA" #+ p32(target) + p32(target)# + "AAAA"
io.sendline(payload)

io.recv()
io.recv()
```

经过几次测试，是可以成功执行system的。（成功率大概50% ? XD）

## 总结

主要发挥作用其实还是Canary保护机制。若考虑爆破的成分，如果此程序运行在远程服务器上，比如一个pwn题。那么基本上是不可能完成的。

获取返回地址通过ecx寄存器进行，是gcc4.9之后的新特性，StackOverflow会破坏esp。同样的代码编译成64bit，无论开没开启Canary，结尾都只是简单的通过leave;ret实现的返回。

第一次写这么长的文章，可能会有很多描述不正确的地方。欢迎各位给我纠错。

但这个探索的过程很有趣。
