---
layout: post
title:  "2020.03.19 修改firmadyne修复模拟崩溃"
tags: [iot]
date: 2020-03-19
comments: false
---

# 如何魔改firmadyne来修复模拟崩溃



## 一、问题

用过firmadyne的大家都知道，对于某些固件，firmadyne并不能获取到正确网络接口，甚至不能正常启动qemu虚拟机。导致这种后果原因可能有很多种，其中一种是调用某些nvram函数不成功，导致某些init程序崩溃，无法正常初始化网卡等设备。

NVRAM:非易失性随机访问存储器 (Non-Volatile Random Access Memory)，是指断电后仍能保持数据的一种RAM。在嵌入式系统领域内，可以直接理解成板子上的FLASH芯片，里面保存着代码数据，用户配置数据等，如UBOOT,kernel,rootfs,user data。数据多以key/value形式储存。


## 二、解决方案

对于nvram函数导致的问题，最有效的解决方法还是分析crash log，根据需要的参数自行修改libnvram源码并且重新编译。

firmadyne自带了修改过的libnvram.so，并且会在makeimage阶段设置劫持固件原本的libnvram.so。它可以根据key令nvram_get等函数返回用户事先定义好的key/value中的value，若key未定义，则返回null。

它的源码位于`firmadyne/sources/libnvram/` 

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyieu4zwpj30vo03uaah.jpg)

`nvram.c`文件定义了要劫持的库函数等。

`alias.c`文件定义了一些函数的别名。

`config.h`定义的是要初始化的所有key/value。

下图为config.h代码，可以看到默认情况下，firmadyne作者已经在其中增加了对很多型号设备的适配：

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyi4lbhdzj31as0r6dms.jpg)

所以我们解决问题的方法就是修改上述文件，向config.h中添加我们需要的key/value，并且重新编译libnvram.so。



## 三、举个例子



路由器型号:DIR-2640-US

下载地址:https://support.dlink.com/productinfo.aspx?m=DIR-2640-US

固件版本:Firmware (1.01B04)

更新日期:02/07/20

---



### 1.获得固件

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyioty7w2j31rb0u0agc.jpg)

固件本身是经过加密的，不过加密方式是跟其他较新的路由器相同，所以也可以用其他路由器中的`bin/imgdecrypt`来解密。

`qemu-mipsel -L . ./bin/imgdecrypt DIR2640A1_FW101B04.bin`

`mv /tmp/.firmware.orig /path/DIR2640A1_FW101B04_decrypted.bin`

之后`binwalk -Me DIR2640A1_FW101B04_decrypted.bin`可以分离出fs

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyitrmlp1j31bg06kq46.jpg)



### 2.尝试模拟

我这里安装的是2020年的firmware-analysis-toolkit,链接:https://github.com/attify/firmware-analysis-toolkit

执行`./fat.py DIR2640A1_FW101B04_decrypted.bin`

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyj09cii1j31by0osadk.jpg)

### 3.定位crash

片刻后，喜闻乐见的Network interfaces为空。此时不要按回车开始模拟固件，先查看在获取网络配置阶段产生的log，位于`firmadyne/scratch/ID/qemu.initial.serial.log`，这里ID为2。

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyj5gsk4hj31890u0gtk.jpg)

可以看到nvram_daemon崩溃,ra和epc地址并不像在程序text段，更像是在lib中。

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyj8gc4ljj30og0lkq5d.jpg)

用ghidra分析一波`bin/nvram_daemon`先，重点关注nvram相关函数。其中`nvram_safe_set()`在alias.h和nvram.h中都没有被定义，后面需要我们手动添加到alias.h。

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyjb9mvrsj30ea0e4gmw.jpg)

先看最基础的nvram_get , nvram_set函数xref:

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyjgjxbk9j30l606gta0.jpg)

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyjg4cp8xj30pm062abv.jpg)

随便定位到两处可以大概判断出函数原型

```c
char *nvram_get(int idx , const char *key);

int nvram_set(int idx , const char *key , const char *value);
```





接着看看主函数:

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyjk4dzr9j30r210k7b0.jpg)

FUN_00403038():

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyjpvcuuwj30u00vqjwv.jpg)

WRSConfigGet()是一个库函数，定义在`lib/libwrscfg.so`，它实际上是调用`libnvram.so`中的`nvram_safe_get`来获取内容。

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyjrx6ajij30xm0ledj9.jpg)

在`nvram.c`中定义了`nvram_safe_get`这个函数，所以它会被劫持。

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyjxwfqgej30oe05udg8.jpg)

正如前面提到的，在`config.h`中并没有我们事先定义的`factory_mode`这个key，所以`WRSConfigGet("factory_mode")`返回值为空字符串.

因此函数最终会执行到`TW_LoadDefaultConfig()`，这是一个定义在`lib/librcm.so`中的库函数，它的作用是清空设备，重新把各项参数的默认值加载到nvram等设备中去:

![](https://tva1.sinaimg.cn/large/00831rSTly1gcyk5ufp7pj30vf0u0gra.jpg)

`loadDefault(0xb2c)`:

![](https://tva1.sinaimg.cn/large/00831rSTly1gcz9h7dr6lj30hq074t9o.jpg)

分析`bin/rallink_init`:

![](https://tva1.sinaimg.cn/large/00831rSTly1gcz9ic5ia5j30y00c4wgl.jpg)

`nvram_clear()`也是固件原本libnvram.so中的库函数，但是firmadyne并没有劫持这个函数，所以会导致崩溃。 

### 4.尝试修复

因此一个解决方法是让FUN_00403038()不能执行到`TW_LoadDefaultConfig()`，也就是需要修改`config.h`设置factory_mode的value不为空且不为1。并且添加原本需要设置默认值的key/value。

![](https://tva1.sinaimg.cn/large/00831rSTly1gczakuwpeoj30rm07k756.jpg)

同时注意到firmadyne中定义的nvram_get和nvram_set函数原型跟上述两函数原型并不同:

这是固件中的函数原型

```c
char *nvram_get(int idx , const char *key);
int nvram_set(int idx , const char *key , const char *value);
```

这是firmadyne中定义的函数原型

```c
char *nvram_get(const char *key);
int nvram_set(const char *key, const char *val);
```

因此需要修改firmadyne中libnvram源码中的函数使其传参与固件相同，并且向alias.c中添加`nvram_safe_set()`。

由于c语言不支持重载，用内联汇编的方式也不能很好的解决(firmadyne本身就尝试使用这种方式，效果不是很好)。这里选择大部分重写，在nvram_get和nvram_set两个函数里都增加一个idx参数，暂时无作用。

![](https://tva1.sinaimg.cn/large/00831rSTly1gczedu8dv5j30ti07ojsq.jpg)

![](https://tva1.sinaimg.cn/large/00831rSTly1gczeggtj1yj313u02q74o.jpg)

并且把`nvram.c`，`alias.c`中所有调用，定位到这两个函数的地方全部修改，下图是几个例子。

![](https://tva1.sinaimg.cn/large/00831rSTly1gczekkmj80j31520homyy.jpg)

![](https://tva1.sinaimg.cn/large/00831rSTly1gczen0dsboj30o805mmxc.jpg)

![](https://tva1.sinaimg.cn/large/00831rSTly1gczeowirjmj31am08stat.jpg)

向alias.c中添加`nvram_safe_set()`

```c
int nvram_safe_set(const char *key, const char *val) {
    return nvram_set(1,key, val);
}
```

全部修改完后我们就可以重新编译，替换`firmadyne/binaries/libnvram.so.mipsel`。

这里需要重新交叉编译，可以自建toolchain(https://github.com/firmadyne/firmadyne#compiling-from-source)

或者直接下载firmadyne提供的toolchains:https://cmu.app.boxcn.net/s/hnpvf1n72uccnhyfe307rc2nb9rfxmjp

下载后解压出`mipsel-linux-musl.tar.xz`，将解压后的内容放到某个文件夹.

![](https://tva1.sinaimg.cn/large/00831rSTly1gczey9nko5j311008ogmk.jpg)

在`firmadyne/sources/libnvram`下执行

```bash
make clean && CC=/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-gcc make
mv libnvram.so ../../binaries/libnvram.so.mipsel
```

即可。



接着重新尝试模拟，不出意外上一次的crash不会出现，但还是会在其他地方crash，因为还没有添加出厂默认参数。

查看log，ra=00402090

![](https://tva1.sinaimg.cn/large/00831rSTly1gczk4ov0ibj314m0u0wn4.jpg)

0x402090:

![](https://tva1.sinaimg.cn/large/00831rSTly1gczk5esvytj30pk066myj.jpg)

![](https://tva1.sinaimg.cn/large/00831rSTly1gczk5s6rlnj30mw05s0tq.jpg)

未设置BssidNum的value，导致atoi参数为Null，函数报错导致crash，确实是有些key没有设置好。

重新看到`TW_LoadDefaultConfig()`:

![](https://tva1.sinaimg.cn/large/00831rSTly1gczkk7uuvcj30be032jrs.jpg)

![](https://tva1.sinaimg.cn/large/00831rSTly1gczkkib60mj30v60u046w.jpg)

分别调用了三个文件，文件的内容都是key=value的形式，将其中的内容全部加入到`config.h`，记得删除`factory_mode=1`的键值对。

这里写了个简单的脚本来转换:

```python
#!/usr/bin/env python3
from sys import argv

try:
    f = open(argv[1],"r")
except:
    print("Usage: ./genconfig.py filename")
    exit()
f2 = open("result.txt","a")
for line in f.readlines():
    if not line.startswith("#") and "=" in line:
        if line.endswith("\n"):
            line = line[:-1]
        line = line.replace("\"","\\\"")
        d = line.split("=")
        f2.write("ENTRY(\""+d[0]+"\", nvram_set , \""+d[1]+"\") \\\n")

f.close()
f2.close()
```



![](https://tva1.sinaimg.cn/large/00831rSTly1gczkq6pux0j30xq0u0ahk.jpg)

多次尝试，还会有几次崩溃，到崩溃的地点确定key值，在`config.h`中一一设置，直到没有crash即可，此时应该也可以看到成功获取到网络接口信息。

![](https://tva1.sinaimg.cn/large/00831rSTly1gczl7zgoraj314c0p2q6e.jpg)

到此为止启动过程中crash，无法获得网络接口的问题应该是被解决。

### 5.更多

但启动后又发现有其他问题:

`EXT2-fs error (device sda1): ext2_lookup: deleted inode referenced: 41076`

![](https://tva1.sinaimg.cn/large/00831rSTly1gczlanlhi6j31ec0u0jze.jpg)

经过一些排查，发现是qemu启动时使用image的问题，firmadyne整个过程会两次使用同一个image来启动qemu虚拟机，第一次用来获取网络接口。第二次是根据网络接口，添加与主机通信的网卡然后最终启动。

第一次获取完网络接口后，未按正确方式退出，而且firmadyne也没有将image复原，第二次使用的image是第一次修改过的，会导致某些固件的image在第二次mount时出现问题。

解决方法也很简单，在获取网络接口之前创建一个image的备份，获取结束后恢复image。

修改`firmadyne/scripts/run.mipsel.sh`:

![](https://tva1.sinaimg.cn/large/00831rSTly1gczllrk1wwj30nq09sdgv.jpg)

修改`firmadyne/scripts/inferNetwork.sh`:

![](https://tva1.sinaimg.cn/large/00831rSTly1gczln6csguj30tc0a4q3x.jpg)

再次尝试，错误不再出现，使用`admin/twsz@2018`可以登录shell

![](https://tva1.sinaimg.cn/large/00831rSTly1gczlyscnfnj31bg0iyacs.jpg)

![](https://tva1.sinaimg.cn/large/00831rSTly1gczmd7p4lnj319t0u0aoq.jpg)





