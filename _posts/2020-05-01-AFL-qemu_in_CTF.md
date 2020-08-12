---
layout: post
title:  "2020.5.1 AFL-QEMU in CTF"
tags: [fuzz, re, ctf]
date: 2020-05-01
comments: true
---
# AFL-QEMU in CTF


## AFL-QEMU

通过修改qemu部分源码，实现fuzz闭源程序

### QEMU 块翻译

QEMU实现了在宿主机(host)上运行非宿主机(target)架构的程序

其实现方法是在两种架构之间添加了一个TCG(Tiny Code Generator)。

1.`TCG前端`将target架构的指令转换为一种架构无关的指令，称之为中间表示(IR intermediate representation)

2.`TCG后端`将IR指令转换为host架构的指令

上述这种翻译的单位是基本块(BB)。翻译是在模拟基本块(BB)的同时进行的，翻译后的翻译块(TB)会被存到缓存中，如果相应BB后续再次被执行到，会直接从缓存中取出TB执行。  



AFL修改了QEMU的部分源码

AFL实现了一个forkserver，用来fork产生子进程进行fuzz，且在forkserver上监听子进程发来的一些数据

子进程正常执行，在每个TB执行时记录路径。在遇到未翻译的BB时，会进行翻译，并将相关信息(pc csbase)发送给forkserver，forkserver检查这个BB在forkserver的缓存中是否存在，如果不存在，则将它翻译并放到缓存中，这样后面fork出的子进程就会拥有这个缓存。  



当然AFL这种做法并不是最优的，它为了保证记录路径的完整性，禁用了qemu的chain功能，增加了资源的消耗。

已经有人对AFL-qemu进行优化，在保留chain功能的前提下提升AFL效率，这一点后面再说。



## 思路

我们考虑一种情形，假设CTF中一个re题目，要求输入一串字符，将输入进行处理，最终判断出是否正确，且这个处理过程是一个字节一个字节进行的。  


两种情况：

1.如果输入的第一个字符是正确的，那么会继续判断第二个字符

2.如果输入的第一个字符是错误的，那么不继续判断，进入其他逻辑

那么这两种情况执行到的基本块是不相同的，产生的执行路径是不相同的。  




所以，可以利用AFL-QEMU的覆盖率返回结果，找出能触发不同路径的payload，依次爆破出flag。

当然这种方法只能解决一小小小小部分题目。(



## 代码及实现效果

实现了手动和自动两个模式  


1.手动：

提供一个字符串(seed)，会在其后面追加一个字符，进行测试并且记录bitmap size。这样测试完所有可打印字符并且记录结果。

统计所有bitmap size，选出出现次数最多的bitmap size及所有对应的字符，将除了上面找到的字符的剩余字符高亮显示，以供下一轮输入。

2.自动：

从空字符串开始，查看所有执行情况的bitmap size，同样将非bitmap size出现次数最多的对应字符递归进行下一轮测试，直到所有测试bitmap size相同。

也可以提供flag长度，使用x填充flag。  




源码放在github了：https://github.com/leeeddin/AFLre  




效果

1.手动：

小例子测试一下

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    char inp[32];
    fgets(inp,31,stdin);
    if(inp[0]=='l'){
        if(inp[1]=='e'){
            if(inp[2]=='3'){
                if(inp[3]=='d'){
                    if(inp[4]=='1'){
                        if(inp[5]=='n'){
                            if(inp[6]=='g'){
                                puts("triggered.");
                                abort();
                            }
                        }
                    }
                }
            }
        }
    }
    puts(inp);
}

```



![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged104y8slj30sa0rudhe.jpg)

![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged10j7zhyj308u0o2jsb.jpg)



![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged10v5qpsj30di0smq4b.jpg)



![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged11u9qdrj30qq0akdgx.jpg)





2.自动：

例子https://github.com/bash-c/reverse_repo/tree/master/ASIS_Final_2019_cursed_app

![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged0vsyu5gj30zk0j4goc.jpg)

![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged0w4wtpjj30j205qjrw.jpg)

![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged0wolnnmj30g603gglt.jpg)

输出文件:

![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged0ulzfytj30u01c946z.jpg)

![](https://tva1.sinaimg.cn/large/007S8ZIlly1ged0v0hcpij30u012l48o.jpg)





## 灵感

来自

http://m4x.fun/post/perf-in-ctf/

http://m4x.fun/post/pin-in-ctf/