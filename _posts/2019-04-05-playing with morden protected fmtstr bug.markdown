---
layout: post
title:  "2019.4.5 playing with morden protected fmtstr bug"
tags: [pwn, linux, formatstring, morden]
date: 2019-04-05
comments: true
---

# 从一道CTF题目看linux全保护机制下的格式化字符串漏洞。

代码如下:

```c
/*************************************************************************
 @Author: le3d1ng
 @Created Time : 2019年04月05日 星期五 17时15分07秒
 @File Name: newplayme.c
 @Description:
 ************************************************************************/
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);

  if(target != 0) {
        system("cat flag");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

来源为protostar，我做了一点改变。

在ubuntu16.04下编译，并打开所有保护机制。同时机器也开启了ASLR。

```bash
gcc -z now -pie -fPIC newplayme.c -o newplayme
```

![5ca72a8dc93fc](https://i.loli.net/2019/04/05/5ca72a8dc93fc.png)

只看一下代码，发现目标是改变target这个变量的值。

我们知道，格式化字符串漏洞，输入存储在栈上，只要有参数偏移，目标地址，就可以做到任意地址写。

从这个角度来看，似乎很简单。



但是，注意target这个变量并不是一个全局变量，它是存储在栈上的。

![5ca72ba830bbd](https://i.loli.net/2019/04/05/5ca72ba830bbd.png)

受aslr的影响，每次运行程序，栈的基址都会有略微的不同。因此target的存放位置也就每次都不相同。

为了观察这一点，我们可以修改一下源代码，让它打印出target的地址。

![5ca72d003fcb0](https://i.loli.net/2019/04/05/5ca72d003fcb0.png)

他们都由0x7ff开始，由0xc结束。

但这看起来很糟糕，我们不能得到target的准确地址，也就没法准确的写值了。



有没有一种可能恰好猜到它的地址呢？



让我们仔细程序运行后栈的样子。

![5ca72fc9ee1a0](https://i.loli.net/2019/04/05/5ca72fc9ee1a0.png)

![5ca72ea677eab](https://i.loli.net/2019/04/05/5ca72ea677eab.png)

右上方的0x414141414114141是传入的A*8，buffer也就是从这里开始的。



实际上栈上此时有两处地方存储着"AAAAAAAA",一处便是上图位置，另一处为存储环境变量的位置，在栈的很底部。

原因是使用了sprintf这个函数。



同时buffer的上方存着target。



通过观察，发现栈上存着很多与target类似的地址，它们的前4个bytes均相同。



或许我们可以借助栈上已有的地址，恰巧伪造出正确的target地址，从而修改target值。

可以知道，target地址最低一个1/2byte都为0xc，因此我们可以溢出它的最低byte为0x?c。逗号很适合。

![5ca733248ec08](https://i.loli.net/2019/04/05/5ca733248ec08.png)



我们选择0x7fffffffe368+8处的地址。



先看一下我们需要填充多少个字节让buffer达到它的位置。

8 + 9*8 = 80



接着看一下它在printf参数位置的偏移大小。这里我们只需要找AAAAAAAA的偏移，然后加10即可。

![5ca734be6286e](https://i.loli.net/2019/04/05/5ca734be6286e.png)

可以看到 AAAAAAAA 位置的偏移为9，目标跳板位置的偏移为19.



因此我们先填充80个字符，再添加一个逗号(0x2c)将跳板的最低byte覆盖为0x2c，如果幸运的话，这个跳板的位置恰好是target的位置。接着我们使用%19$n给其指向位置赋值，便成功修改掉了target的值。



payload: %80lx,%19$ln



多次运行，发现flag被打印出来了。

![5ca736739b54d](https://i.loli.net/2019/04/05/5ca736739b54d.png)



# 总结



hitcon training中的playfmt与此题有几分相似，都是通过跳板间接修改数据。




