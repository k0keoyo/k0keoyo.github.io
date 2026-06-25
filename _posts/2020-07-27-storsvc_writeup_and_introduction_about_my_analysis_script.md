---
layout: post
title: "StorSvc writeup and introduction about my analysis script"
date: 2020-07-27 14:39:00 +0800
permalink: "/post/StorSvc_writeup_and_introduction_about_my_analysis_script/"
---

# StorSvc writeup and introduction about my analysis script
---

Author: k0shl of Qihoo 360 Vulcan Team

---
Today, I'd like to share two of my favorite logical escalation of priviledge vulnerabilities which I reported in 2019 -- CVE-2019-0983 and CVE-2019-0998 and a simple introduction about my RPC static analysis script, I public these [two PoCs](https://github.com/k0keoyo/my_vulnerabilities) and [my script](https://github.com/k0keoyo/ksRPC_analysis_script) in my github. All of them were found by reversing, actually, I don't know how to trigger it by normal user interactive and monite it with monitor such as procmon. I will share more detail about how I found it in this paper.

So let's begin our journey.

---
### StorSvc overview

StorSvc is windows storage service which provide service for storage setttings and extern extension storage. There were two interesting vulnerabilities about Storage Service in history, [CVE-2018-0983](https://bugs.chromium.org/p/project-zero/issues/detail?id=1428) which reported by James Forshaw, and [a blog](https://sandboxescaper.blogspot.com/)(SandboxEscaper deleted that paper) from SandboxEscaper. So I decided to look into this service.

According to James Forshaw and SandboxEscaper founding, they both focused on a RPC interface storsvc!SvcMoveFileInheritSecurity, and after patched, Microsoft seemed patched this logical vulnerability with "a simple way".

***After Patch***

```
signed __int64 SvcMoveFileInheritSecurity()
{
  return 0x80004001;
}
```

But this was not the only RPC interface in this service, after I reversed StorSvc.dll, I found two interesting points.

---
### StorSvc volume structure

Before I introduce about my CVEs, I'd like to talk about a interesting structure during reversing.

Almost every RPC interface reference this structure and check it.

such as:

```
          v6 = 0x450 * v5;
          v7 = *(_DWORD *)(0x450 * v5 + g_StorageService[v3 + 5] + 564);
          if ( !(v7 & 1)
            ....
         LODWORD(v4) = StringCchCopyW(&FileName, 0x104ui64, (const wchar_t *)(v6 + g_StorageService[v3 + 5] + 4));
              if ( (signed int)v4 >= 0 )
              {
                    .....
              }
```

As the code show,  variable v5 looks like a index, and there is a structure which size is 0x450, g_StorageService is a global variable which store these structures like a structures table. When I went into these RPC interfaces, it always be failure when service check this structure.

```
0:002> dc poi(0x7ffe5b683bb0+0x28)+0x450 l4
00000169`44831820  00000000 00000000 00000000 00000000  ................
```

The content of this structure always be zero. That's bad, so I tried to find why it failed and how to set the value.

After some code review, I noticed that this content can be set by mounting a extension volume.

Now I knew why this value always be zero, I tested it in VM, and there was only one origin volume C:\ in VM. After a little researched, there was a easy way to make it work, I could added a new disk in VM, such as E:\. And then, the content of structure is set, and I can got some variable in structure meaning, for example, the offset 0x4 in this structure was point to VolumeName, the offset 0x234 in this structure was point to volume state.

```
0:001> dc poi(0x7ffe5b683bb0+0x28)+0x450 l4
00000169`44831820  00000000 003a0045 0000005c 00000000  ....E.:.\.......
```

Now let  me introduce CVE-2019-0983 and CVE-2019-0998.
(***I used hardlink in these two CVEs, because Microsoft wasn't release hardlink mitigation at that time***)

---
### CVE-2019-0983

The vulnerability caused by a logical error in StorageService::ProvisionStorageCardForUser, error code like this:

```
__int64 __fastcall StorageService::ProvisionStorageCardForUser(__int64 a1, int a2, unsigned int a3, wchar_t *a4)
{
        v22 = StringCchPrintfW(&ExistingFileName, 0x104ui64, L"%s\\desktop.ini");
      v9 = 0;
      if ( v22 >= 0 )
      {
        v23 = StringCchPrintfW(&NewFileName, 0x104ui64, L"%s\\desktop.ini", v21);
        v9 = 0;
        if ( v23 >= 0 )
        {
          CopyFileW(&ExistingFileName, &NewFileName, 0);
          v9 = 0;
        }
      }
}
```

CVE-2019-0983 is easy to understand. ExistingFileName was "C:\User\k0shl\Video\desktop.ini", and NewFileName was "E:\User\k0shl\Video\desktop.ini",  these two files could be controlled by normal user. So I can create a hardlink to a high priviledge file. It will finally be occupied by my controlled file.

After patch:

```
    v15 = RpcImpersonateClient(0i64);
    if ( v15 < 0 )
      goto LABEL_44;
    v23 = (void **)&v39;
    if ( v41 >= 8 )
      v23 = v39;
    v24 = &v35;
    if ( (unsigned __int64)Dst >= 8 )
      v24 = (struct _SECURITY_ATTRIBUTES **)v35;
    if ( StringCchPrintfW(&ExistingFileName, 0x104ui64, L"%s\\desktop.ini", v24) >= 0
      && StringCchPrintfW(&NewFileName, 0x104ui64, L"%s\\desktop.ini", v23) >= 0 )
    {
      CopyFileW(&ExistingFileName, &NewFileName, 0);
    }
    RpcRevertToSelf();
```

It invokes RPCimpersonateClient() before CopyFileW().

---
### CVE-2019-0998

The vulnerability caused by a logical error in StorSvc!SvcSetStorageSettings, the error code in function StorageService::SetWriteAccess :

```
            v14 = GetUserFolder(&pObjectName);
            ...
             _wsplitpath_s(&pObjectName, 0i64, 0i64, 0i64, 0i64, &Filename, 0x104ui64, 0i64, 0i64);
             LODWORD(phkResult) = StringCchCopyW(
                                     &PathName,
                                     0x104ui64,
                                     (const wchar_t *)(*(_QWORD *)(v7 + 8i64 * (_QWORD)v6 + 40) + 1104 * v11 + 4));
              if ( (signed int)phkResult >= 0 )
              {
                LODWORD(phkResult) = PathCchAppend(&PathName, 260i64, &Filename);
            if ( !CreateDirectoryW(&PathName, &SecurityAttributes) )
            {
              v17 = GetLastError();
              if ( v17 == 183 )
              {
                v18 = SetNamedSecurityInfoW(
                        &PathName,
                        SE_FILE_OBJECT,
                        4u,
                        0i64,
                        0i64,
                        *(PACL *)&SecurityAttributes.nLength,
                        0i64);
```

First, service invoked GetUserFolder() to get a full folder path and _wsplitpath_() to split full path to its final name. For example, GetUserFolder() return a full path "C:\User\k0shl", and after _wsplitpath_(), I get FileName "k0shl".

And finally PathName will set to "E:\k0shl" and invoke CreateDirectory, service want to create a user folder in another volume, and if it create directory failed, it will get last error value, if value is 0xb7, it means file already exist. Service will invoke SetNamedSecurityInfoW to set it DACL, but it not check if PathName is a file or a directory. How about "E:\k0shl" is a file not a direcotry? If I create a file instead of directory in volume and make a symbolic link to a high priviledge file, it will finally modified high priviledge file's DACL.

After patch:

```
if ( CreateDirectoryW(&PathName, &SecurityAttributes) )
                    goto LABEL_107;
                  v17 = GetLastError();
                  if ( v17 == 183 )
                  {
                    if ( !(GetFileAttributesW(&PathName) & 0x10) )
                    {
                      LODWORD(phkResult) = -2147024891;
                      goto LABEL_92;
                    }
                    v18 = SetNamedSecurityInfoW(
                            &PathName,
                            SE_FILE_OBJECT,
                            4u,
                            0i64,
                            0i64,
                            (PACL)SecurityAttributes.lpSecurityDescriptor,
                            0i64);
```

After patch, it check the file's attribute to confirm it's a directory. Actually, I think there is still a TOCTOU, but after I test it, the time window is too small, I can't delete directory and make a symbol link between GetFileAttribute and SetNamedSecurityInfoW. Of course, I also can't use oplock, because GetFileAttribute() just query file object information.

#### Introduction about my analysis script

After I reported these two logical vulnerabilities, I thought about how I found these two vulnerabilities. First, I found some sensitive functions such as SetNamedSecurityInfo or CopyFile, and I get a code path from RPC interface.

As I said in [my another blog](https://whereisk0shl.top/post/a-simple-story-of-dssvc), I finally decide to write a script to help me analyze all RPC server.

I make a simple framework about script in my mind.

* Step 1: I need to get all RPC server
* Step 2: I need to get all RPC interfaces
* Step 3: I need to parse RPC dll or exe in IDA
* Step 4: I need to find a code path from RPC interface to sensitive function

Actually, all of this were easy to complete, I use [James Forshaw's awesome tool NtApiDotNet](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/master/NtApiDotNet), I can use this tool to help me to parse RPC server, there is a class named Win32 in NtApiDotNet, and a interesting method named ParsePeFile.

This function can parse RPC server and export RPC interfaces like RPCView, I just need the RPC interface name.

```
 public static IEnumerable<RpcServer> ParsePeFile(string file, string dbghelp_path, string symbol_path, bool parse_clients, bool ignore_symbols)
        {
            List<RpcServer> servers = new List<RpcServer>();
            using (var result = SafeLoadLibraryHandle.LoadLibrary(file, LoadLibraryFlags.DontResolveDllReferences, false))
            {
                if (!result.IsSuccess)
                {
                    return servers.AsReadOnly();
                }

                var lib = result.Result;
                var sections = lib.GetImageSections();
                var offsets = sections.SelectMany(s => FindRpcServerInterfaces(s, parse_clients));
                if (offsets.Any())
                {
                    using (var sym_resolver = !ignore_symbols ? SymbolResolver.Create(NtProcess.Current,
                            dbghelp_path, symbol_path) : null)
                    {
                        foreach (var offset in offsets)
                        {
                            IMemoryReader reader = new CurrentProcessMemoryReader(sections.Select(s => Tuple.Create(s.Data.DangerousGetHandle().ToInt64(), (int)s.Data.ByteLength)));
                            NdrParser parser = new NdrParser(reader, NtProcess.Current,
                                sym_resolver, NdrParserFlags.IgnoreUserMarshal);
                            IntPtr ifspec = lib.DangerousGetHandle() + (int)offset.Offset;
                            var rpc = parser.ReadFromRpcServerInterface(ifspec);
                            servers.Add(new RpcServer(rpc, parser.ComplexTypes, file, offset.Offset, offset.Client));
                        }
                    }
                }
            }

            return servers.AsReadOnly();
        }
```

And in IDA, I can used IDAPython to parse code path with xrefs, and I also found that there maybe path explosion in analyze python script, so I set a recursion depth to 10 and 7, if the function call count is larger than recursion depth, it will return diffrent result, of course you can change it. Now I collected all I need for this script now.

In my script(about script config please check it in my github):

* I go through all exe and dll file under C:\Windows\System32(***Actually, this not include all RPC servers, there are some other RPC servers in other directory or suffix diffrent from "dll" or "exe" such as Windows Defender or unimdm.tsp, you can config the search path in my script***)
* I use Win32.RPC.ParsePeFile to parse every file, if it's a RPC server, it will return code like IDL
* I create a file store sensitive functions and use a IDAPython script to parse RPC dll or exe
* I get all the code path to sensitive functions, and if it start from RPC interface which get from the result by Win32.RPC.ParseFile, I store it in SpecialFinal.txt

The result like:

```
SvcSetStorageSettings[////////__imp_SetNamedSecurityInfoW<--?CreateStorageCardDirectory@StorageService@@IEAAJW4_STORAGE_DEVICE_TYPE@@KPEBGKPEAU_SECURITY_ATTRIBUTES@@PEAU_ACL@@H@Z<--?ProvisionStorageCardForUser@StorageService@@IEAAJW4_STORAGE_DEVICE_TYPE@@KPEAG1KPEAU_SECURITY_ATTRIBUTES@@PEAU_ACL@@@Z<--?SetWriteAccess@StorageService@@IEAAJW4_STORAGE_DEVICE_TYPE@@KK@Z<--?SetStorageSettings@StorageService@@QEAAJW4_STORAGE_DEVICE_TYPE@@KW4_STORAGE_SETTING@@K@Z<--SvcSetStorageSettings]

SvcSetStorageSettings[////////__imp_CopyFileW<--?ProvisionStorageCardForUser@StorageService@@IEAAJW4_STORAGE_DEVICE_TYPE@@KPEAG1KPEAU_SECURITY_ATTRIBUTES@@PEAU_ACL@@@Z<--?SetWriteAccess@StorageService@@IEAAJW4_STORAGE_DEVICE_TYPE@@KK@Z<--?SetStorageSettings@StorageService@@QEAAJW4_STORAGE_DEVICE_TYPE@@KW4_STORAGE_SETTING@@K@Z<--SvcSetStorageSettings]
```

#### Time Line
***Feb 2019 :***  Vulnerabilities Reported
***Feb 2019 :***  Microsoft reproduced
***May 2019 :*** Patch released
***May 2019 :*** Bounty awarded

#### Reference

https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0983

https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0983

https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0998

https://github.com/k0keoyo/ksRPC_analysis_script

https://github.com/k0keoyo/my_vulnerabilities/tree/master/CVE-2019-0983

https://github.com/k0keoyo/my_vulnerabilities/tree/master/CVE-2019-0998
