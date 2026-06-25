---
layout: post
title: "A simple story of DsSvc, \"Live and Die\""
date: 2020-02-10 21:24:29 +0800
permalink: "/post/a-simple-story-of-DsSvc/"
---

Author: k0shl of 360 Vulcan Team

### Overview

DsSvc is a data sharing service that provides data sharing between processes. I have not conducted an in-depth analysis of the specific functions of this service. It is known that it provides some methods of file sharing between processes. As shown in the following figure, the process specifies a shared file through DsSvc, and calls CoCreateGuid to create a GUID as a file token, and stores information such as its token and file path into DbTable. Other processes can obtain file objects through this token and perform other files operating.

![1.PNG](https://whereisk0shl.top/20191122/1.PNG)

Data sharing services contain many file operations, which also bring a lot of security issues. Microsoft spent nearly a year to fix the logical issue in this service. The security issue caused by file operations is one of the types of logical vulnerability. Important partitions, it's necessary to be careful when dealing with files' operation, especially for file security attributes. I will analyze the logical vulnerabilities in DsSvc, as well as Microsoft's patch, and bypass. Let's start our story.

### The Beginning of story...

In November 2018, Microsoft patched a [data sharing service vulnerability](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8584) discovered by [SandboxEscaper](https://twitter.com/SandboxBear) (PolarBear). SandboxEscaper shared details about this vulnerability on the blog. Since this article on the SandboxEscaper's blog is inaccessible, it is not possible to reference the SandboxEscaper blog address. A description of vulnerability is as follows:

```
Bug description:
RpcDSSMoveFromSharedFile(handle,L"token",L"c:\\blah1\\pci.sys");
This function exposed over alpc, has a arbitrary delete vuln. 
Hitting the timing was pretty annoying. But my PoC will keep rerunning until c:\windows\system32\drivers\pci.sys is deleted.
I believe it’s impossible to hit the timing on a single core VM. I was able to trigger it using 4 cores on my VM. (Sadly I wasn’t able to use OPLOCKS with this particular bug)
Root cause is basically just a delete without impersonation because of an early revert to self. Should be straight forward to fix it… 
Exploitation wise.. you either try to trigger dll hijacking issues in  3rd party software.. or delete temp files used by a system service in c:\windows\temp and hijack them and hopefully do some evil stuff.
```

This is an arbitrary file deletion vulnerability. The vulnerability occurs in the RPC interface RpcDSSMoveFromSharedFile. The issue existed in function PolicyChecker::CheckFilePermission. The code is as follows:

```
__int64 __fastcall PolicyChecker::CheckFilePermission(const WCHAR *FileName, unsigned int a2, unsigned int a3, int a4, __int64 a5)
{
  [...CreateFile flag check...]
  [...Impersonate...]
  v12 = CreateFileW(v5, dwDesiredAccess, dwShareMode, 0i64, 4u, 0x80u, 0i64);
  [...RevertToSelf...]
  if ( v12 == (void *)-1i64 )
  {
    [...]
  }
  else
  {
    v17 = v14;
    if ( !a5 || (v8 = DSUtils::GetFinalPathFromHandle(v12, a5), (v8 & 0x80000000) == 0) )
    {
      CloseHandle(v12);//Close
      v12 = (void *)-1i64;
      if ( v17 )
        return v8;
      DeleteFileW(v5);//arbitrary file deletion
    }
    if ( v13 != (void *)-1i64 )
      CloseHandle(v13);
  }
  return v8;
}
```

In this function, FileName is defined by the user. First, the parameters DesiredAccess and ShareMode will be checked. Then RpcImpersonateClient will be called to impersonate client and call CreateFile to open the file. DsSvc will delete the file after RevertToSelf.

Although DsSvc calls ImpersonateClient to open the file, which means that when I try to open a limit file, it will fail and return, but there is still have TOCTOU issue. Before calling CeateFile, you can create a junction to the user-controllable path, so CreateFile will succeed. After that, you can change the junction to a limit directory. It will invoke DeleteFile to delete limit file finally.

In the patch, Microsoft no longer uses DeleteFile but uses the FileDispositionInfo class of SetFileInformationByHandle to delete file. Thus, calling SetFileInformationByHandle refers to the file handle created by CreateFile instead of the file path. The final deletion is a normal file opened after ImpersonateClient.

```
else
  {
    v17 = v14;
    if ( !a5 || (v8 = DSUtils::GetFinalPathFromHandle(v13, a5), v8 >= 0) )
    {
      if ( !v17 )
      {
        FileInformation = 1;
        if ( !SetFileInformationByHandle(v13, FileDispositionInfo, &FileInformation, 1u) )
        {
          [...]
        }
      }
    }
    CloseHandle(v13);
```


### My research has started...

After this vulnerability was exposed, I started my study on the logic vulnerability. One day, when I was chatting with my friend 0x9k, he talked about the complete full chain of 11 Android logical vulnerabilities used by MWRLab in Pwn2Own. Then I read [MWRLab's slide](https://labs.f-secure.com/assets/BlogFiles/G.-Geshev-and-Rob-Miller-Chainspotting.pdf) about this full chain exploitation which they talked on CanSecWest. 

There is a show in this slide about the tool jandroid that they use when finding android logic vulnerabilities.

![2.PNG](https://whereisk0shl.top/20191122/2.PNG)

After read about jandroid in slide, I came up with the idea that such this method can be used to finding logical vulnerabilities on Windows? The answer is yes. 

I think I can assist the subsequent reverse engineering by parsing the path travesal of the sensitive operation on the RPC-related dll. I took some time to implement my idea. (Later in August 2019 [Adam Chester](https://twitter.com/_xpn_) published a blog post about his [RPC parsing implementation idea](https://blog.xpnsec.com/analysing-rpc-with-ghidra-neo4j/))

I used [James Forshaw's](https://twitter.com/tiraniddo) project [NtApiDotNet](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/master/NtApiDotNet) when writing the parsing code. It can complete pre-working in my parsing framework, there is a class called NdrProcedureDefinition in NtApiDotNet, which plays a key role in RPC interface parsing, it can parse out of the RPC interface of the DCE syntax, I made a few modifications to the NdrProcedureDefinition part of the method, so that it can parse the RPC interface of the Ndr64 syntax, which may resolve more potential attack surfaces in the x64 system. (The figure below shows the analysis result of Chakra.dll which use Ndr64 syntax)

![3.PNG](https://whereisk0shl.top/20191122/3.PNG)


Here are two points to mention. 
[+] The first is that almost all RPC dlls in Windows x64 systems use DCE syntax, but also contain a very small number of RPC dlls for Ndr64 syntax, such as Chakra.dll.
[+] And the second is that I am not find the way to parsing incoming parameter of RPC interface of Ndr64 syntax, so I can only parse the RPC interface function without parameters, but this does not affect sensitive operation path travesal parsing.


The following picture shows the logs of some of the path travesals after I run my parsing code. Actually, I found out some interesting path travesals in DsSvc after that time, but James Forshaw report most of them :).

![4.PNG](https://whereisk0shl.top/20191122/4.PNG)

### Get down to business

In January 2019, Microsoft patched [5 DsSvc EoP Vulnerabilities](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0574) reported by James Forshaw , there is a interesting patch in these 5 vulnerabilities which about the [MoveFileInheritSecurity function](https://bugs.chromium.org/p/project-zero/issues/detail?id=1681), the vulnerability code is as follows:

```
__int64 __fastcall PolicyChecker::MoveFileInheritSecurity(const WCHAR *lpNewFileName, const WCHAR *lpExistingFileName)
{
  [...]
  if ( MoveFileExW(lpNewFileName, lpExistingFileName, 3u) )
  {
    if ( !InitializeAcl(&pAcl, 8u, 2u) )
    {
LABEL_4:
      v6 = GetLastError();
      goto LABEL_10;
    }
    v6 = SetNamedSecurityInfoW(lpExistingFileName, SE_FILE_OBJECT, 0x20000004u, 0i64, 0i64, &pAcl, 0i64);
    if ( v6 )
      MoveFileExW(lpExistingFileName, lpNewFileName, 3u);
  }
  [...]
}
```

As the code show, DsSvc will set the DACL of the new file through SetNamedSecurityInfoW after the MoveFile. James forshaw create a hardlink to a limit file, and call RpcDSSMoveFromSharedFile interface, the DsSvc get the file path directly, but not check if the file is accessible, it will finally set the limit file's DACL.

Before patch:
```
__int64 __fastcall DSUtils::VerifyPathRoundTrip(wchar_t *Str2, wchar_t *a2)
{
  [...]
    v3 = CreateFileW(Str2, 0x80000000, 7u, 0i64, 4u, 0x80u, 0i64);
  if ( v3 != (HANDLE)-1i64 )
  {
    v2 = v3;
LABEL_6:
    v5 = DSUtils::VerifyPathFromHandle(v1, v2);
    goto LABEL_7;
  }
  [...]
}
```

After patch：
```
__int64 __fastcall DSUtils::VerifyPathRoundTrip(wchar_t *Str2, wchar_t *a2)
{
  [...]
  v5 = CreateFileW(Str2, 0x80000000, 7u, 0i64, 4u, 0x80u, 0i64);
  if ( v5 != (HANDLE)-1i64 )
  {
    v4 = v5;
LABEL_6:
    v7 = DSUtils::VerifyPathFromHandle(v3, v4);
    if ( v7 >= 0 )
      v7 = DSUtils::VerifyFileIdFromHandle(v2, v4);
    goto LABEL_8;
  }
  [...]
}
```

After patch, function DSUtils::VerifyFileIdFromHandle is added. The function contains a check for the hardlink. The BY_HANDLE_FILE_INFORMATION structure returned by calling the GetFileInformationByHandle function contains the member variable nNumberOfLinks. If it is greater than 1, it indicates that there is a symbolic link, and function will fail and return.

```
__int64 __fastcall DSUtils::GetFileIdFromHandle(HANDLE hFile, __int64 a2)
{
  [...]
  if ( GetFileInformationByHandle(v3, &FileInformation) )
    goto LABEL_19;
  [...]
LABEL_19:
  if ( FileInformation.nNumberOfLinks <= 1 )
  {
    v11 = (_WORD *)*v2;
    v2[1] = *v2;
    *v11 = 0;
  }
  [...]
}
```

### The story is far from ending...

Obviously, Microsoft's patch still have problem. I found that there is still a time window between the end of the check of the symbolic link and the call to the MoveFileInheritSecurity function, which means that there is a TOCTOU vulnerability, I can make a hardlink to limit file after the symbolink check, so that when DsSvc calls the MoveFileInheritSecurity function, it will set the limit file's DACL finally. I later reported this vulnerability to Microsoft.

[Microsoft's patch](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1383) is very simple, they canceled RpcDSSMoveFromSharedFile and RpcDSSMoveToSharedFile two RPC interfaces of DsSvc in Windows 10 rs6 and later. 

```
///After parse DsSvc RPC interface you can find out that 
///RpcDSSMoveFromSharedFile and RpcDSSMoveToSharedFile are canceled

[uuid("bf4dc912-e52f-4904-8ebe-9317c1bdd497"), version(1.0)]
interface intf_bf4dc912_e52f_4904_8ebe_9317c1bdd497 {
    HRESULT RpcDSSCreateSharedFileToken( handle_t p0,  [In] wchar_t[1]* p1,  [In] struct Struct_0* p2,  [In] /* ENUM16 */ int p3,  [In] /* ENUM16 */ int p4,  [Out] wchar_t** p5);
    HRESULT RpcDSSGetSharedFileName( handle_t p0,  [In] wchar_t[1]* p1,  [Out] wchar_t** p2);
    HRESULT RpcDSSGetSharingTokenInformation( handle_t p0,  [In] wchar_t[1]* p1,  [Out] wchar_t** p2,  [Out] wchar_t** p3,  [Out] /* ENUM16 */ int* p4);
    HRESULT RpcDSSDelegateSharingToken( handle_t p0,  [In] wchar_t[1]* p1,  [In] struct Struct_1* p2);
    HRESULT RpcDSSRemoveSharingToken( handle_t p0,  [In] wchar_t[1]* p1);
    HRESULT RpcDSSOpenSharedFile( handle_t p0,  [In] wchar_t[1]* p1,  [In] int p2,  [Out] long* p3);
    HRESULT RpcDSSCopyFromSharedFile( handle_t p0,  [In] wchar_t[1]* p1,  [In] wchar_t[1]* p2);
    HRESULT RpcDSSRemoveExpiredTokens();
}
```

The old version still exists these two interfaces. In the old version, Microsoft's patch is also very simple. The PolicyChecker::MoveFileInheritSecurity function is directly deleted, and DsSvc use another method for file copy. I will share this method later.

### Other attack surfaces

In my RPC parsing log, I noticed another RPC interface, DSSCopyFromSharedFile, which calls the CopyFile function to copy file to a controllable path.

```
__int64 __fastcall DSSCopyFromSharedFile(const unsigned __int16 *a1, wchar_t *a2)
{
  [...Check File...]
  if ( !CopyFileW(*(LPCWSTR *)(v10 + 184), v4, 0) )
  {
    [...]
  }
  [...]
}
```

This vulnerability is very obvious, although DsSvc checked the permissions of the copied target file before CopyFile, I can still use race condition to link the file to the limit file after checking the target file permissions, and finally copy the shared file to limit file. In this function, the shared file can be specified by the user, so it is easy to write the payload into the file under system32.

When I reported this vulnerability, Microsoft did not award bounty for the vulnerability because Microsoft introduced a [mitigation for hardlink](https://whereisk0shl.top/post/2019-06-08). Whether normal user have control permission for the target file, if not, the hard link cannot be created, that is, the hardlink cannot be used by normal user in rs6 and WIP.

### DsSvc security feature bypass

After receiving the reply from Microsoft, I made a quick review on the DsSvc service code again and found a very interesting place. In DsSvc, it will protect the folder where the target file is to be operated. Create a lock file to prevent this folder from being mounted to another directory. The function that implements this security feature is DSUtils::DirectoryLock::Lock. The function code is as follows:

```
__int64 __fastcall DSUtils::DirectoryLock::Lock(signed __int64 this, const unsigned __int16 *a2)
{
  [...]
  v20 = CreateFileW(v19, 0x80000000, 7u, 0i64, 4u, 0x4000100u, 0i64);
  [...]
}
```

The function calls CreateFile to create the lock file. I found that the lock file inherits the security descriptor of the parent directory, so actually, I have full control on lock file. It means I can delete the lock file after the lock file is created and after that I mount the directory to limit directory(the directory will be empty after I delete file). This way, even if I don't use hardlink, I can finally call CopyFile to copy the payload to a limit file in the limit directory.

### The story is still going on

Microsoft finally patched [vulnerability I report](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1272). In CopyFromSharedFile, Microsoft use a new function DSUtils::CopyFileWithProgress with the following code:

```
__int64 __fastcall DSUtils::CopyFileWithProgress(BOOL *this, DSUtils *a2, DSUtils *a3, const unsigned __int16 *a4)
{
   DSUtils::OpenFile((const WCHAR *)a2, (const unsigned __int16 *)0x80000000i64, 7u, 0, &hObject);
   v7 = DSUtils::OpenFile((const WCHAR *)a3, (const unsigned __int16 *)0x80000000i64, 3u, 0, &pbCancel);
   [...]
   DSUtils::IsHardLinkFile(pbCancel, &vars0);
   [...]
   v8 = DSUtils::GetFinalPathFromHandle(v7, (__int64)&lpData);
   if ( v8 >= 0
        && !CopyFileExW(
           (LPCWSTR)a2,
           (LPCWSTR)a3,
           (LPPROGRESS_ROUTINE)CopyFileProgressRoutine,
           lpData,
           (LPBOOL)dwCopyFlags,
           0) )
   [...]     
}
```

In the patch, Microsoft not only checks whether the file is hardlink, but also uses CopyFileExW function. This function calls a callback function CopyFileProgressRoutine when copying the file. The callback function will check if the target file path is the same as before the IsHardLinkFile check.

```
signed __int64 __fastcall CopyFileProgressRoutine(LARGE_INTEGER TotalFileSize, LARGE_INTEGER TotalBytesTransferred, LARGE_INTEGER StreamSize, LARGE_INTEGER StreamBytesTransferred, DWORD dwStreamNumber, DWORD dwCallbackReason, HANDLE hSourceFile, HANDLE hDestinationFile, LPVOID lpData)
{
  [...]
  v9 = DSUtils::GetFinalPathFromHandle(hDestinationFile, (__int64)&Str2);
    if ( v9 >= 0 && _wcsicmp((const wchar_t *)lpData, Str2) )
  [...]
}
```

### Is it really over?

After I analyze Microsoft's patch, I sent an email to Microsoft to confirm whether they fixed the problem I reported later, that is, the problem about lock file created. At that time, my suggestion was to create a lock file that can not be controlled by normal users. This way the user cannot delete the lock file and mount the current directory to another directory. Microsoft confirmed that it had fixed the previous problem, but they may did not understand my suggestion.

Although Microsoft added multiple checks, it can be found that Microsoft has finished checking the target file when it calls DSUtils::OpenFile to open the file and the callback function CopyFileProgressRoutine compares the file path before and after, so there is a very obvious issue:

If I still have full control over the lock file, I can still bypass the check in another way, James Forshaw's [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) introduce a method, this way it mounts the directory to the root directory of the namespace, and then links the named object to other files. This method will cause the file path to be resolved to other file when NT parsing the file path. Instead of setting the symbolic link through the SetFileInformation method, the advantage of this method is that the target file parsed when calling GetFileInformationByHandle is the target file, so the member variable nNumberOfLinks is still 1, you can easily bypass the IsHardlinkFile check.

Therefore, you can link file to other file in this way before OpenFile. After OpenFile, including the GetFinalPathNameByHandle in the callback function, they all will be parsed to the same path. Therefore, the patch is finally bypassed, and the payload file can still be copied to the limit file by CopyFile.

### last of the last...

Microsoft released [a new patch in November 2019](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1417). Finally, Microsoft deleted the DirectoryLock function and the MoveFileInheritSecurity function I mentioned earlier, and used a new method DSUtils::OpenFileAlways to open the file and return the file handle which will be used in DSUtils::CopyFileWithProgress, it will opened until the function return. So, when the file is opened, the file no longer can be deleted and the mount point can not be created to other directory. Before CopyFile, the file directory to be copied is parsed by the GetFileInformationByHandle function.

```
///Instead of file path, DsSvc use file handle as incoming parameter

DSUtils::CopyFileWithProgress(v5, (const unsigned __int16 *)hObject, hFile, (void *)v19);
{
  [...]
  DSUtils::GetFinalPathFromHandle(hObject, (__int64)lpExistingFileName);
  [...]
  DSUtils::GetFinalPathFromHandle(hFile, (__int64)lpNewFileName);
  [...]
  DSUtils::IsHardLinkFile(hFile, dwCopyFlags, v8);
  [...]
  else if ( !CopyFileExW(
                     lpExistingFileName[0],
                     lpNewFileName[0],
                     CopyFileProgressRoutine,
                     v4,
                     (LPBOOL)&dwCopyFlags[1],
                     0) )
  [...]
}
```

And also, DsSvc uses ImpersonateClient to make sure the target file is an accessible file.

```
 v6 = AutoImpersonate<1>::ImpersonateClient(&v39);
 [...]
 v6 = DSUtils::OpenFileAlways(lpFileName, Str, (unsigned __int64)&hFile);
 [...]
 if ( (_DWORD)v39 )
   RpcRevertToSelf();
```

Similarly, Microsoft has rewritten the CopyFileProgressRoutine callback function. In the function, DsSvc will compare the source file and target file with the FilePath and the FileID.

```
signed __int64 __fastcall CopyFileProgressRoutine(LARGE_INTEGER TotalFileSize, LARGE_INTEGER TotalBytesTransferred, LARGE_INTEGER StreamSize, LARGE_INTEGER StreamBytesTransferred, __int64 dwStreamNumber, __int64 dwCallbackReason)
{
 [...]
 v7 = DSUtils::GetFileIdFromHandle(hFile);
 [...]
 v7 = DSUtils::GetFileIdFromHandle((HANDLE)dwStreamNumber);
 [...]
 v7 = DSUtils::GetFinalPathFromHandle(hFile, (__int64)&v33);
 [...]
 v7 = DSUtils::GetFinalPathFromHandle((HANDLE)dwStreamNumber, (__int64)&v36);
 [...]
 if ( (unsigned int)utl::basic_string<unsigned short,utl::char_traits<unsigned short>,utl::allocator<unsigned short>>::compare(
                             dwCallbackReason,
                             &v27) )
 [...]
 if ( (unsigned int)utl::basic_string<unsigned short,utl::char_traits<unsigned short>,utl::allocator<unsigned short>>::compare(
                             dwCallbackReason + 64,
                             &v30) )
 [...]
 if ( (unsigned int)utl::basic_string<unsigned short,utl::char_traits<unsigned short>,utl::allocator<unsigned short>>::compare(
                             dwCallbackReason + 32,
                             &v33) )
 [...]
 if ( (unsigned int)utl::basic_string<unsigned short,utl::char_traits<unsigned short>,utl::allocator<unsigned short>>::compare(
                             dwCallbackReason + 96,
                             &v36) )
 [...]
}
```

In the old version, MoveFromSharedFile and MoveToSharedFile also use CopyFileWithProgress to move files. The story about DsSvc ends here.
