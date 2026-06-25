---
layout: post
title: "Isolate me from sandbox - Explore elevation of privilege of CNG Key Isolation"
date: 2023-09-01 19:18:04 +0800
permalink: "/post/Isolate me from sandbox - Explore elevation of privilege of CNG Key Isolation/"
---

### Isolate me from sandbox - Explore elevation of privilege of CNG Key Isolation
---
### Author: k0shl of Cyber Kunlun

## Summary

In recently months, Microsoft patched vulnerabilities I reported in CNG Key Isolation service, assigned CVE-2023-28229 and CVE-2023-36906, the CVE-2023-28229 included 6 use after free vulenrabilities with similar root cause and the CVE-2023-36906 is a out of bound read information disclosure. Microsoft marked them as "Exploitation Less Likely" in assessment status, but actually, I completed the exploitation with these two vulnerabilities.

As an annual update blogger(sorry for that:P), I share this blogpost to introduce my exploitation on CNG Key Isolation service, so let's start our journey!

## Simple Overview

CNG Key Isolation is a service under lsass process which provides key process isolation to private keys, the CNG Key Isolation is worked as a RPC server that could be accessed with the Appcontainer Integrity process such as the render process in adobe or firefox. There are some important objects in keyiso service, let's go through them simply as following:

1. Context object. Context object is just like the manage object of keyiso RPC server, it will hold the provider object when the client invoke open storage provider to create a new provider object and it is managed by a global list named SrvCryptContextList. This object must be intialized first.

2. Provider object. Client should open an existed provider in a collection of all of the providers, if the provider open succeed, it will allocate the provider object and store the pointer into the context object. 

3. Key object. Key object is managed by context object, it will be allocated and inserted into the context object.

4. Memory Buffer object. Memory Buffer object is managed by context object, it will be allocate and inserted into the context object.

5. Secret object. Secret object is managed by context object, it will be allocate and inserted into the context object.

In these four objects, provider object/key object/secret object have similar object structure, offset 0x0 of the object stores the magic value, 0x44444446 means provider object, 0x44444447 means key object, 0x44444449 means secret object, when these objects freed, the magic value will be set to another value, offset 0x8 of the object stores the reference count, and offset 0x30 of the object stores the index of the object, this index is just like the handle of the object, it will be a flag when client use it to search the specified object which means the object is predictable, it is begin at 0 and when a new object allocated, it will add 1. 

***There is additional information to talk about how I win the race with the handle of object***, when I review the code, I noticed that the handle could be predictable, let's check the SrvAddKeyToList function:

```C++
SrvAddKeyToList:
  handlevalue = ++*(_QWORD *)(context_object + 0xA0); // =====> [a]
  *(_QWORD *)(key_object + 0x30) = handlevalue; // =====> [b]

SrvFreeKey:
  if ( *((_QWORD *)key_object + 6) == handlevalue ) // ====> [c]
      break;
```

The handle value is stored in the offset 0xA0 of context object, and in fact, the handle value is just like a index value, the initilized value is 0, and when a new key object is allocated, the index will add 1 [a] and be set to the offset 0x30 of new key object [b]. When the key object is freed, it will compare the handle value, if it matched [c], it will continue to hit vulnerable code. So the handle value could be predictable, for example, you could call SrvFreeKey with the handle value is 1 when you create the first key, or you could call the SrvFreeKey with the handle value is 10 when you create the No.10 key object, so that the key object could be retrieved in FreeKey function when adding key to context object with the new handle value.

I make the following simple chart to show you the relationship between theses objects.

![1.PNG](https://whereisk0shl.top/20230831/1.png)

## Root cause of CVE-2023-28229

In this section, I will introduce the root cause of CVE-2023-28299, I will use the key object as example, actually the rest of objects have similar issue.

When I do researching on keyiso service, I find out that each object has their own allocate and free interface, such as key object, there are the allocate RPC interface named s_SrvRpcCryptCreatePersistedKey and the free RPC interface named s_SrvRpcCryptFreeKey. And I quickly notice that there is an issue between object allocate and free.

```C++
__int64 __fastcall SrvCryptCreatePersistedKey(
        struct _RTL_CRITICAL_SECTION *a1,
        __int64 a2,
        _QWORD *a3,
        __int64 a4,
        __int64 a5,
        int a6,
        int a7)
{
[...]
    keyobject = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, 0x38ui64);
[...]
    *((_DWORD *)keyobject + 1) = 0;
    *(_DWORD *)keyobject = 0x44444447;
    *((_DWORD *)keyobject + 2) = 1; // ==========> [a]
    *((_QWORD *)keyobject + 4) = v12;
    SrvAddKeyToList((__int64)a1, (__int64)keyobject); // =============> [b]
    v11 = 0;
    *a3 = *((_QWORD *)keyobject + 6);
    return v11;
[...]
}

__int64 __fastcall SrvCryptFreeKey(__int64 a1, __int64 a2, __int64 a3)
{
[...]
  if ( _InterlockedExchangeAdd(freebuffer + 2, 0xFFFFFFFF) == 1 ) // ============> [c]
  {
    v17 = SrvFreeKey((PVOID)freebuffer); // ===============> [d]
    if ( v17 < 0 )
      DebugTraceError(
        (unsigned int)v17,
        "Status",
        "onecore\\ds\\security\\cryptoapi\\ncrypt\\iso\\service\\srvutils.c",
        700i64);
  }
  if ( _InterlockedExchangeAdd(freebuffer + 2, 0xFFFFFFFF) == 1 ) // ===============> [e]
  {
    v12 = (*(__int64 (__fastcall **)(_QWORD, _QWORD))(*((_QWORD *)freebuffer + 4) + 0x80i64))( // ==============> [f]
            *(_QWORD *)(*((_QWORD *)freebuffer + 4) + 0x118i64),
            *((_QWORD *)freebuffer + 5));
    v13 = v12;
[...]
}
```

When the client invoke allocate RPC interface, keyiso will allocate a heap from proccess heap and intialize the structure, it will set the reference count of key object to 1 first [a], then it will add the key object to context object, and add the reference count [b], and when client free the key object, keyiso will check if the reference is 1 [c], if it is, keyiso will free the key object [d], but it still use the key object after free [e], then it will call the function in vftable.

There aren't lock function when the reference count of key object is initialized to 1 and added, which means there is a time window between the intialization and addition, the key object will be freed [c] [d] after the reference count is set to 1 [a], and it could pass the next check [e] when reference count add 1 [b], finally, it will cause the use after free when the function of vftable called[f]. 

I wrote the PoC and figured out that it may be exploitable, but as the code show below, the function of vftable is picked from the pointer stored in offset 0x20 of the keyobject which means even I could control the free buffer, I still need a validate address in the offset 0x20 of the key object. I need a information disclosure.

## Root Cause of CVE-2023-36906

Then I try to find out a information disclosure, I go through the RPC interface and find out there is a property structure which is stored in provider object, and the property could be query and set with the RPC interface SPCryptSetProviderProperty and SPCryptGetProviderProperty.

```C++
__int64 __fastcall SPCryptSetProviderProperty(__int64 a1, const wchar_t *a2, _DWORD *a3, unsigned int a4, int a5)
{
[...]
    if ( !wcscmp_0(a2, L"Use Context") )
    {
      v15 = *(void **)(v8 + 32);
      if ( v15 )
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, v15);
      Heap = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, v6);
      *(_QWORD *)(v8 + 32) = Heap;
      if ( !Heap )
      {
        v10 = 1450i64;
LABEL_21:
        v9 = -2146893810;
        v11 = 2148073486i64;
        goto LABEL_42;
      }
      v17 = Heap;
      goto LABEL_40;
      }
      memcpy_0(v17, a3, v6); // ============> [b]
    } 
[...]
}

__int64 __fastcall SPCryptGetProviderProperty(
        __int64 a1,
        const wchar_t *a2,
        _DWORD *a3,
        unsigned int a4,
        unsigned int *a5,
        int a6)
{
[...]
    if ( !wcscmp_0(a2, L"Use Context") )
    {
      v17 = *(_QWORD *)(v10 + 32);
      v15 = 21;
      if ( !v17 )
        goto LABEL_31;
      do
        ++v13;
      while ( *(_WORD *)(v17 + 2 * v13) ); // =============> [c]
      v16 = 2 * v13 + 2;
      if ( 2 * (_DWORD)v13 == -2 )
      {
LABEL_31:
        v11 = 517i64;
LABEL_32:
        v9 = -2146893807;
        v12 = 2148073489i64;
        goto LABEL_57;
      }
      v25 = *(const void **)(v10 + 32);
      memcpy_0(a3, v25, v16); // ============> [d]
    } 
[...]
}
```

The client could specific which property to set, if the property named "Use Context", it will allocate a new buffer with the size which could be controlled by client, and store the "Use Context" buffer into the provider object, but when I review the query code, I notice that the "Use Context" should be a string type, it will go through the buffer in a while loop and break when it meets the null charactor [c], then return the whole buffer to client.

There will be a out of bound read when I set the "Use Context" property with a non-zero content in buffer, and actually, this property is a good object for exploitation because the size and content of the buffer could be controlled by client.

## Exploitation stage

Now, I have a out of bound read which could leak the content of adjacent object and a use after free elevation privilege could call arbitrary address if I could control the free buffer. I think it's time for me to chain the vulnerability.

I look back to the free buffer to find out what I need first:

```C++
v12 = (*(__int64 (__fastcall **)(_QWORD, _QWORD))(*((_QWORD *)freebuffer + 4) + 0x80i64))( 
            *(_QWORD *)(*((_QWORD *)freebuffer + 4) + 0x118i64),
            *((_QWORD *)freebuffer + 5));
```

If I could control the freebuffer, and I have a useful address, I could set this address to the offset 0x20 of freebuffer, and there are two important address in the validate address, the offset 0x80 of the address should be a validate function address, and the offset 0x118 should be another buffer. 

The lsass process enable the XFG mitigation, so I couldn't use ROP in this exploitation, but if I could control the first parameter of the function, I could use LoadLibraryW to load a controlled dll path, so the target is set offset 0x80 of validate address to LoadlibraryW address and set the payload dll to the address which stored in offset 0x118 of the address.

As I introduce in the previous section, the property "Use Context" is a good primitive object because I could control the size and whole content of this property, and I have a out of bound read issue, so the question is what object should be adjacent to my property object?

I review all objects of keyiso, and find out the memory buffer may be a useful target.

```C++
    v7 = SrvLookupAndReferenceProvider(hContext, hProvider, 0);
    [...]
    _InterlockedIncrement((volatile signed __int32 *)(v7 + 8));
    *(_QWORD *)Heap = v7; // ===========> [a]
    *((_QWORD *)Heap + 1) = v32;
    SrvAddMemoryBufferToList((__int64)hContext, (__int64)Heap);
    v26 = *((_QWORD *)Heap + 4);
    Heap = 0i64;
    *v15 = v26;
```

When the memory buffer created, keyiso will look up the provider object and store the provider object in the offset 0x0 of the memory buffer[a], so if I fill up property object with non-zero value and when I query the property object, it will leak the provider object address.

And of course, different objects have different size, I don't need to worry about the different object influence the layout when I do heap fengshui.

Finally, I figure out the exploitation scenario as following:

1. Spray the provider object and memory buffer object. Provider object is for the finaly stage of explointation, and memory buffer is for leak the provider object.

![2.PNG](https://whereisk0shl.top/20230831/2.png)

2. Free some memory buffer objects to make a heap hole, then allocate property with the same size of memory buffer object, it will occupy one of the freed holes, and then query the property to get the provider object address.

![3.PNG](https://whereisk0shl.top/20230831/3.png)

3. Free enough provider objects to make sure the leaked provider object is freed, and spray the properties with the same size of provider object to occupy the leaked provider object address. The LoadlibraryW address and payload dll should be stored in the offset 0x80 and offset 0x118 in the fake provider object. But I only have one leaked address, I could set the payload dll path in another offset in property buffer, and set the address in the offset 0x118 of property buffer.

![4.PNG](https://whereisk0shl.top/20230831/4.png)

4. Finally, I could trigger use after free with mutiple three diffrent threads, Thread A is for allocating the key object, Thread B is for releasing the key object, Thread C is for allocating the property object with the same size of key object, and set the fake reference count and leaked property address in offset 0x20 of property buffer.

![5.PNG](https://whereisk0shl.top/20230831/5.png)

When client win the race which means the property object occupy the key object hole after key object freed at SrvFreeKey function, it will finally load arbitrary dll in lsass process which finally cause appcontainer sandbox escape.

## Patch

Microsoft patch with adding the lock functions between the key object intialized and freed.

Before:
```C++
[...]
  RtlLeaveCriticalSection(v5);
  if ( _InterlockedExchangeAdd(freebuffer + 2, 0xFFFFFFFF) == 1 )
  {
    v17 = SrvFreeKey((PVOID)freebuffer);
    if ( v17 < 0 )
      DebugTraceError(
        (unsigned int)v17,
        "Status",
        "onecore\\ds\\security\\cryptoapi\\ncrypt\\iso\\service\\srvutils.c",
        700i64);
  }
  if ( _InterlockedExchangeAdd(freebuffer + 2, 0xFFFFFFFF) == 1 )
  {
    v12 = (*(__int64 (__fastcall **)(_QWORD, _QWORD))(*((_QWORD *)freebuffer + 4) + 0x80i64))(
            *(_QWORD *)(*((_QWORD *)freebuffer + 4) + 0x118i64),
            *((_QWORD *)freebuffer + 5));
[...]
```

After:
```C++
[...]
    RtlEnterCriticalSection(v8);
    v12 = *((_QWORD *)v9 + 2);
    if ( *(volatile signed __int64 **)(v12 + 8) != v9 + 2
      || (v13 = (volatile signed __int64 **)*((_QWORD *)v9 + 3), *v13 != v9 + 2) )
    {
      __fastfail(3u);
    }
    *v13 = (volatile signed __int64 *)v12;
    *(_QWORD *)(v12 + 8) = v13;
    if ( _InterlockedExchangeAdd64(v9 + 1, 0xFFFFFFFFFFFFFFFFui64) == 1 )
    {
      v14 = SrvFreeKey(v9);
      if ( v14 < 0 )
        DebugTraceError(
          (unsigned int)v14,
          "Status",
          "onecore\\ds\\security\\cryptoapi\\ncrypt\\iso\\service\\srvutils.c",
          705i64);
    }
    RtlLeaveCriticalSection(v8);
    if ( _InterlockedExchangeAdd64(v9 + 1, 0xFFFFFFFFFFFFFFFFui64) == 1 )
    {
      v15 = (*(__int64 (__fastcall **)(_QWORD, _QWORD))(*((_QWORD *)v9 + 4) + 128i64))(
              *(_QWORD *)(*((_QWORD *)v9 + 4) + 280i64),
              *((_QWORD *)v9 + 5));
[...]
```

Thanks for discussing with @chompie1337, @DannyOdler and @cplearns2h4ck. Actually even after patch, there should be UAF after SrvFreeKey get called, because SrvFreeKey function must free the key object but there still be a reference after the function returned, but the function seems never could be called, this is weird code that I don't know why Microsoft designed it like this, but after they add lock function between key object is intialized and freed, the UAF race condition got fixed.
