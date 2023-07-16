# Summary
In this blog, we will be continue into looking more into the field inside PEB using a debugger. Also we will analyse and walk over PEB and understand how the NTDLL file is loaded into the process memeory.

If you want to read the previous part click **[here](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md)**

# Index
1. **[ProcessHeap](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%202.md#processheap)**
2. **[FastPebLock](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%202.md#fastpeblock)**
3. **[KernelCallbackTable](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%202.md#kernelcallbacktable)**
4. **[Walking the PEB](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%202.md#walking-the-peb)**
5. **[Walking the PEB with C++](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%202.md#walking-the-peb-with-c)**
6. **[Resources](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%202.md#resources)**

You can open any process for this, but I'm selecting **notepad.exe**

# ProcessHeap
The ```ProcessHeap``` field in the Process Environment Block (PEB) structure is a pointer to the process heap. 
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/65d46066-a985-4241-a642-adf64ef74fcc)

In 64-bit environments, the ProcessHeap is located at the offset of 0x30. It uses the **_HEAP** structure. Let's take a look at it.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/4f98239e-5d57-4131-91e5-a118fcd56a1a)

```
0:006> dt _PEB ProcessHeap @$peb
ntdll!_PEB
   +0x030 ProcessHeap : 0x000002c8`274e0000 Void
```
```
0:006> dt _HEAP 0x000002c8274e0000
ntdll!_HEAP
   +0x000 Segment          : _HEAP_SEGMENT
   +0x000 Entry            : _HEAP_ENTRY
   +0x010 SegmentSignature : 0xffeeffee
   +0x014 SegmentFlags     : 2
   +0x018 SegmentListEntry : _LIST_ENTRY [ 0x000002c8`274e0120 - 0x000002c8`274e0120 ]
   +0x028 Heap             : 0x000002c8`274e0000 _HEAP
   +0x030 BaseAddress      : 0x000002c8`274e0000 Void
   +0x038 NumberOfPages    : 0xff
   +0x040 FirstEntry       : 0x000002c8`274e0740 _HEAP_ENTRY
   +0x048 LastValidEntry   : 0x000002c8`275df000 _HEAP_ENTRY
   +0x050 NumberOfUnCommittedPages : 0x8b
   +0x054 NumberOfUnCommittedRanges : 1
   +0x058 SegmentAllocatorBackTraceIndex : 0
   +0x05a Reserved         : 0
   +0x060 UCRSegmentList   : _LIST_ENTRY [ 0x000002c8`27553fe0 - 0x000002c8`27553fe0 ]
   +0x070 Flags            : 2
   +0x074 ForceFlags       : 0
   +0x078 CompatibilityFlags : 0
   +0x07c EncodeFlagMask   : 0x100000
   +0x080 Encoding         : _HEAP_ENTRY
   +0x090 Interceptor      : 0
   +0x094 VirtualMemoryThreshold : 0xff00
   +0x098 Signature        : 0xeeffeeff
   +0x0a0 SegmentReserve   : 0x100000
   +0x0a8 SegmentCommit    : 0x2000
   +0x0b0 DeCommitFreeBlockThreshold : 0x400
   +0x0b8 DeCommitTotalFreeThreshold : 0x1000
   +0x0c0 TotalFreeSize    : 0x257
   +0x0c8 MaximumAllocationSize : 0x00007fff`fffdefff
   +0x0d0 ProcessHeapsListIndex : 1
   +0x0d2 HeaderValidateLength : 0x2c0
   +0x0d8 HeaderValidateCopy : (null) 
   +0x0e0 NextAvailableTagIndex : 0
   +0x0e2 MaximumTagIndex  : 0
   +0x0e8 TagEntries       : (null) 
   +0x0f0 UCRList          : _LIST_ENTRY [ 0x000002c8`27553fd0 - 0x000002c8`27553fd0 ]
   +0x100 AlignRound       : 0x1f
   +0x108 AlignMask        : 0xffffffff`fffffff0
   +0x110 VirtualAllocdBlocks : _LIST_ENTRY [ 0x000002c8`274e0110 - 0x000002c8`274e0110 ]
   +0x120 SegmentList      : _LIST_ENTRY [ 0x000002c8`274e0018 - 0x000002c8`274e0018 ]
   +0x130 AllocatorBackTraceIndex : 0
   +0x134 NonDedicatedListLength : 0
   +0x138 BlocksIndex      : 0x000002c8`274e02e8 Void
   +0x140 UCRIndex         : (null) 
   +0x148 PseudoTagEntries : (null) 
   +0x150 FreeLists        : _LIST_ENTRY [ 0x000002c8`27524a10 - 0x000002c8`275521d0 ]
   +0x160 LockVariable     : 0x000002c8`274e02c0 _HEAP_LOCK
   +0x168 CommitRoutine    : 0x0f65525e`88e4e94d     long  +f65525e88e4e94d
   +0x170 StackTraceInitVar : _RTL_RUN_ONCE
   +0x178 CommitLimitData  : _RTL_HEAP_MEMORY_LIMIT_DATA
   +0x198 FrontEndHeap     : 0x000002c8`27440000 Void
   +0x1a0 FrontHeapLockCount : 0
   +0x1a2 FrontEndHeapType : 0x2 ''
   +0x1a3 RequestedFrontEndHeapType : 0x2 ''
   +0x1a8 FrontEndHeapUsageData : 0x000002c8`274e67f0  ""
   +0x1b0 FrontEndHeapMaximumIndex : 0x402
   +0x1b2 FrontEndHeapStatusBitmap : [129]  "???"
   +0x238 Counters         : _HEAP_COUNTERS
   +0x2b0 TuningParameters : _HEAP_TUNING_PARAMETERS
```
It has large no of fields and it is worth mentioning that the **_HEAP** structure is mostly undocumented. Using the **GetProcessHeap()** API we can get the handle of the heap
```CPP
HANDLE GetProcessHeap();
```
In Windows, the process heap is managed by the Heap Manager, which is part of the Memory Manager. The Heap Manager provides a set of functions for allocating, freeing, and managing memory on the process heap. Here are some important Windows API functions related to the process heap.

**[HeapCreate()](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate)** - This function creates a new heap object for the calling process. The function takes several parameters, including the initial size of the heap, the maximum size of the heap, and flags that control the behavior of the heap.
```CPP
HANDLE HeapCreate(
  [in] DWORD  flOptions,
  [in] SIZE_T dwInitialSize,
  [in] SIZE_T dwMaximumSize
);
```

**[HeapAlloc()](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)** - This function allocates a block of memory from the process heap. The function takes two parameters - the handle to the heap to allocate from, and the size of the block to allocate.
```CPP
DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
  [in] HANDLE hHeap,
  [in] DWORD  dwFlags,
  [in] SIZE_T dwBytes
);
```

**[HeapFree()](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree)** - This function frees a block of memory that was previously allocated from the process heap. The function takes two parameters - the handle to the heap the block was allocated from, and a pointer to the block to free.
```CPP
BOOL HeapFree(
  [in] HANDLE                 hHeap,
  [in] DWORD                  dwFlags,
  [in] _Frees_ptr_opt_ LPVOID lpMem
);
```
[HeapReAlloc()](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc) - This function changes the size of a block of memory that was previously allocated from the process heap. The function takes three parameters - the handle to the heap the block was allocated from, a pointer to the block to resize, and the new size of the block.
```CPP
DECLSPEC_ALLOCATOR LPVOID HeapReAlloc(
  [in] HANDLE                 hHeap,
  [in] DWORD                  dwFlags,
  [in] _Frees_ptr_opt_ LPVOID lpMem,
  [in] SIZE_T                 dwBytes
);
```

# FastPEBLock
The **`FastPebLock`** field in the Process Environment Block (PEB) structure is a synchronization mechanism used to provide thread safety when accessing the PEB structure. It is a fast, lightweight lock that is used to ensure that only one thread can access or modify the PEB structure at a time.  
The purpose of the **`FastPebLock`** is to prevent data corruption or inconsistencies when multiple threads are simultaneously accessing or modifying the PEB structure. It helps to maintain the integrity of the data stored in the PEB and ensures that concurrent access to the structure is properly synchronized.  
The **`FastPebLock`** is implemented as a slim reader/writer lock. It allows multiple threads to simultaneously read the PEB structure, while ensuring that only one thread can hold a write lock to modify the structure at a time.  
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/778466a4-4efb-44a5-81e6-6d87ca34e396)  
The **`RtlAcquirePebLock()`** function is used to acquire the **`FastPebLock`** before accessing or modifying the PEB structure. This ensures that only one thread can access the PEB at a time, preventing data corruption or inconsistencies.
```CPP
RtlAcquirePebLock(VOID)
{
   PPEB Peb = NtCurrentPeb ();
   RtlEnterCriticalSection(Peb->FastPebLock);
}
```
The RtlReleasePebLock() function is used to release the FastPebLock after the necessary operations on the PEB structure have been performed.
```CPP
RtlReleasePebLock(VOID)
{
   PPEB Peb = NtCurrentPeb ();
   RtlLeaveCriticalSection(Peb->FastPebLock);
}
```

# KernelCallbackTable
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/7578faad-2be3-4b25-9c68-f58e3b2e315b)
The **`KernelCallbackTable`** field in the PEB structure is a pointer to an array of kernel-mode callback function pointers. Kernel-mode callbacks are a mechanism in Windows that allow registered drivers or kernel components to intercept and handle specific system events or operations.  
The array pointed to by **`KernelCallbackTable`** contains function pointers that correspond to different callback routines. These callback routines are called by the Windows kernel when certain events occur, such as process or thread creation, registry operations, file system operations, and more.  
The `KernelCallbackTable` can be found in the PEB and is initialized to an array of functions when user32.dll is loaded into a GUI process.  
Here is the struct of it.  
```CPP
typedef struct _KERNELCALLBACKTABLE_T {
  ULONG_PTR __fnCOPYDATA;
  ULONG_PTR __fnCOPYGLOBALDATA;
  ULONG_PTR __fnDWORD;
  ULONG_PTR __fnNCDESTROY;
  ULONG_PTR __fnDWORDOPTINLPMSG;
  ULONG_PTR __fnINOUTDRAG;
  ULONG_PTR __fnGETTEXTLENGTHS;
  ULONG_PTR __fnINCNTOUTSTRING;
  ULONG_PTR __fnPOUTLPINT;
  ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
  ULONG_PTR __fnINLPCREATESTRUCT;
  ULONG_PTR __fnINLPDELETEITEMSTRUCT;
  ULONG_PTR __fnINLPDRAWITEMSTRUCT;
  ULONG_PTR __fnPOPTINLPUINT;
  ULONG_PTR __fnPOPTINLPUINT2;
  ULONG_PTR __fnINLPMDICREATESTRUCT;
  ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
  ULONG_PTR __fnINLPWINDOWPOS;
  ULONG_PTR __fnINOUTLPPOINT5;
  ULONG_PTR __fnINOUTLPSCROLLINFO;
  ULONG_PTR __fnINOUTLPRECT;
  ULONG_PTR __fnINOUTNCCALCSIZE;
  ULONG_PTR __fnINOUTLPPOINT5_;
  ULONG_PTR __fnINPAINTCLIPBRD;
  ULONG_PTR __fnINSIZECLIPBRD;
  ULONG_PTR __fnINDESTROYCLIPBRD;
  ULONG_PTR __fnINSTRING;
  ULONG_PTR __fnINSTRINGNULL;
  ULONG_PTR __fnINDEVICECHANGE;
  ULONG_PTR __fnPOWERBROADCAST;
  ULONG_PTR __fnINLPUAHDRAWMENU;
  ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
  ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
  ULONG_PTR __fnOUTDWORDINDWORD;
  ULONG_PTR __fnOUTLPRECT;
  ULONG_PTR __fnOUTSTRING;
  ULONG_PTR __fnPOPTINLPUINT3;
  ULONG_PTR __fnPOUTLPINT2;
  ULONG_PTR __fnSENTDDEMSG;
  ULONG_PTR __fnINOUTSTYLECHANGE;
  ULONG_PTR __fnHkINDWORD;
  ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
  ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
  ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
  ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
  ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
  ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
  ULONG_PTR __fnHkINLPMSG;
  ULONG_PTR __fnHkINLPRECT;
  ULONG_PTR __fnHkOPTINLPEVENTMSG;
  ULONG_PTR __xxxClientCallDelegateThread;
  ULONG_PTR __ClientCallDummyCallback;
  ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
  ULONG_PTR __fnOUTLPCOMBOBOXINFO;
  ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
  ULONG_PTR __xxxClientCallDevCallbackCapture;
  ULONG_PTR __xxxClientCallDitThread;
  ULONG_PTR __xxxClientEnableMMCSS;
  ULONG_PTR __xxxClientUpdateDpi;
  ULONG_PTR __xxxClientExpandStringW;
  ULONG_PTR __ClientCopyDDEIn1;
  ULONG_PTR __ClientCopyDDEIn2;
  ULONG_PTR __ClientCopyDDEOut1;
  ULONG_PTR __ClientCopyDDEOut2;
  ULONG_PTR __ClientCopyImage;
  ULONG_PTR __ClientEventCallback;
  ULONG_PTR __ClientFindMnemChar;
  ULONG_PTR __ClientFreeDDEHandle;
  ULONG_PTR __ClientFreeLibrary;
  ULONG_PTR __ClientGetCharsetInfo;
  ULONG_PTR __ClientGetDDEFlags;
  ULONG_PTR __ClientGetDDEHookData;
  ULONG_PTR __ClientGetListboxString;
  ULONG_PTR __ClientGetMessageMPH;
  ULONG_PTR __ClientLoadImage;
  ULONG_PTR __ClientLoadLibrary;
  ULONG_PTR __ClientLoadMenu;
  ULONG_PTR __ClientLoadLocalT1Fonts;
  ULONG_PTR __ClientPSMTextOut;
  ULONG_PTR __ClientLpkDrawTextEx;
  ULONG_PTR __ClientExtTextOutW;
  ULONG_PTR __ClientGetTextExtentPointW;
  ULONG_PTR __ClientCharToWchar;
  ULONG_PTR __ClientAddFontResourceW;
  ULONG_PTR __ClientThreadSetup;
  ULONG_PTR __ClientDeliverUserApc;
  ULONG_PTR __ClientNoMemoryPopup;
  ULONG_PTR __ClientMonitorEnumProc;
  ULONG_PTR __ClientCallWinEventProc;
  ULONG_PTR __ClientWaitMessageExMPH;
  ULONG_PTR __ClientWOWGetProcModule;
  ULONG_PTR __ClientWOWTask16SchedNotify;
  ULONG_PTR __ClientImmLoadLayout;
  ULONG_PTR __ClientImmProcessKey;
  ULONG_PTR __fnIMECONTROL;
  ULONG_PTR __fnINWPARAMDBCSCHAR;
  ULONG_PTR __fnGETTEXTLENGTHS2;
  ULONG_PTR __fnINLPKDRAWSWITCHWND;
  ULONG_PTR __ClientLoadStringW;
  ULONG_PTR __ClientLoadOLE;
  ULONG_PTR __ClientRegisterDragDrop;
  ULONG_PTR __ClientRevokeDragDrop;
  ULONG_PTR __fnINOUTMENUGETOBJECT;
  ULONG_PTR __ClientPrinterThunk;
  ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
  ULONG_PTR __fnOUTLPSCROLLBARINFO;
  ULONG_PTR __fnINLPUAHDRAWMENU2;
  ULONG_PTR __fnINLPUAHDRAWMENUITEM;
  ULONG_PTR __fnINLPUAHDRAWMENU3;
  ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
  ULONG_PTR __fnINLPUAHDRAWMENU4;
  ULONG_PTR __fnOUTLPTITLEBARINFOEX;
  ULONG_PTR __fnTOUCH;
  ULONG_PTR __fnGESTURE;
  ULONG_PTR __fnPOPTINLPUINT4;
  ULONG_PTR __fnPOPTINLPUINT5;
  ULONG_PTR __xxxClientCallDefaultInputHandler;
  ULONG_PTR __fnEMPTY;
  ULONG_PTR __ClientRimDevCallback;
  ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
  ULONG_PTR __ClientCallLocalMouseHooks;
  ULONG_PTR __xxxClientBroadcastThemeChange;
  ULONG_PTR __xxxClientCallDevCallbackSimple;
  ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
  ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
  ULONG_PTR __fnGETWINDOWDATA;
  ULONG_PTR __fnINOUTSTYLECHANGE2;
  ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
} KERNELCALLBACKTABLE;
```
Command in WinDbg to display the struct.
```
0:006> dps 0x00007ffe24d01070
00007ffe`24d01070  00007ffe`24c92710 USER32!_fnCOPYDATA
00007ffe`24d01078  00007ffe`24cf9a00 USER32!_fnCOPYGLOBALDATA
00007ffe`24d01080  00007ffe`24c90b90 USER32!_fnDWORD
00007ffe`24d01088  00007ffe`24c969f0 USER32!_fnNCDESTROY
00007ffe`24d01090  00007ffe`24c9da60 USER32!_fnDWORDOPTINLPMSG
00007ffe`24d01098  00007ffe`24cfa230 USER32!_fnINOUTDRAG
00007ffe`24d010a0  00007ffe`24c97f20 USER32!_fnGETTEXTLENGTHS
00007ffe`24d010a8  00007ffe`24cf9ed0 USER32!_fnINCNTOUTSTRING
00007ffe`24d010b0  00007ffe`24cf9f90 USER32!_fnINCNTOUTSTRINGNULL
00007ffe`24d010b8  00007ffe`24c99690 USER32!_fnINLPCOMPAREITEMSTRUCT
00007ffe`24d010c0  00007ffe`24c92b70 USER32!__fnINLPCREATESTRUCT
00007ffe`24d010c8  00007ffe`24cfa050 USER32!_fnINLPDELETEITEMSTRUCT
00007ffe`24d010d0  00007ffe`24c9fdf0 USER32!__fnINLPDRAWITEMSTRUCT
00007ffe`24d010d8  00007ffe`24cfa0b0 USER32!_fnINLPHELPINFOSTRUCT
00007ffe`24d010e0  00007ffe`24cfa0b0 USER32!_fnINLPHELPINFOSTRUCT
00007ffe`24d010e8  00007ffe`24cfa1b0 USER32!_fnINLPMDICREATESTRUCT
```
It's been abused by malwares and threat actors like FinSpy and Lazarus group using a using a technique called Process Injection via KernelCallbackTable **[MITRE - T1574.013](https://attack.mitre.org/techniques/T1574/013/)**.

# Walking the PEB
In this demonstration, we will fetch the base address of the NTDLL file residing inside LDR data structure in PEB. Process will be notepad.exe. In order to underand more in details, I've explained it my previous part **PEB - Part1** LDR section **[here](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#ldr)**.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/fb333e72-5a9c-4504-9f14-cb143a635385)\
The LDR structure is at the offset **0x18** which is for 64-bit architecture. Here is the structure of PEB, you'll see the following.
```Cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  // ...
} PEB, *PPEB;
```
The first three entries ``Reserved1``, ``BeingDebugged`` and ``Reserved2`` take up 4 bytes on x86 and x64. After that, the offset calculation changes between 32-bit and 64-bit code.
In 32-bit code, pointers are 4-byte aligned. Thus, there is no padding between Reserved2 and Reserved3. With Reserved3's size being 8 bytes (2 4-byte pointers), the offset of Ldr evaluates to **2 * 1 + 1 + 1 * 1 + 0 + 2 * 4 (i.e. 12 or 0x0C)**.
In 64-bit code there are 2 differences: pointers are 8 bytes in size, and 8-byte aligned. The latter introduces padding between Reserved2 and Reserved3. The offset of Ldr thus evaluates to **2 * 1 + 1 + 1 * 1 + 4 + 2 * 8 (i.e. 24 or 0x18)**.
Better look at the table below

| Field | Offset(x86) | Offset(x64) |
| ------ | ---------- | ---------- |
| Reserved1 | 0 -> +2 | 0 -> +2 |
| BeingDebugged | 2 -> +1 | 2 -> +1 |
| Reserved2 | 3 -> +1 | 3 -> +1+4(padding) |
| Reserved3 | 4 -> +(2*4=8) | 8 -> +(2*8=16)  |
| Ldr | **12(0x0C)** | **24(0x18)** |

The next value of the address is added in each column to understand the offset flow.

Now navigating inside LDR structure.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/e3cc0855-30c3-4477-8068-7fd1d0b73b68)\
It has three important modules that are most important. If we take a look at anyone of them, we can see that it's(all three) a doubly-link with Flink(Forward) and Blink(Backward) like a standard doubly-linked list. If we navigate to FLINK address.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/8a5a5f43-f801-4aed-8b7e-304d6c4190e6)\
We can see the executable name and it's full path. Now checking the ``InInitializationmodulelist``  the link list.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/68a85d0e-9cf9-4af6-a615-ee2195047e5c)\
We got memory read error. Because it is a doubly link list we have to minus 20h cause the InInitializeOrderLinks is at offset 20. More like going 20 steps back to ``InLoadOrderLinks`` to get the base address of the NTDLL.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/4fd22437-dad9-4278-b3b9-f3742c3d70fc)\
Here we can see the base address of the NTDLL file. We can keep going backwards in link list to retrieve more DLL's address. In next section, we will write a code to do it for us.

# Walking the PEB with C++
Instead of manually doing all the offset calculation, we can write a C++ code that will do the heavy work for us. In this case, we will get the base address of all the DLL's base addresses. Before we move forward, we will take a visual representation of the whole PEB LDR structure representing with a diagram.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/5d5be64a-9b53-41e7-93ec-a78a5b24ef4f)

Now moving towards write the code. You can find the whole code **[here](https://github.com/Faran-17/Windows-Internals/blob/main/codes/Processes%20and%20Jobs/PEB_walker.cpp)**.\
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/95d7fa40-6630-412c-ba52-97ebf89172b8)\
Including all the necessary header files. Now rather than using the regular PEB structure as per MSDN **[here]([https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)** and LDR struture we can refined it's strucutre for our specific use (reference from **[here](http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html)**).
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/e73d373f-e914-4092-96de-fd6fc3de17cf)\
Continuing on to the main section.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/10a52a39-8511-4bd6-aa6b-e6b8995b37ff)\
Here is what we're doing.
1. Fetching the PEB address, using ``__readgsqword( 0x60 )`` for 64-bit architecture.
2. Fetching PEB_LDR_DATA Structure Address from the PEB.
3. Fetching the ``InLoadOrderModuleList``.
4. Then parsing it to the LDR_DATA_TABLE_ENTRY structure.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/96358357-84bf-494b-aaf6-e3eb45571e39)\
In next step,
1. Using while to check if the DLLBase address is not 0.
2. Fetching the DllBase address from LDR Table entry.
3. Fetching the BaseDLLName address from LDR Table entry.
4. Printing the details.
5. Loading the next DLL address.

If we compile and run the code.
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/014dc758-4806-4b7d-84c8-976c72c19273)\
We can see it successfully loaded the name and address of the executables and DLLs.

That is all in this blog, hope you guys enojyed reading it!!😄

# Resources
1. **[https://www.youtube.com/watch?v=kOTb0Nm3_ks](https://www.youtube.com/watch?v=kOTb0Nm3_ks)**.
2. **[https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software](https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software)**.
3. **[https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block)**.
