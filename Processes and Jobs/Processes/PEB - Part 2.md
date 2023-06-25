# Summary
In this blog, we will be continue into looking more into the field inside PEB using a debugger. Also we will analyse and walk over PEB and understand how the NTDLL file is loaded into the process memeory.

If you want to read the previous part click **[here](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md)**

# Index
1. **[ProcessHeap]()**
2. **[FastPebLock]()**
3. **[KernelCallbackTable]()**
4. **[Walking the PEB]()**

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








