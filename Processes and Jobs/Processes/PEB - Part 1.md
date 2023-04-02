# Summary
In this blog, we will take a look at what PEB is and it's inner workings using the a debugger. This will be a multipart series of blogs where I try to cover and understand different parameters of the PEB and it's structure. References are mentioned at the end.

# Index
1. **[What is PEB?](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#what-is-peb)**
2. **[Structure of PEB](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#structure-of-the-peb)**
3. **[PEB analysis in WinDbg](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#peb-analysis-in-windbg)**
4. **[BeingDebugged](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#beingdebugged)**
5. **[BitField](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#bitfield)**
6. **[Protected Process]()**
7. **[IsImageDynamicallyRelocated ]()**

# What is PEB?
PEB is the representation of a process in the user space. This is the user-mode structure that has the most knowledge about a process. It contains direct details on the process, and many pointers to other structs holding even more data on the PE. Any process with a slightest user-mode footprint will have a corresponding PEB structure. The PEB is created by the kernel but is mostly operated from user-mode. It is used to store data that is managed by the user-mode, hence providing easier data access than transition to kernel mode or inter process communication. 

# Structure of the PEB

Here is the representation of where PEB lies in the Windows architecture.
![image](https://user-images.githubusercontent.com/59355783/229268611-066a1413-f9e3-47eb-bacd-fe77e2762fcd.png)

In the above diagram, we can see that the PEB structure lies on the user space. However, there is more into it. Let's understand it in a very simple way. 

The kernel space in the Windows OS is divided into three parts, the HAL, the Kernel and the Executive Subsystem. The Executive subsystem deals with general OS policies and operation, the Kernel deals with process architecture details and low-level operations. The HAL deals with differences that arise in particular implementations of a processor architecture. Although they have their own complexity which are topics of their own.

So when we create a new process, both the Kernel and Executive Subsystem wants to track it, for thier own purposes. The structure that the Kernel uses to track the process is the KPROCESS and the structure that the Executive Subsystems use to track it is the EPROCESS. Also if we consider, the KPROCESS is the first field of the EPROCESS. Let's take a look at it's structure in a Kernel debugger.

```
lkd> dt _eprocess
nt!_EPROCESS
  +0x000 Pcb              : _KPROCESS
  +0x080 ProcessLock      : _EX_PUSH_LOCK
  +0x088 CreateTime       : _LARGE_INTEGER
  +0x090 ExitTime         : _LARGE_INTEGER
  +0x098 RundownProtect   : _EX_RUNDOWN_REF
  +0x09c UniqueProcessId  : Ptr32 Void
  +0x0a0 ActiveProcessLinks : _LIST_ENTRY
  +0x0a8 QuotaUsage       : [3] Uint4B
  +0x0b4 QuotaPeak        : [3] Uint4B
  +0x0c0 CommitCharge     : Uint4B
  +0x0c4 PeakVirtualSize  : Uint4B
  +0x0c8 VirtualSize      : Uint4B
  +0x0cc SessionProcessLinks : _LIST_ENTRY
  +0x0d4 DebugPort        : Ptr32 Void
  +0x0d8 ExceptionPortData : Ptr32 Void
  +0x0d8 ExceptionPortValue : Uint4B
  +0x0d8 ExceptionPortState : Pos 0, 3 Bits
  +0x0dc ObjectTable      : Ptr32 _HANDLE_TABLE
  +0x0e0 Token            : _EX_FAST_REF
  +0x0e4 WorkingSetPage   : Uint4B
  +0x0e8 AddressCreationLock : _EX_PUSH_LOCK
  +0x0ec RotateInProgress : Ptr32 _ETHREAD
  +0x0f0 ForkInProgress   : Ptr32 _ETHREAD
  +0x0f4 HardwareTrigger  : Uint4B
  +0x0f8 PhysicalVadRoot  : Ptr32 _MM_AVL_TABLE
  +0x0fc CloneRoot        : Ptr32 Void
  +0x100 NumberOfPrivatePages : Uint4B
  +0x104 NumberOfLockedPages : Uint4B
  +0x108 Win32Process     : Ptr32 Void
  +0x10c Job              : Ptr32 _EJOB
  +0x110 SectionObject    : Ptr32 Void
  +0x114 SectionBaseAddress : Ptr32 Void
  +0x118 QuotaBlock       : Ptr32 _EPROCESS_QUOTA_BLOCK
```
We can see that is the very first field is the KPROCESS. If we look KPROCESS structure it is represented as -

```
lkd> dt _kprocess
nt!_KPROCESS
  +0x000 Header           : _DISPATCHER_HEADER
  +0x010 ProfileListHead  : _LIST_ENTRY
  +0x018 DirectoryTableBase : Uint4B
  +0x01c Unused0          : Uint4B
  +0x020 LdtDescriptor    : _KGDTENTRY
  +0x028 Int21Descriptor  : _KIDTENTRY
  +0x030 IopmOffset       : Uint2B
  +0x032 Iopl             : UChar
  +0x033 Unused           : UChar
  +0x034 ActiveProcessors : Uint4B
  +0x038 KernelTime       : Uint4B
  +0x03c UserTime         : Uint4B
  +0x040 ReadyListHead    : _LIST_ENTRY
  +0x048 SwapListEntry    : _SINGLE_LIST_ENTRY
  +0x04c VdmTrapcHandler  : Ptr32 Void
  +0x050 ThreadListHead   : _LIST_ENTRY
  +0x058 ProcessLock      : Uint4B
  +0x05c Affinity         : Uint4B
  +0x060 AutoAlignment    : Pos 0, 1 Bit
  +0x060 DisableBoost     : Pos 1, 1 Bit
  +0x060 DisableQuantum   : Pos 2, 1 Bit
  +0x060 ReservedFlags    : Pos 3, 29 Bits
  +0x060 ProcessFlags     : Int4B
  +0x064 BasePriority     : Char
  +0x065 QuantumReset     : Char
  +0x066 State            : UChar
  +0x067 ThreadSeed       : UChar
  +0x068 PowerState       : UChar
  +0x069 IdealNode        : UChar
  +0x06a Visited          : UChar
  +0x06b Flags            : _KEXECUTE_OPTIONS
  +0x06b ExecuteOptions   : UChar
  +0x06c StackCount       : Uint4B
  +0x070 ProcessListEntry : _LIST_ENTRY
  +0x078 CycleTime        : Uint8B
```
The same logic is applied the process's threads in representation of ETHREAD and KTHREAD. The PEB comes from the Thread Environment Block (TEB) which also happens to be commonly referred to as the Thread Information Block (TIB). The TEB is responsible for holding data about the current thread – every thread has
it’s own TEB structure.

I've explained all this term in a very basic way but under the hood things get a little complext and Each structure deservers it's own attention and time which we will do in the future blogs.

Before we move forwards, let's understand the basic flow of creation of and where everything fits.  
1. A new process(Eg. Cmd.exe) is started, this process will call the Win32API **[CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)** which sends the request to create the proccess.
2. EPROCESS structure is created in the Kernel Space.
3. Windows creates the process, virtual memory, and its representation of the physical memory and saves it inside the EPROCESS structure.
4. PEB structures is created in the User Space with all the necessary information and then loads the two most importand DLLs Ntdll.dll and Kernel32.dll
5. Loading the PE and starting the execution.

To know more about the APIs that are called when you create a simple process. Check out my previous blog where I covered this topic **[here](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/Overview%20of%20process%20creation.md)**.

Let's take a look at the PEB structure asn per official **[MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)**.
```Cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```
The PEB isn't fully documented. So we will take a look at in inside the WinDbg.

```
0:007> dt ntdll!_PEB
+0x000 InheritedAddressSpace : UChar
+0x001 ReadImageFileExecOptions : UChar
+0x002 BeingDebugged : UChar
+0x003 BitField : UChar
+0x003 ImageUsesLargePages : Pos 0, 1 Bit
+0x003 IsProtectedProcess : Pos 1, 1 Bit
+0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
+0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
+0x003 IsPackagedProcess : Pos 4, 1 Bit
+0x003 IsAppContainer : Pos 5, 1 Bit
+0x003 IsProtectedProcessLight : Pos 6, 1 Bit
+0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
+0x004 Padding0 : [4] UChar
+0x008 Mutant : Ptr64 Void
+0x010 ImageBaseAddress : Ptr64 Void
+0x018 Ldr : Ptr64 _PEB_LDR_DATA
+0x020 ProcessParameters : Ptr64 _RTL_USER_PROCESS_PARAMETERS
+0x028 SubSystemData : Ptr64 Void
+0x030 ProcessHeap : Ptr64 Void
+0x038 FastPebLock : Ptr64 _RTL_CRITICAL_SECTION
+0x040 AtlThunkSListPtr : Ptr64 _SLIST_HEADER
+0x048 IFEOKey : Ptr64 Void
+0x050 CrossProcessFlags : Uint4B
+0x050 ProcessInJob : Pos 0, 1 Bit
+0x050 ProcessInitializing : Pos 1, 1 Bit
+0x050 ProcessUsingVEH : Pos 2, 1 Bit
+0x050 ProcessUsingVCH : Pos 3, 1 Bit
+0x050 ProcessUsingFTH : Pos 4, 1 Bit
+0x050 ProcessPreviouslyThrottled : Pos 5, 1 Bit
+0x050 ProcessCurrentlyThrottled : Pos 6, 1 Bit
+0x050 ReservedBits0 : Pos 7, 25 Bits
+0x054 Padding1 : [4] UChar
+0x058 KernelCallbackTable : Ptr64 Void
+0x058 UserSharedInfoPtr : Ptr64 Void
+0x060 SystemReserved : Uint4B
+0x064 AtlThunkSListPtr32 : Uint4B
+0x068 ApiSetMap : Ptr64 Void
+0x070 TlsExpansionCounter : Uint4B
+0x074 Padding2 : [4] UChar
+0x078 TlsBitmap : Ptr64 Void
+0x080 TlsBitmapBits : [2] Uint4B
+0x088 ReadOnlySharedMemoryBase : Ptr64 Void
+0x090 SharedData : Ptr64 Void
+0x098 ReadOnlyStaticServerData : Ptr64 Ptr64 Void
+0x0a0 AnsiCodePageData : Ptr64 Void
+0x0a8 OemCodePageData : Ptr64 Void
+0x0b0 UnicodeCaseTableData : Ptr64 Void
+0x0b8 NumberOfProcessors : Uint4B
+0x0bc NtGlobalFlag : Uint4B
+0x0c0 CriticalSectionTimeout : _LARGE_INTEGER
+0x0c8 HeapSegmentReserve : Uint8B
+0x0d0 HeapSegmentCommit : Uint8B
+0x0d8 HeapDeCommitTotalFreeThreshold : Uint8B
+0x0e0 HeapDeCommitFreeBlockThreshold : Uint8B
8/17
+0x0e8 NumberOfHeaps : Uint4B
+0x0ec MaximumNumberOfHeaps : Uint4B
+0x0f0 ProcessHeaps : Ptr64 Ptr64 Void
+0x0f8 GdiSharedHandleTable : Ptr64 Void
+0x100 ProcessStarterHelper : Ptr64 Void
+0x108 GdiDCAttributeList : Uint4B
+0x10c Padding3 : [4] UChar
+0x110 LoaderLock : Ptr64 _RTL_CRITICAL_SECTION
+0x118 OSMajorVersion : Uint4B
+0x11c OSMinorVersion : Uint4B
+0x120 OSBuildNumber : Uint2B
+0x122 OSCSDVersion : Uint2B
+0x124 OSPlatformId : Uint4B
+0x128 ImageSubsystem : Uint4B
+0x12c ImageSubsystemMajorVersion : Uint4B
+0x130 ImageSubsystemMinorVersion : Uint4B
+0x134 Padding4 : [4] UChar
+0x138 ActiveProcessAffinityMask : Uint8B
+0x140 GdiHandleBuffer : [60] Uint4B
+0x230 PostProcessInitRoutine : Ptr64 void
+0x238 TlsExpansionBitmap : Ptr64 Void
+0x240 TlsExpansionBitmapBits : [32] Uint4B
+0x2c0 SessionId : Uint4B
+0x2c4 Padding5 : [4] UChar
+0x2c8 AppCompatFlags : _ULARGE_INTEGER
+0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER
+0x2d8 pShimData : Ptr64 Void
+0x2e0 AppCompatInfo : Ptr64 Void
+0x2e8 CSDVersion : _UNICODE_STRING
+0x2f8 ActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
+0x300 ProcessAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
+0x308 SystemDefaultActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
+0x310 SystemAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
+0x318 MinimumStackCommit : Uint8B
+0x320 FlsCallback : Ptr64 _FLS_CALLBACK_INFO
+0x328 FlsListHead : _LIST_ENTRY
+0x338 FlsBitmap : Ptr64 Void
+0x340 FlsBitmapBits : [4] Uint4B
+0x350 FlsHighIndex : Uint4B
+0x358 WerRegistrationData : Ptr64 Void
+0x360 WerShipAssertPtr : Ptr64 Void
+0x368 pUnused : Ptr64 Void
+0x370 pImageHeaderHash : Ptr64 Void
+0x378 TracingFlags : Uint4B
+0x378 HeapTracingEnabled : Pos 0, 1 Bit
+0x378 CritSecTracingEnabled : Pos 1, 1 Bit
+0x378 LibLoaderTracingEnabled : Pos 2, 1 Bit
+0x378 SpareTracingBits : Pos 3, 29 Bits
+0x37c Padding6 : [4] UChar
+0x380 CsrServerReadOnlySharedMemoryBase : Uint8B
+0x388 TppWorkerpListLock : Uint8B
+0x390 TppWorkerpList : _LIST_ENTRY
+0x3a0 WaitOnAddressHashTable : [128] Ptr64 Void
+0x7a0 TelemetryCoverageHeader : Ptr64 Void
+0x7a8 CloudFileFlags : Uint4B
```
There are lot of fields. In this blog series, I will try to cover as much as possible in a very simplistic way possible.

# PEB analysis in WinDbg
For this demonstration, we will pickup a simple executable CMD.exe and examine it's PEB structure inside WinDbg Preview. Start cmd.exe and open WinDbg Preview.

![image](https://user-images.githubusercontent.com/59355783/229278028-b9d5323a-a01c-462b-9899-c6b92d2d93d4.png)

Attach the cmd.exe process.

![image](https://user-images.githubusercontent.com/59355783/229278077-a75d5674-7707-4f7f-ac1b-95c8f62c083e.png)

The target process is sucessfully loaded into WinDbg. Now's let get the address of the PEB. There are two ways to get and we'll take a look at both of it.

Open ProcessHacker tool and double click on the cmd.exe process. We can see that the PEB address is displayed

![image](https://user-images.githubusercontent.com/59355783/229278269-2f2618e7-93d2-4517-9980-82782818be92.png)

We can also use WinDbg command to get the PEB address.
```
0:001> r $peb
$peb=0000004a69bb6000
```
Now loading the PEB structure of Cmd.exe with the command:
```
dt _peb @$peb
```
![image](https://user-images.githubusercontent.com/59355783/229278461-442ccad4-f232-429c-8c6e-ef093df7a9ce.png)

We can also use similar command that has better visual
```
!peb
```
![image](https://user-images.githubusercontent.com/59355783/229278517-1bcd58b5-d889-4934-b899-015d65b42a6e.png)

Let's start look at PEB's fields

# BeingDebugged

Indicates whether the specified process is currently being debugged by a user-mode debugger like OllyDbg, WinDbg etc. Some malware manually checked the PEB instead of using the API **```kernel32!IsDebuggerPresent()```**. The following code can be used to terminate the process if it is being debugged.

```ASM
.text:004010CD                 mov     eax, large fs:30h   ; PEB
.text:004010D3                 db      3Eh                 ; IDA Pro display error (byte is actually used in next instruction)
.text:004010D3                 cmp     byte ptr [eax+2], 1 ; PEB.BeingDebugged
.text:004010D8                 jz      short loc_4010E1
```

```Cpp
if (IsDebuggerPresent())
    ExitProcess(-1);
```

If the byte ptr [eax+2] returns 1 which we got in our above output. Then it means that our current process is being debugged.

# BitField

This indicates the architecture of the process.

![image](https://user-images.githubusercontent.com/59355783/229284527-ff245c55-9c7d-4a46-941d-a111ce4bf74f.png)

The offset we got for it was 0x84 which means that cmd.exe is a 32-bit process and also indicates the Windows OS version. Check **[this](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/bitfield.htm)** for more reference.

# Protected Process

![image](https://user-images.githubusercontent.com/59355783/229335144-01a9a9cd-9ac9-47c9-aec2-e6a30bb3a85e.png)

The **```IsProtectedProcess```** and **```IsProtectedProcessLight```** are used to check if the current process is protected or not. Microsoft use these mechanisms to protect their own System processes from being abused by malicious software or forcefully shut down by a third-party source.

All of this is enforced from kernel mode by the Windows Kernel using the undocumented and opaque EPROCESS structure, and you cannot write to these fields in the PEB structure and have the changes take effect because it won’t update the EPROCESS structure for the current process.

# IsImageDynamicallyRelocated 

![image](https://user-images.githubusercontent.com/59355783/229343435-67d72dc7-ed22-44f3-9247-76bcf25785b2.png)

The **```IsImageDynamicallyRelocated```** flag is a boolean value indicating whether the current process's executable image has been dynamically relocated at runtime. Dynamic relocation is a process by which the operating system loads an executable image at a memory location different from the address specified in the image's headers. This is done to avoid conflicts with other processes that may be using the same memory address space.

When a process is dynamically relocated, the operating system modifies certain pointers and addresses in the image's headers to reflect the new memory location. The IsImageDynamicallyRelocated flag in the PEB is set to true if this process has been performed on the current process.

Programs can access the IsImageDynamicallyRelocated flag through the Process Environment Block (PEB) data structure by calling the Win32 API function **[GetModuleHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexa)** with the **[GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexa#get_module_handle_ex_flag_unchanged_refcount-0x00000002)** flag. This function retrieves a handle to a module and updates the reference count for the module, but does not load the module if it has not been loaded yet. The function also sets the IsImageDynamicallyRelocated flag in the PEB if the module has been dynamically relocated.


Writing of this blog is in process...

