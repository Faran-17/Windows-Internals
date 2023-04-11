# Summary
In this blog, we will take a look at what PEB is and it's inner workings using a debugger. This will be a multipart series of blogs where I try to cover and understand different parameters of the PEB and it's structure. References are mentioned at the end.

# Index
1. **[What is PEB?](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#what-is-peb)**
2. **[Structure of PEB](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#structure-of-the-peb)**
3. **[PEB analysis in WinDbg](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#peb-analysis-in-windbg)**
4. **[BeingDebugged](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#beingdebugged)**
5. **[BitField](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#bitfield)**
6. **[Protected Process](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#protected-process)**
7. **[IsImageDynamicallyRelocated ](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#isimagedynamicallyrelocated)**
8. **[SkipPatchingUser32Forwarders](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#skippatchinguser32forwarders)**
9. **[IsLongPathAwareProcess](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#islongpathawareprocess)**
10. **[ImageBaseAddress](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#imagebaseaddress)**
11. **[LDR](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#ldr)**
12. **[Process Parameters](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md#process-parameters)**

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

# SkipPatchingUser32Forwarders

![image](https://user-images.githubusercontent.com/59355783/229345019-2cbef7ea-1c34-48fa-a06f-3a64ac9eb568.png)

The **```SkipPatchingUser32Forwarders```** field in the Process Environment Block (PEB) structure is a bit flag that is used by the Windows operating system to control the patching of certain user-mode library functions in the process.

When a process loads the user32.dll library, the operating system normally applies a process-specific set of patches to certain exported functions in the library. These patches are known as "forwarders" and are used to redirect calls to these functions to a different location within the library or to an entirely different library altogether. This process is known as "forwarding".

The **```SkipPatchingUser32Forwarders```** flag controls whether or not these forwarders are applied in the current process. When the flag is set to 1, the operating system will skip the patching of forwarders in the user32.dll library. When the flag is set to 0, the operating system will apply the forwarder patches as normal.

The primary use case for setting the **```SkipPatchingUser32Forwarders```** flag is to improve the startup time of certain types of processes. The patching process can be time-consuming, especially for processes that make heavy use of the user32.dll library. By skipping the patching step, the process can be started more quickly and without the overhead of the patching process.

However, it's worth noting that skipping the patching of forwarders can potentially cause compatibility issues with certain types of applications. In general, it's recommended to only set the **```SkipPatchingUser32Forwarders```** flag if it is known to be safe and necessary for the specific application or scenario.

The **```SkipPatchingUser32Forwarders```** flag is set to 1 by default on 64-bit versions of Windows, which means that forwarders are skipped unless explicitly enabled. On 32-bit versions of Windows, the flag is set to 0 by default, which means that forwarders are applied unless explicitly disabled.

To explicitly enable or disable the **```SkipPatchingUser32Forwarders```** flag, you can use the **[SetProcessMitigationPolicy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)** API.

```
BOOL SetProcessMitigationPolicy(
  [in] PROCESS_MITIGATION_POLICY MitigationPolicy,
  [in] PVOID                     lpBuffer,
  [in] SIZE_T                    dwLength
);
```

# IsLongPathAwareProcess

![image](https://user-images.githubusercontent.com/59355783/229345697-559a3125-2011-40e6-915d-0082996bb652.png)

The **`IsLongPathAwareProcess`** field in the Process Environment Block (PEB) structure is a boolean flag that indicates whether the current process is aware of long paths. Long paths are paths that exceed the maximum path length of 260 characters in the Windows operating system.

When a process is long path aware, it can handle long paths in its file I/O operations without encountering any errors or exceptions. This is because long paths require a special prefix (**`\\?\`**) to be specified, and not all software is capable of handling these paths correctly

A value of 1 for the **`IsLongPathAwareProcess`** field indicates that the current process is aware of long paths, while a value of 0 indicates that it is not. This flag is set by the operating system when the process is started, based on certain conditions such as the presence of a manifest file that specifies long path awareness.

# ImageBaseAddress

![image](https://user-images.githubusercontent.com/59355783/229346244-ce02380e-05c2-45e6-bb8a-576ea13fde88.png)

In the context of the Process Environment Block (PEB) structure in Windows, the term **```ImageBaseAddress```** refers to the virtual memory address at which the executable image of a process is loaded in memory.

When a process is started in Windows, the operating system creates a new process object and allocates a block of virtual memory for the process to use. The executable image of the process is then loaded into this virtual memory space, and the process is initialized and executed. The **```ImageBaseAddress```** field in the PEB structure contains the virtual memory address at which the first module in the process's module list is loaded.

The **```ImageBaseAddress```** is important because it is the base address at which all the code and data in the process's executable image are loaded into memory. When the process is executed, the processor uses the **```ImageBaseAddress```** to calculate the virtual memory addresses of all the instructions and data in the process's code. This allows the operating system to properly link and execute the code, and enables the process to access and modify its own data.

We can take a look at it using WinDbg

![image](https://user-images.githubusercontent.com/59355783/229346336-d19b029b-a8dc-45ae-a19c-bb1f7dc562b9.png)

# LDR

One of the fields in the PEB structure is the Loader Data Table (LDR) field, which contains information about all the loaded modules (i.e., DLLs and executables) in the process's address space.

When a process starts, the operating system creates the LDR field in the PEB structure and initializes it with an LDR entry for the process's main executable image. As the process loads additional modules into its address space, new LDR entries are added to the LDR field to describe these modules.

The LDR field is important because it provides the operating system with information about the loaded modules in a process's address space. This information is used to resolve symbols, calculate virtual memory addresses, and perform other tasks necessary to properly execute the code in the process.

![image](https://user-images.githubusercontent.com/59355783/229349180-104c5895-6101-4930-9d18-903bce1d576c.png)

Click on the LDR hyperlink.

![image](https://user-images.githubusercontent.com/59355783/229349200-efa7f43b-a86c-4036-90b2-19d1e0c00c13.png)

This displays its structure. 

```
0:001> dx -r1 ((ntdll!_PEB_LDR_DATA *)0x7ffa92a9a4c0)
((ntdll!_PEB_LDR_DATA *)0x7ffa92a9a4c0)                 : 0x7ffa92a9a4c0 [Type: _PEB_LDR_DATA *]
    [+0x000] Length           : 0x58 [Type: unsigned long]
    [+0x004] Initialized      : 0x1 [Type: unsigned char]
    [+0x008] SsHandle         : 0x0 [Type: void *]
    [+0x010] InLoadOrderModuleList [Type: _LIST_ENTRY]
    [+0x020] InMemoryOrderModuleList [Type: _LIST_ENTRY]
    [+0x030] InInitializationOrderModuleList [Type: _LIST_ENTRY]
    [+0x040] EntryInProgress  : 0x0 [Type: void *]
    [+0x048] ShutdownInProgress : 0x0 [Type: unsigned char]
    [+0x050] ShutdownThreadId : 0x0 [Type: void *]
```

It has three important lists as highlighted. If we take a look at anyone of the list structure.

```
0:001> dx -r1 (*((ntdll!_LIST_ENTRY *)0x7ffa92a9a4d0))
(*((ntdll!_LIST_ENTRY *)0x7ffa92a9a4d0))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0x29d7c1b2fa0 [Type: _LIST_ENTRY *]
    [+0x008] Blink            : 0x29d7c1b4a90 [Type: _LIST_ENTRY *]
```

We can see these are doubly-linked list. As per MSDN 

```Cpp
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
```

And each of the list entry has a structure like this.

```Cpp
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

But if we use the Windbg command we will get more detailed list.

```
0:001> dt _LDR_DATA_TABLE_ENTRY
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x010 InMemoryOrderLinks : _LIST_ENTRY
   +0x020 InInitializationOrderLinks : _LIST_ENTRY
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING
   +0x058 BaseDllName      : _UNICODE_STRING
   +0x068 FlagGroup        : [4] UChar
   +0x068 Flags            : Uint4B
   +0x068 PackagedBinary   : Pos 0, 1 Bit
   +0x068 MarkedForRemoval : Pos 1, 1 Bit
   +0x068 ImageDll         : Pos 2, 1 Bit
   +0x068 LoadNotificationsSent : Pos 3, 1 Bit
   +0x068 TelemetryEntryProcessed : Pos 4, 1 Bit
   +0x068 ProcessStaticImport : Pos 5, 1 Bit
   +0x068 InLegacyLists    : Pos 6, 1 Bit
   +0x068 InIndexes        : Pos 7, 1 Bit
   +0x068 ShimDll          : Pos 8, 1 Bit
   +0x068 InExceptionTable : Pos 9, 1 Bit
   +0x068 ReservedFlags1   : Pos 10, 2 Bits
   +0x068 LoadInProgress   : Pos 12, 1 Bit
   +0x068 LoadConfigProcessed : Pos 13, 1 Bit
   +0x068 EntryProcessed   : Pos 14, 1 Bit
   +0x068 ProtectDelayLoad : Pos 15, 1 Bit
   +0x068 ReservedFlags3   : Pos 16, 2 Bits
   +0x068 DontCallForThreads : Pos 18, 1 Bit
   +0x068 ProcessAttachCalled : Pos 19, 1 Bit
   +0x068 ProcessAttachFailed : Pos 20, 1 Bit
   +0x068 CorDeferredValidate : Pos 21, 1 Bit
   +0x068 CorImage         : Pos 22, 1 Bit
   +0x068 DontRelocate     : Pos 23, 1 Bit
   +0x068 CorILOnly        : Pos 24, 1 Bit
   +0x068 ChpeImage        : Pos 25, 1 Bit
   +0x068 ReservedFlags5   : Pos 26, 2 Bits
   +0x068 Redirected       : Pos 28, 1 Bit
   +0x068 ReservedFlags6   : Pos 29, 2 Bits
   +0x068 CompatDatabaseProcessed : Pos 31, 1 Bit
   +0x06c ObsoleteLoadCount : Uint2B
   +0x06e TlsIndex         : Uint2B
   +0x070 HashLinks        : _LIST_ENTRY
   +0x080 TimeDateStamp    : Uint4B
   +0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
   +0x090 Lock             : Ptr64 Void
   +0x098 DdagNode         : Ptr64 _LDR_DDAG_NODE
   +0x0a0 NodeModuleLink   : _LIST_ENTRY
   +0x0b0 LoadContext      : Ptr64 _LDRP_LOAD_CONTEXT
   +0x0b8 ParentDllBase    : Ptr64 Void
   +0x0c0 SwitchBackContext : Ptr64 Void
   +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
   +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x0f8 OriginalBase     : Uint8B
   +0x100 LoadTime         : _LARGE_INTEGER
   +0x108 BaseNameHashValue : Uint4B
   +0x10c LoadReason       : _LDR_DLL_LOAD_REASON
   +0x110 ImplicitPathOptions : Uint4B
   +0x114 ReferenceCount   : Uint4B
   +0x118 DependentLoadFlags : Uint4B
   +0x11c SigningLevel     : UChar
```

Now loading the LDR Data.

```
0:001> dt _PEB_LDR_DATA 0x7ffa92a9a4c0
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x58
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x010 InLoadOrderModuleList : _LIST_ENTRY [ 0x0000029d`7c1b2fa0 - 0x0000029d`7c1b4a90 ]
   +0x020 InMemoryOrderModuleList : _LIST_ENTRY [ 0x0000029d`7c1b2fb0 - 0x0000029d`7c1b4aa0 ]
   +0x030 InInitializationOrderModuleList : _LIST_ENTRY [ 0x0000029d`7c1b2e30 - 0x0000029d`7c1b4ab0 ]
   +0x040 EntryInProgress  : (null) 
   +0x048 ShutdownInProgress : 0 ''
   +0x050 ShutdownThreadId : (null)
```

It will load the LDR struct. Now take a look at **```InLoadOrderModuelList```***.

![image](https://user-images.githubusercontent.com/59355783/229349802-c4e7e144-912e-463c-b453-2d7da140fbd9.png)

1. It contains the path of the exe that is loaded. In which case it’s "cmd.exe"
2. The base address of the cmd.exe. Let’s confirm

![image](https://user-images.githubusercontent.com/59355783/229349851-518db39c-2422-443f-9ca6-066b3686472b.png)

3. The address of the next LIST ENTRY, which is InMemoryOrderModuleList

![image](https://user-images.githubusercontent.com/59355783/229349914-7e60d691-5284-401f-a13d-d7817771c911.png)

The PEB LDR is a topic of its own I will explain it later in some other blog. 

# Process Parameters

The ProcessParameters field contains information about the command line and environment variables used to start the process.

![image](https://user-images.githubusercontent.com/59355783/230592651-8ba1d08c-f379-4737-88e4-49b700f4f7fb.png)

This uses **```_RTL_USER_PROCESS_PARAMETERS```** structure. We can take a look at it in Windbg.

```
0:001> dx -r1 ((ntdll!_RTL_USER_PROCESS_PARAMETERS *)0x29d7c1b2550)
((ntdll!_RTL_USER_PROCESS_PARAMETERS *)0x29d7c1b2550)                 : 0x29d7c1b2550 [Type: _RTL_USER_PROCESS_PARAMETERS *]
    [+0x000] MaximumLength    : 0x7aa [Type: unsigned long]
    [+0x004] Length           : 0x7aa [Type: unsigned long]
    [+0x008] Flags            : 0x6001 [Type: unsigned long]
    [+0x00c] DebugFlags       : 0x0 [Type: unsigned long]
    [+0x010] ConsoleHandle    : 0x44 [Type: void *]
    [+0x018] ConsoleFlags     : 0x0 [Type: unsigned long]
    [+0x020] StandardInput    : 0x50 [Type: void *]
    [+0x028] StandardOutput   : 0x54 [Type: void *]
    [+0x030] StandardError    : 0x58 [Type: void *]
    [+0x038] CurrentDirectory [Type: _CURDIR]
    [+0x050] DllPath          [Type: _UNICODE_STRING]
    [+0x060] ImagePathName    [Type: _UNICODE_STRING]
    [+0x070] CommandLine      [Type: _UNICODE_STRING]
    [+0x080] Environment      : 0x29d7c1c5540 [Type: void *]
    [+0x088] StartingX        : 0x0 [Type: unsigned long]
    [+0x08c] StartingY        : 0x0 [Type: unsigned long]
    [+0x090] CountX           : 0x0 [Type: unsigned long]
    [+0x094] CountY           : 0x0 [Type: unsigned long]
    [+0x098] CountCharsX      : 0x0 [Type: unsigned long]
    [+0x09c] CountCharsY      : 0x0 [Type: unsigned long]
    [+0x0a0] FillAttribute    : 0x0 [Type: unsigned long]
    [+0x0a4] WindowFlags      : 0x801 [Type: unsigned long]
    [+0x0a8] ShowWindowFlags  : 0x1 [Type: unsigned long]
    [+0x0b0] WindowTitle      [Type: _UNICODE_STRING]
    [+0x0c0] DesktopInfo      [Type: _UNICODE_STRING]
    [+0x0d0] ShellInfo        [Type: _UNICODE_STRING]
    [+0x0e0] RuntimeData      [Type: _UNICODE_STRING]
    [+0x0f0] CurrentDirectores [Type: _RTL_DRIVE_LETTER_CURDIR [32]]
    [+0x3f0] EnvironmentSize  : 0x1584 [Type: unsigned __int64]
    [+0x3f8] EnvironmentVersion : 0x5 [Type: unsigned __int64]
    [+0x400] PackageDependencyData : 0x0 [Type: void *]
    [+0x408] ProcessGroupId   : 0x244 [Type: unsigned long]
    [+0x40c] LoaderThreads    : 0x0 [Type: unsigned long]
    [+0x410] RedirectionDllName [Type: _UNICODE_STRING]
    [+0x420] HeapPartitionName [Type: _UNICODE_STRING]
    [+0x430] DefaultThreadpoolCpuSetMasks : 0x0 [Type: unsigned __int64 *]
    [+0x438] DefaultThreadpoolCpuSetMaskCount : 0x0 [Type: unsigned long]
    [+0x43c] DefaultThreadpoolThreadMaximum : 0x0 [Type: unsigned long]
```

Here is the full structure of it from the undocumented **[website](http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FRTL_USER_PROCESS_PARAMETERS.html)**

```Cpp
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                   MaximumLength;
  ULONG                   Length;
  ULONG                   Flags;
  ULONG                   DebugFlags;
  PVOID                   ConsoleHandle;
  ULONG                   ConsoleFlags;
  HANDLE                  StdInputHandle;
  HANDLE                  StdOutputHandle;
  HANDLE                  StdErrorHandle;
  UNICODE_STRING          CurrentDirectoryPath;
  HANDLE                  CurrentDirectoryHandle;
  UNICODE_STRING          DllPath;
  UNICODE_STRING          ImagePathName;
  UNICODE_STRING          CommandLine;
  PVOID                   Environment;
  ULONG                   StartingPositionLeft;
  ULONG                   StartingPositionTop;
  ULONG                   Width;
  ULONG                   Height;
  ULONG                   CharWidth;
  ULONG                   CharHeight;
  ULONG                   ConsoleTextAttributes;
  ULONG                   WindowFlags;
  ULONG                   ShowWindowFlags;
  UNICODE_STRING          WindowTitle;
  UNICODE_STRING          DesktopName;
  UNICODE_STRING          ShellInfo;
  UNICODE_STRING          RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];

} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

Let’s take a look at it. **```dt _RTL_USER_PROCESS_PARAMETERS 0x0000029d`7c1b2550```**

![image](https://user-images.githubusercontent.com/59355783/230593148-c6ea7ce0-b2e1-4730-b93e-54800cc0fdc6.png)

You can see the full path of the cmd.exe 

This is the end of the part 1 of understanding the internals of PEB. In the next part, we will take a look at more fields inside PEB. Stay tuned :blush:


# References 

1. **[https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block)**
2. **[https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/peb](https://mohamed-fakroud.gitbook.io/red-teamings-dojo/windows-internals/peb)**
3. **[https://papers.vx-underground.org/papers/Malware%20Defense/Malware%20Analysis%202018/2018-02-26%20-%20Anatomy%20of%20the%20Process%20Environment%20Block%20(PEB)%20(Windows%20Internals).pdf](https://papers.vx-underground.org/papers/Malware%20Defense/Malware%20Analysis%202018/2018-02-26%20-%20Anatomy%20of%20the%20Process%20Environment%20Block%20(PEB)%20(Windows%20Internals).pdf)**
4. **[https://dosxuz.gitlab.io/post/perunsfart/](https://dosxuz.gitlab.io/post/perunsfart/)**
5. **[https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm)**


