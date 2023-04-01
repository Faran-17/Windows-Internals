# Summary
In this blog, we will take a look at what PEB is and it's inner workings using the a debugger. This will be a multipart series of blogs where I try to cover and understand different parameters of the PEB and it's structure. References are mentioned at the end.

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
1. 

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



Writing of this blog is in process...

