# Summary
In this blog, we will take a short look at how a simple process is created and what Win32 API functions are called just to create a small process. What functions are called from the user space dlls and finally transitioning into the kernel space. This will be a general overview, practical code execution will be included in later blogs.

# What is a process?
In simple words a process is an instance of a program running in the computer. We write our computer programs in a text file and when we execute this program, it becomes a process which performs all the tasks mentioned in the program. A process is usually defined as an instance of a running program and consists of two components:
* A kernel object that the operating system uses to manage the process. The kernel object is also where the system keeps statistical information about the process.
* An address space that contains all the executable or dynamic-link library (DLL) module's code and data. It also contains dynamic memory allocations such as thread stacks and heap allocations

# Process Creation Overview
Now we will take a look at how a simple process is created and what APIs are called to properly call and create a process.
![image](https://user-images.githubusercontent.com/59355783/210196058-6975f607-d0db-4fa6-8fd6-c8b4a60d8c6f.png)

If we take a look at the above diagram. When a user creates a process a simple it uses a simple Win API function called **[CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)** which resides in the Kernel32.dll and creates a process in the same context and token as the user. Here is code structure of the API in C++ and C#.
```Cpp
BOOL creationResult;
    
    creationResult = CreateProcess(
        NULL,                   // No module name (use command line)
        cmdLine,                // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        FALSE,                  // Set handle inheritance to FALSE
        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, // creation flags
        NULL,                   // Use parent's environment block
        NULL,                   // Use parent's starting directory 
        &startupInfo,           // Pointer to STARTUPINFO structure
        &processInformation);   // Pointer to PROCESS_INFORMATION structure
```

```C#
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
static extern bool CreateProcess(
   string lpApplicationName,
   string lpCommandLine,
   ref SECURITY_ATTRIBUTES lpProcessAttributes,
   ref SECURITY_ATTRIBUTES lpThreadAttributes,
   bool bInheritHandles,
   uint dwCreationFlags,
   IntPtr lpEnvironment,
   string lpCurrentDirectory,
   [In] ref STARTUPINFO lpStartupInfo,
   out PROCESS_INFORMATION lpProcessInformation);
```

The CreateProcess is used and abused by many malwares that utilizes techniques like creating or modifying system process(**[T1543](https://attack.mitre.org/techniques/T1543/)**) and process injection techniques(**[T1055](https://attack.mitre.org/techniques/T1055/)**) and many more.

Using this API, the created process runs in the context (meaning the same access token) of the calling process. Execution then continues with a call to undocumentated **CreateProcessInternal()**, which is responsible for actually creating the user-mode process. Below is the structure of this API I found in the ReactOS source code(**[Refer the line 4625](https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c_source.html)**).
```C++
BOOL WINAPI CreateProcessInternalA(HANDLE hToken,
		LPCSTR lpApplicationName,
		LPSTR lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCSTR lpCurrentDirectory,
		LPSTARTUPINFOA lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation,
		PHANDLE hNewToken 
	)
```

Then it calls the **NtCreateUserProcess()** which resides in the ntdll.dll to make the transition from user mode to kernel mode. Here is the structure for the C/C++ and C#.
```C++
NTSTATUS NTAPI
NtCreateUserProcess (
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPROCESS_CREATE_INFO CreateInfo,
    PPROCESS_ATTRIBUTE_LIST AttributeList
    );
```
```C#
[DllImport("ntdll.dll", SetLastError=true)]
static extern UInt32 NtCreateUserProcess(ref IntPtr ProcessHandle, ref IntPtr ThreadHandle, AccessMask ProcessDesiredAccess, AccessMask ThreadDesiredAccess, IntPtr ProcessObjectAttributes, IntPtr ThreadObjectAttributes, UInt32 ProcessFlags, UInt32 ThreadFlags, IntPtr ProcessParameters, ref PS_CREATE_INFO CreateInfo, ref PS_ATTRIBUTE_LIST AttributeList);
```
After this transition will happen to kernel mode which will call the NtCreateUserProcess in the ntoskernel which is undocumented.

(Writing is in progress ....)
