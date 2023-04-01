# Summary
In this blog, we will take a short look at how a simple process is created and what Win32 API functions are called just to create a simple process. What functions are called from the user space dlls and finally transitioning into the kernel space. This will be a general overview, practical code execution will be included in later blogs.

# What is a process?
In simple words a process is an instance of a program running in the computer. We write our computer programs in a text file and when we execute this program, it becomes a process which performs all the tasks mentioned in the program. A process is usually defined as an instance of a running program and consists of two components:
* A kernel object that the operating system uses to manage the process. The kernel object is also where the system keeps statistical information about the process.
* An address space that contains all the executable or dynamic-link library (DLL) module's code and data. It also contains dynamic memory allocations such as thread stacks and heap allocations

# Process Creation Overview
Now we will take a look at how a simple process is created and what APIs are called to properly call and create a process.
![image](https://user-images.githubusercontent.com/59355783/210236481-014dd790-ad94-4440-b852-a5979c2e7284.png)

Note - After researching I've made some slight changes in the above diagram compared to the on in the Windows Internals Part 1 book(Page 114).

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

The CreateProcess is used and abused by malwares that utilizes techniques like creating or modifying system process(**[T1543](https://attack.mitre.org/techniques/T1543/)**) and process injection techniques(**[T1055](https://attack.mitre.org/techniques/T1055/)**) and many more.

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
After this transition will happen to kernel mode which will call the **NtCreateUserProcess** in the ntoskernel which is undocumented.

There are also many other Win APIs that resides inside other DLLs. One of them being the **Advapi.dll** file. Advapi is also known as Advanced Windows 32 Base API which is located in the ***%SYSTEM%*** sub-folder, like ***C:\Windows\System32*** folder. Advapi32.dll is a part of the advanced API services library. It provides access to advanced functionality that comes in addition to the kernel. It is responsible for things like the Windows registry, restarting and shutting down the system, starting/stopping and creating Windows services, and managing user accounts.

Let's take a look at some of the APIs that are called by Advapi.

First one is the **CreateProcessWithLogon** that starts a new process, opens an application in that process, and uses a passed UserID and Password. The application opened is running under the credentials and authority of the UserID passed. This API is also used by Runas command. C++ structure.
```C++
BOOL CreateProcessWithLogonW(
  LPCWSTR lpUsername,
  LPCWSTR lpDomain,
  LPCWSTR lpPassword,
  DWORD dwLogonFlags,
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInfo
);
```
C# Structure.
```C#
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcessWithLogonW(
     String             userName,
     String             domain,
     String             password,
     LogonFlags         logonFlags,
     String             applicationName,
     String             commandLine,
     CreationFlags          creationFlags,
     UInt32             environment,
     String             currentDirectory,
     ref  StartupInfo       startupInfo,
     out ProcessInformation     processInformation);
```
The CreateProcessWithLogon is abused by malwares that used techniques like Access Token Manipulation(**[T1134](https://attack.mitre.org/techniques/T1134/)**) read more about it **[here](https://www.elastic.co/blog/how-attackers-abuse-access-token-manipulation)**. 

Another API is the CreateProcessWithTokenW that is used to create a process with a specific user’s token. C++ and C# structure is as follows.
```C++
BOOL CreateProcessWithTokenW(
  [in]                HANDLE                hToken,
  [in]                DWORD                 dwLogonFlags,
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```
```C#
[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        UInt32 dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        UInt32 dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);
```
This API is also abused by malwares that utilizes the sub-technique of the above mentioned attack which is called "**Create Process with token i.e [T1134.002](https://attack.mitre.org/techniques/T1134/002/)**".

**Note** - The CreateProcessWithLogonW and CreateProcessWithTokenW functions are similar to the CreateProcessAsUser function, except that the caller does not need to call the LogonUser function to authenticate the user and get a token.

**CreateProcessWithTokenW** and **CreateProcessWithLogon** makes RPC calls to the Seclogon.dll which is the Secondary Logon Service of the Microsoft Windows operating system. Its startup setting is "manual": it runs only when the user or another program starts it. It resides in **C:\Windows\System32** and is hosted by the **svchost.exe** which is a shared-service process that serves as a shell for loading services from DLL files.
The **seclogon.dll** exposes **SlrCreateProcessWithLogon** function called from **SeclCreateProcessWithLogonW**.
```C
DWORD SlrCreateProcessWithLogon(
        RPC_BINDING_HANDLE BindingHandle,
        PSECONDARYLOGONINFOW psli,
        LPPROCESS_INFORMATION ProcessInformationOutput)
``
which internally calls another API i.e **CreateProcessAsUserA**
```C
BOOL CreateProcessAsUserA(
  HANDLE                hToken,
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```
```C#
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
static extern bool CreateProcessAsUser(
    IntPtr hToken,
    string lpApplicationName,
    string lpCommandLine,
    ref SECURITY_ATTRIBUTES lpProcessAttributes,
    ref SECURITY_ATTRIBUTES lpThreadAttributes,
    bool bInheritHandles,
    uint dwCreationFlags,
    IntPtr lpEnvironment,
    string lpCurrentDirectory,
    ref STARTUPINFO lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation);
```
We can also call **CreateProcessAsUser** directly without using the seclogon service. For this you will need **SeAssignPrimaryToken** privilege that is assigned to windows service accounts. Then finally it calls **NtCreateUserProcess()** in the Ntdll file as above. Which then calls **NtCreateUserProcess()** in the kernel space.

Although this blog is a general overview of creating a simple process but under the hood things are complex which I will learn and explain it on later upcoming blogs.

Hope you enjoyed reading it😃
