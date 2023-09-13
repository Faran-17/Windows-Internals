# Summary
In this blog, we will take a deep dive inside on how a normal process is created in a Windows environment. We will start by writing a short code to create a simple process then debug it via debugger to understand it's internal working and also we will be taking a look at how to create a process via NTAPIs. 

Note - All the references, credits and codes will mentioned in this blog.

# Index
1. **[Process Creation Via C++](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/Creation%20Of%20Process.md#process-creation-via-c)**
2. **[Static Analysis](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/Creation%20Of%20Process.md#static-analysis)**
3. **[X64dbg Analysis](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/Creation%20Of%20Process.md#x64dbg-analysis)**
4. **[Process Creatia Via NTAPIs](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/Creation%20Of%20Process.md#creating-process-via-ntapis)**

# Process Creation Via C++
I wrote a blog a while go on the overview of how a process is created inside a Windows environment, you can read it **[here](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/Overview%20of%20process%20creation.md)**. In there I tried to explain the general overview of the whole process of creation of process(no puns intended). Let's take a deep dive. Below here is a simple C++ code that will spawn **notepad.exe** process. (The code is stored **[here](https://github.com/Faran-17/Windows-Internals/blob/main/codes/Processes%20and%20Jobs/Create_Process.cpp)**)
```CPP
#include <windows.h>
#include <iostream>

int main() {
    STARTUPINFO si = {};
    PROCESS_INFORMATION pi = {};

    // Path to the executable
    LPCWSTR notepadPath = L"C:\\Windows\\System32\\notepad.exe";

    if (CreateProcess(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::wcout << L"Process ID (PID): " << pi.dwProcessId << std::endl;

        // Close process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cerr << "CreateProcess failed. Error: " << GetLastError() << std::endl;
    }

    return 0;
}
```
The above code uses the basics API called **[CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)**, which is used by Windows to create a process and malwares to create a malicious process. Here is the structure of the API.
```CPP
BOOL CreateProcessW(
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```
Let's go throught the parameters.  
* **lpApplicationName** is the name of the process to be created and should have a full path to the process executable. In this example, we can see that it is **notepadPath** variable as a parameter and also this variable is declared above with the full path of the notepad.exe
    ```CPP
    // Path to the executable
    LPCWSTR notepadPath = L"C:\\Windows\\System32\\notepad.exe";
    ```
* **`lpCommandLine`** is the command line arguments of a process that can be decalred and passed. This is optional so it is **NULL**.
* The **`lpProcessAttributes`** is a pointer to the **[SECURITY_ATTRIBUTES](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85))** structure that determines whether the returned handle to the new process object can be inherited by child processes. If lpProcessAttributes is **NULL**, the handle cannot be inherited.
* The **`lpThreadAttributes`** is the same as **lpProcessAttributes**, declared as **NULL**.
* If **`bInheritHandles`** is TRUE, each inheritable handle in the calling process is inherited by the new process. Here it is declared **FALSE**, which means the handles are not inherited.
* The **`dwCreationFlags`** controls the priority class and the creation of the process. Here are the list of values for reference(**(here)[https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags]**). The flag is decalred with a value of 0.
* The **`lpEnvironment`** parameter is a pointer to the environment block for the new process. The parameter is declared **NULL**, the new process uses the environment of the calling process.
* The **`lpCurrentDirectory`** is the full path to the directory of the process. It is declares as **NULL**, which means the process will have the same current drive and directory as the calling process. Also we don't need the pull path as we've already declared the full path of notepad.exe
* The **`lpStartupInfo`** contains the pointer to the **[STARTUPINFO](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa)** structure which is used to specify main window properties if a new window is created for the new process. Declaring it's structure in the code.
  ```
  STARTUPINFO si = {};
  ```
* The **`lpProcessInformation`** points to the **[PROCESS_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information)** structure which contains the information about a newly created process and its primary thread. Declaring it's structure in the code.
  ```
  PROCESS_INFORMATION pi = {};
  ```

Now we compile the code in Release mode and double-click on the generated executable.  
![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/f43f7ead-889a-42c9-ac65-38c2dd191e67)  
It ran successfully and spawned notepad.exe

# Static Analysis
Just like a malware, let's first take a look at inside the methodology of our code. For static analysis we will open the executable inside a tool called Cutter.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/3726d542-596e-456b-be43-42157db4951f)  

Here is whole graphical flow of the whole process(no puns again)  

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/898ce84a-6f51-45c6-9ba4-4cc3afc5f159)  

As we can see, the **`main()`** function is shown in the analysis along with the variables and structures decalred.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/ad38b8af-a6e6-4666-8cc5-c04d213eaefb)  

Scroll down and we see the whole code in the form of assembly, here its what happenning -
* The value of `lpApplicationName` is loaded into rcx,
* The value of `lpThreadAttributes` is set to NULL
* The value of `lpProcessAttributes` is set to NULL
* The value of `lpCommandLine` is set to NULL
* The pointer to `lpProcessInformation` is set from the variable defined
* The pointer to `lpStartupInfo` is set from the variable defined
* Other parameters values are set accordingly.
* Then the `CreateProcess` API is called along with it’s variables.

The CreateProcess API has return type of BOOL. The return value will be non-zero if the API runs successfully or else the value will be 0.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/041b603e-f040-4388-ab7d-0c6296290415)  

The JE(Jump If Equal) will do the comparison and will redirect the execution. If the API fails.  

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/a29f207f-fd3b-40cb-b2a0-abf066459e40)  

The **[GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)** is called to handle the error. And if the API is successful.  

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/021481ac-be19-4a17-a2a5-ec782ed3bc28)  

The process is spawned and the **[CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)** API is called to close the process completely.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/1370a892-b808-4441-8830-4b3b03f0aea8)  

And then the return function is called to close the program. Although the whole flow is understanable, still we can't see how the switch from user mode to kernel mode happens. To know this, we'll be doing dynamic analysis of the executable

# X64Dbg Analysis
Open the exectuable inside x64Dbg and press F9 to start the execution. To make things easy, I've already setup breakpoints at important places to make is more understandable.

Before we move on, here is the whole diagram of the flow of creating a process.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/eba6b471-572b-445b-bf92-0ced7d844a22)  

Make sure to keep this flow in your mind for better understanding. Open the exe inside the debugger and press F9 to start the execution.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/1aea77c1-7eb7-4bd1-9a78-e72c47bc5950)  

Pressing F9 to move to the next breakpoint. 

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/41281d05-6696-47cd-acc3-fefcc02f035f)  

An execution call is mode to the executable binary i.e **create-process.exe**. Now stepping into this execution call and pressing F9 to move to the next breakpoint.  

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/c3cec5bc-b66c-4b83-861c-db2693f172a0)  

Moving inside we will see the CreatePreocessW API call, this is where are the parameters are set. Then step into it as well. After setting the parameters we step into the moment before it get’s executed.  

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/61ba8bba-9a08-4577-b1e8-cfd103ac9101)  

Then we step into the it to see what happens after the **`CreateProcessW`** is called.  

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/67eaf446-edff-45c5-b144-4e78a95cd3b6)  

We can see that the **[CreateProcessInternalW](https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c.html#a13a0f94b43874ed5a678909bc39cc1ab)** is called from KernelBase.dll which in simple words gets functionality from kernel32.dll and advapi32.dll. Now we step inside CreateProcessInternalW.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/8adecf16-f317-4880-a074-e62e5face271)

It is making call to **`NtCreateUserProcess`** inside NTDLL. Here is the structure of the API
```CPP
NTSTATUS
NTAPI
NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_ PPS_ATTRIBUTE_LIST AttributeList
);
```
Stepping inside the API call.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/84654a36-8566-4e16-a0ca-e63d8ab67d61)  

We can see that it is making a syscall to NtCreateUserProcess which resides inside kernel and that actually start our process. If we press F9 to resume the execution, notepad.exe will be spawned.  

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/ea71ca75-a070-4698-bcf4-19e1982c3e61)  

We can visualize this whole process creation in a small video.  

https://github.com/Faran-17/Windows-Internals/assets/59355783/fc21c971-ade9-4505-8628-4a2298cd0331

# Creating Process Via NTAPIs
In this section, we will take a look at how we can create a process directly with the Native API **`NtCreateUserProcess`**. Although this is beyond my skillset, fortunately **[@CaptMeelo](https://twitter.com/CaptMeelo)** created a awesome blog post on how to do it exactly. In this section, I'll just try to explain the method in an easy way. In order to know more about this topics you can read it on the author's website **([HERE](https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html))**. All credits to the creator for this amazing write-up

As we saw the **`NtCreateUserProcess`** API is where the transition from User mode to Kernel mode happens. Here is the structure of the API

```CPP
NTSTATUS
NTAPI
NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_ PPS_ATTRIBUTE_LIST AttributeList
);
```
Let's try to understand it's parameter. 
**`ProcessHandle`** and **`ThreadHandle`** which will store the handles to the created process and thread. These two arguments are too simple and can be initialized with the following.
```
HANDLE hProcess, hThread = NULL;
```
For **`ProcessDesiredAccess`** and **`ThreadDesiredAccess`** parameters, we need to supply them with **`ACCESS_MASK`** values that would identify the rights and controls we have over the process and thread we’re creating. Different values could be assigned to **`ACCESS_MASK`** and they are listed in **`winnt.h`**. Since we’re only dealing with process and thread objects, we can use the process- and thread-specific access rights **`PROCESS_ALL_ACCESS`** and **`THREAD_ALL_ACCESS`**.

Here are the other properties - 
* **[PROCESS ACCESS RIGHTS](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)**
* **[THREAD ACCESS RIGHTS](https://docs.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights)**

The next parameters are **`ProcessObjectAttributes`** and **`ThreadObjectAttributes`**, which are pointers to an **[OBJECT_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes)**. This structure contains the attributes that could be applied to the objects or object handles that will be created. These parameters are optional hence we can simply assign **`NULL`** values to them.

Moving on, the flags set within **`ProcessFlags`** and **`ThreadFlags`** determine how we want our process and thread to be created. These are similar to the **`dwCreationFlags`** argument of **`CreateProcess()`** API which doesn't apply in this case. We will look into **[Process Hacker](https://processhacker.sourceforge.io/)** which is open-source software and also it's a useful tool to look inside a process properties it does interact with the kernel and native APIS. 

From the NTSAPI, here are the **`ProcessFlags`** valid parameters and values(**[Here](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1354)**).
```CPP
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040 // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080 // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_MINIMAL_PROCESS 0x00000800 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL 0x00002000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT 0x00004000 //
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000 // NtCreateProcessEx & NtCreateUserProcess
```
And for the **`ThreadFlags`** as well(**[Here](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L2325)**).
```CPP
#define THREAD_CREATE_FLAGS_NONE 0x00000000
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
```
One good thing about this is that the comments mentioned which flags are supported by which APIs. Now we're working on a nomral process creation so setting the flag to **NULL**.

The last argument, **`AttributeList`**  parameter is used to set up the attributes for process and thread creation. An example of this is when implementing PPID Spoofing where the **`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`** attribute is set. We can again look at NTSAPI of Process Hacker for its valid values and parameters (**[Here](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L2001)**).

```CPP
#define PS_ATTRIBUTE_PARENT_PROCESS PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_PORT PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_UMS_THREAD PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_SECURE_PROCESS PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHPE PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_MACHINE_TYPE PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE)
```

In the code, here how it is initialized.

```CPP
PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);

AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
AttributeList->Attributes[0].Size = NtImagePath.Length;
AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;
```

The **`pProcessParameters`** points to the **`RTL_USER_PROCESS_PARAMETERS`** structure, which will hold the process parameter information as a result of executing **`RtlCreateProcessParametersEx()`**. Any information stored in the structure is then used as an input to **`NtCreateProcess()`**.

Here is the structure of **`RtlCreateProcessParametersEx()`**,

```CPP
typedef NTSTATUS (NTAPI *_RtlCreateProcessParametersEx)(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags
);
```

And the strucutre of **`RTL_USER_PROCESS_PARAMETERS`**,

```CPP
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
 
    ULONG Flags;
    ULONG DebugFlags;
 
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
 
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
 
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
 
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
 
    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

The second parameter **`ImagePathName`** holds the full path (in NT path format) of the image/binary from which the process will be created. For example.

```CPP
UNICODE_STRING NtImagePath;
RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\calc.exe");
```

The **`RtlInitUnicodeString()`** function, which has the following syntax, is necessary to initialize the **`UNICODE_STRING`** structure.

```CPP
VOID NTAPIRtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PWSTR SourceString
);
```

And here is the structure of **`UNICODE_STRING`**.

```CPP
typedef struct _UNICODE_STRING
{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
```

The initialization of the **`UNICODE_STRING`** structure is done by:
- Setting the **`Length`** and **`MaximumLength`** members to the length of the **`SourceString`**
- Setting the **`Buffer`** member to the address of the string passed in **`SourceString`**
  
The other arguments are optional, so setting them to **NULL**. A scenario in which these parameters can be useful is when “blending in” to help avoid detections. As an example, if we set CommandLine to NULL, the value that will be set upon process creation is the same with what’s passed in ImagePathName.  

Here is the full code by **[@CaptMeelo](https://twitter.com/CaptMeelo)**.

```CPP
#include <Windows.h>
#include "ntdll.h"
#pragma comment(lib, "ntdll")

int main()
{
	// Path to the image file from which the process will be created
	UNICODE_STRING NtImagePath;
	RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\calc.exe");

	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	// Initialize the PS_ATTRIBUTE_LIST structure
	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtImagePath.Length;
	AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	// Create the process
	HANDLE hProcess, hThread = NULL;
	NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);

	// Clean up
	RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
	RtlDestroyProcessParameters(ProcessParameters);
}
```

Compiling and running the code will pop-up the calc.exe

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/23a7949e-977c-4753-83ca-2ac1001f3762)


# Conclusion
In this, post we've seen how a normal process is created inside a Windows environment. We wrote a C++ code that spawns a process and debugged it inside a debugger to view it's inner working. Also we've taken a look at the POC that creates a process via NTAPIs. All the reference and resources are mentioned below

Thank you for reading😄

# References
1. **https://doxygen.reactos.org/**
2. **https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html**
3. **https://github.com/capt-meelo/NtCreateUserProcess**
4. **https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h**








 



