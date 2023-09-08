# Summary
In this blog, we will take a deep dive inside on how a normal process is created in a Windows environment. We will start by writing a short code to create a simple process then debug it via debugger to understand it's internal working and also we will be taking a look at how to create a process via NTAPIs. 

Note - All the references, credits and codes will mentioned in this blog.

# Index
1. Process Creation Via C++
2. Static Analysis
3. X64dbg Analysis
4. Process Creatia Via NTAPIs

# Process Creation Via C++
I wrote a blog a while go on the overview of how a process is created inside a Windows environment, you can read it **[here](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/Overview%20of%20process%20creation.md)**. In there I tried to explain the general overview of the whole process of creation of process(no puns intended). Let's take a deep dive. Below here is a simple C++ code that will spawn **notepad.exe** process. (The code is stored here)
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
* **lpCommandLine** is the command line arguments of a process that can be decalred and passed. This is optional so it is **NULL**.
* The **lpProcessAttributes** is a pointer to the **[SECURITY_ATTRIBUTES](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85))** structure that determines whether the returned handle to the new process object can be inherited by child processes. If lpProcessAttributes is **NULL**, the handle cannot be inherited.
* The **lpThreadAttributes** is the same as **lpProcessAttributes**, declared as **NULL**.
* If **bInheritHandles** is TRUE, each inheritable handle in the calling process is inherited by the new process. Here it is declared **FALSE**, which means the handles are not inherited.
* The **dwCreationFlags** controls the priority class and the creation of the process. Here are the list of values for reference(**(here)[https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags]**). The flag is decalred with a value of 0.
* The **lpEnvironment** parameter is a pointer to the environment block for the new process. The parameter is declared **NULL**, the new process uses the environment of the calling process.
* The **lpCurrentDirectory** is the full path to the directory of the process. It is declares as **NULL**, which means the process will have the same current drive and directory as the calling process. Also we don't need the pull path as we've already declared the full path of notepad.exe
* The **lpStartupInfo** contains the pointer to the **[STARTUPINFO](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa)** structure which is used to specify main window properties if a new window is created for the new process. Declaring it's structure in the code.
  ```
  STARTUPINFO si = {};
  ```
* The **lpProcessInformation** points to the **[PROCESS_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information)** structure which contains the information about a newly created process and its primary thread. Declaring it's structure in the code.
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

As we can see, the **main()** function is shown in the analysis along with the variables and structures decalred.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/ad38b8af-a6e6-4666-8cc5-c04d213eaefb)  

Scroll down and we see the whole code in the form of assembly, here its what happenning -
* The value of lpApplicationName is loaded into rcx,
* The value of lpThreadAttributes is set to NULL
* The value of lpProcessAttributes is set to NULL
* The value of lpCommandLine is set to NULL
* The pointer to lpProcessInformation is set from the variable defined
* The pointer to lpStartupInfo is set from the variable defined
* Other parameters values are set accordingly.
* Then the CreateProcess API is called along with it’s variables.

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

Then we step into the it to see what happens after the **CreateProcessW** is called.  

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/67eaf446-edff-45c5-b144-4e78a95cd3b6)  

We can see that the **[CreateProcessInternalW](https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c.html#a13a0f94b43874ed5a678909bc39cc1ab)** is called from KernelBase.dll which in simple words gets functionality from kernel32.dll and advapi32.dll. Now we step inside CreateProcessInternalW.

![image](https://github.com/Faran-17/Windows-Internals/assets/59355783/8adecf16-f317-4880-a074-e62e5face271)

It is making call to NtCreateUserProcess inside NTDLL. Here is the structure of the API
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
In this section, we will take a look at how we can create a process directly with the Native API **NtCreateUserProcess**. Although this is beyond my skillset, fortunately **[@CaptMeelo](https://twitter.com/CaptMeelo)** created a awesome blog post on how to do it exactly. In this section, I'll just try to explain the method in an easy way. In order to know more about this topics you can read it on the author's website **([HERE](https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html))**. All credits to the creator for this amazing write-up

As we saw the **NtCreateUserProcess** API is where the transition from User mode to Kernel mode happens.

















 



