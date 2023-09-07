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
* 




