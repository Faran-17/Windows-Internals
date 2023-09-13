// Blog link - https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/Creation%20Of%20Process.md

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
