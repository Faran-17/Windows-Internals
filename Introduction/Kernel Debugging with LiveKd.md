# Kernel Debugging with LiveKd

Using Windows Sysnternals tool called LiveKd that helps in debugging the Window's kernel structures, modules and etc.

```
https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
```

The LiveKd tool can be used from a cmd or can be attached with WinDbg tool.

# Requirements
1. Sysinternal Suite
```
https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
```
2. Windows 10 VM or baremetal
3. Windbg from the WinSDK packaage
```
https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
```

# Setup
The setup process will be mentioned in the resource section(1)

# Kernel Debugging With LiveKd
Open CMD as admin and type
```
livekd -w
```

![image](https://user-images.githubusercontent.com/59355783/197510520-e617e202-6cfb-4a26-8ae4-46f6496d7a6c.png)

This will open up LiveKd in WinDbg.

## Process

The **```!process```** command will display a specified proccess along with it's details
![image](https://user-images.githubusercontent.com/59355783/197511212-f4d55fa3-1134-4333-b8eb-df0e0ce01702.png)

The above image displays the **windb.exe** process and it's details as highlighted.

The command **```!process 0 0```** will display the details of all the processes running.
![image](https://user-images.githubusercontent.com/59355783/197511812-c74841de-7a30-4514-b72b-f21a0d692aef.png)

The above images displays all the system level processes and their details. Here is the table of processes details(Resource - 2)

Element | Meaning
--- | --- |
Process address | The eight-character hexadecimal number after the word PROCESS is the address of the EPROCESS block. In the final entry in the preceding example, the process address is 0x809258E0.
Process ID (PID) | The hexadecimal number after the word Cid. In the final entry in the preceding example, the PID is 0x44, or decimal 68.
Process Environment Block (PEB) | The hexadecimal number after the word Peb is the address of the process environment block. In the final entry in the preceding example, the PEB is located at address 0x7FFDE000.
Parent process PID | The hexadecimal number after the word ParentCid is the PID of the parent process. In the final entry in the preceding example, the parent process PID is 0x26, or decimal 38.

To get a details of a particular process use the command **```!process ffffb00f40b1c4c0 7```** with the process number and the 0x7 Flag/
![image](https://user-images.githubusercontent.com/59355783/197513424-10cab949-cfb4-4b2a-96f4-6fdae1676429.png)

This displays a lot of output for the process **windbg.exe**







# Resources
1. ```https://samsclass.info/126/proj/p12-kernel-debug-win10.htm```
2. ```https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/-process```
3. ```https://samsclass.info/126/proj/PMA410d.htm```
