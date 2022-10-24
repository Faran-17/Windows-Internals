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
This will open the Livekd in Windbg
![image](https://user-images.githubusercontent.com/59355783/197510520-e617e202-6cfb-4a26-8ae4-46f6496d7a6c.png)






# Resources
1. ```https://samsclass.info/126/proj/p12-kernel-debug-win10.htm```
