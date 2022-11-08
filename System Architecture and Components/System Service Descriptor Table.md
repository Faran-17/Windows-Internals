# Summary
In this post, we will try to take a look and understand what System Service Descriptor Table or SSDT is and understand it with WinDbg tool. Also we will take an example of how when and exe is booted and how Ntdll.dll file is called.

**Note -  System Service Descriptor Table is a vast topic and complex to understand but I will try explain to you and understand myself😅😅**

# What is System Service Descriptor Table?
As per the resources, simply is an array of addresses to kernel routines for 32 bit operating systems or an array of relative offsets to the same routines for 64 bit operating systems. SSDT is the first member of the Service Descriptor Table kernel memory structure as shown below.
```CPP
typedef struct tagSERVICE_DESCRIPTOR_TABLE {
    SYSTEM_SERVICE_TABLE nt; //effectively a pointer to Service Dispatch Table (SSDT) itself
    SYSTEM_SERVICE_TABLE win32k;
    SYSTEM_SERVICE_TABLE sst3; //pointer to a memory address that contains how many routines are defined in the table
    SYSTEM_SERVICE_TABLE sst4;
} SERVICE_DESCRIPTOR_TABLE;
```
Well even I didn't understood the definition properly so finding other resources gives a bit more clarity. Here I will explain you with an example. 

Refer the diagram below.

<p align="center">
  <img src="https://user-images.githubusercontent.com/59355783/199767936-d360e825-7cd9-43db-9963-1bde75895578.png">
</p>

Suppose there is a process running called "Notepad.exe" that wants to write data or save file to the disk. For this to happen it will call an API called **[CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)** from the **Kernel32.dll** file which is a type of DLL that exposes majority of the Win32 APIs to the applications. Now we will try to understand how notepad calls Win32 API and where does SSDT stands.

Let's try to dive-in and understand better.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/199940560-f165e7db-84e5-4ed1-9b80-86aed53046d8.png">
</p>

We will continue our previous example, notepad.exe wants to write to the disk so it will call **CreateFileA** API from the **Kernel32.dll** which in turn calls another API internally called **[NtCreateFile](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtCreateFile.html)** which is called from **Ntdll.dll** file which resides in the userland located in This file is located in the System and System32 system directories. The description of the file is NT Layer DLL. It’s essentially a DLL file that contains core NT kernel functions. 

The code of **NtCreateFile** is responsible to make system call i.e **Syscall** or **Sysenter**, after that the **Ntoskrnl.exe** that resides in the kernel space will call the kernel version of the **NtCreateFile** which in fact is same i.e **NtCreateFile** which does the actual work. **Now the SSDT table is used to find out absolute address of the kernel mode version of the NtCreateFile**. Now that we have idea of where does the SSDT table lies in the picture. We can move to how SSDT works and try to understand it more better. Before we move forward, keep the above diagram in mind to get the bigger picture.

### 32-Bit vs 64-Bit
Now we will take a look at how SSDT table works on 32-bit and 64-bit operating systems. First let's take a look at 32-bit system

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200585784-6d01829f-e814-4fe3-9f1d-09219fd7db01.png">
</p>

Here is the digram of SSDT on 32-bit operating system. Recall the syscall from the previous diagram, syscalls and SSDT (KiServiceTable) work togeher as a bridge between userland API calls and their corresponding kernel routines, allowing the kernel to know which routine should be executed for a given syscall that originated in the user space.

The syscall is the index for the kiservicetable table that has an array of pointers to the actual addresses in the kernel routine. For this demonstration, we are only referring to the syscall number, not the actual function. We will take a detail look with an example later on.

Now let's take a look at 64-bit system.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200587366-892e0994-2a2d-4cd1-8c53-e825aa6c0b9b.png">
</p>

Here is diagram of SSDT on 64-bit operating system from the iredteam. SSDT works a little different on 64-bit. SSDT contains relative offsets to kernel routines. In order to get the absolute address for a given offset, the following formula needs to be applied.
```
RoutineAbsoluteAddress = KiServiceTableAddress + (routineOffset >>> 4)
```
In the above formula we can find the absolute address with the sum of KiServiceTable addres and the routine offset of the syscall and perform unsigned right shift. Let's look at how SSDT table looks like with different tools. First is the SSDT view tool

<p alighn="center">
    <img src="https://user-images.githubusercontent.com/59355783/200593422-fa5227a8-89f0-4080-9d37-6fd53728fc22.png">
</p>

The image above is self explanatory if you understood the previous diagrams. The best way to get a detailed look on SSDT is to use WinDbg tool.

Typing👨‍💻 .....

(Be patient, the blog is currently underwork)
