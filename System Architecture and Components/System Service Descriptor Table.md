# Summary
In this post, we will try to take a look and understand what System Service Descriptor Table or SSDT is and understand it with WinDbg tool. Also we will take an example of how when and exe is booted and how Ntdll.dll and Win32 API file is called.

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

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200593422-fa5227a8-89f0-4080-9d37-6fd53728fc22.png">
</p>

The image above is self explanatory if you understood the previous diagrams. The best way to get a detailed look on SSDT is to use WinDbg tool. For this open up WinDbg with LiveKD tool, refer my blog on how to do it [here](https://github.com/Faran-17/Windows-Internals/blob/main/Introduction/Kernel%20Debugging%20with%20LiveKd.md).

First we can check the Service Descriptor Table structure with **KeServiceDescriptorTable**.  Note that the first member is recognized as **KiServiceTable** - this is a pointer to the SSDT itself - the dispatch table (or simply an array) containing all those pointers/offsets.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200810095-8c98589e-3c0c-4f23-bbbf-40f63977f472.png">
</p>

Printing out all the values from the SSDT.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200811050-41cf0f58-537e-4e41-8347-e23de2f34bf8.png">
</p>

As you can see the SSDT displays all the offset to the kernel routine. And all those offsets leads to a Win API with it's absolute address. Even though any of those offset can lead to proper results, for this I will select those two offsets highlighted - **02907a02** and **020e0900**. Using the formula above to get the absolute address.
```
RoutineAbsoluteAddress = KiServiceTableAddress + (routineOffset >>> 4)
```

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200813874-f7e18f84-1d19-4389-92d4-2f670670e1b7.png">
</p>

Using the formula above, we got two API functions name **[NtAcceptConnectPort](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FPort%2FNtConnectPort.html)** and **[NtWatiForSingleObject](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FNtWaitForSingleObject.html)** along with their absolute address. To verify this, we can dissassemble those both function and match the address.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200815995-9b6ab69b-4174-40d8-bd1c-15272d640a93.png">
</p>
    
If you can see the values matches, proving the point. To visualize it in a diagram it will be as follows

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200821536-f4b9f31d-c070-405e-b0c1-805a3b24ac03.png">
</p>

# Example

Now that we've got an idea of how SSDT works and function. We will try to break down an executable in this case notepad.exe to find absolute address of some Win32 API functions. If we refer the figures above you will get an idea of what is happening here. In WinDbg, open the notepad.exe application in the System32 folder.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200825270-b5f3c857-e8f6-4921-a226-35f5c4502839.png">
</p>

When the notepad.exe is about boot-up it loaded the Ntdll.dll file as highlighted. Dissassemble the **NtCreateFile** function.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200825953-6ea7e4c4-0798-4d63-9434-42bb6829b721.png">
</p>

The EAX register is set to 55h(0x0055) which is the system service number for the Windows 10 x64 and the **syscall** is called at 0x55 as we know causes the processor to transition into the kernel mode. Now if we check the SSDT and it's offset at index 0x55. To dive into the SSDT first open WinDbg with LiveKD as before.

```
0: kd> dd /c1 kiservicetable+4*0x55 L1
fffff806`5e0a1374  01da3d07
```

We have the offset **01da3d07**, now we can get the absolute address using the forumla from before.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200829301-25cb779c-029d-43d0-97d8-2d149ef9e82a.png">
</p>

We get the absolute memory address of the **NtCreateFile** function. Here is how we can define it in the form of diagram.

<p align="center">
    <img src="https://user-images.githubusercontent.com/59355783/200848321-9f220741-d8fe-44f9-84ce-bf2089b681da.png">
</p>    

We can also use a for-loop command to display Win32 API names along with their associated absolute address.

```
0: kd> .foreach /ps 1 /pS 1 ( offset {dd /c 1 nt!KiServiceTable L poi(nt!KeServiceDescriptorTable+10)}){ r $t0 = ( offset >>> 4) + nt!KiServiceTable; .printf "%p - %y\n", $t0, $t0 }
fffff8066ddabde0 - fffff806`6ddabde0
fffff8066ddb3390 - fffff806`6ddb3390
fffff8065e3319c0 - nt!NtAcceptConnectPort (fffff806`5e3319c0)
fffff8065e4f7980 - nt!NtMapUserPhysicalPagesScatter (fffff806`5e4f7980)
fffff8065e2af2b0 - nt!NtWaitForSingleObject (fffff806`5e2af2b0)
fffff8066de61e50 - fffff806`6de61e50
fffff8065e34a550 - nt!NtReadFile (fffff806`5e34a550)
fffff8065e2c05f0 - nt!NtDeviceIoControlFile (fffff806`5e2c05f0)
fffff8065e252e40 - nt!NtWriteFile (fffff806`5e252e40)
fffff8065e302ff0 - nt!NtRemoveIoCompletion (fffff806`5e302ff0)
```

Hope this clears the concept.

# Why SSDT are important?
1. In 32-bit versions, malware developers develop malwares that run in Kernel mode i.e rootkit that modify entries in either the **nt!KiServiceTable** or the **win32k!W32pServiceTable** diverting System calls to their own code in order to cause troubles. Not only malwares but many security products like Anti-virus used to hook the SSDTs as well in order to receive an immediate alert on virus attacks.
2. However, 64-bit versions introduced a strong protection feature called Kernel Patch Protection (generally known by the term PatchGuard). PatchGuard makes periodic checks to make sure that a certain number of critical System structures, including the SSDTs, were not modified in the meantime. Security software, namely antivirus, was forced to search for less efficient alternatives. Authors of Rootkits suffered a violent backlash but not a complete defeat - from time to time, they come up with new but short-lived ways to bypass the PatchGuard.

### Closing thoughts
Hope you all understand what happens when applications like notepad access Win32 APIs from the kernel and SSDT knows exactly the address of the following function and where to call it from. This logic happens in all applications where they interact with Win32 APIs.

**Hope you liked it, stay tuned for more😃**

# Resources
1. https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/glimpse-into-ssdt-in-windows-x64-kernel
2. https://www.codeproject.com/Articles/1191465/The-Quest-for-the-SSDTs
3. https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools
4. https://www.novirusthanks.org/products/ssdt-view/

