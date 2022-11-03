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
Well even I didn't understood the definition properly so finding other resources gives a bit more clarity. Here I will explain you with and example

Typing👨‍💻 .....

(Be patient, the blog is currently underwork)
