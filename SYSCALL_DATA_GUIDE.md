# How to Retrieve Syscall Data from Hooks

## Quick Answer

You get syscall data from the **function parameters** passed to your hook. Each syscall has different parameters - just read them!

---

## Basic Pattern

```cpp
NTSTATUS NTAPI HkYourSyscall(
    PARAM1 param1,      // ← Read these
    PARAM2 param2,      // ← Read these
    PARAM3 param3       // ← Read these
) {
    // 1. Extract data from parameters
    DbgPrintEx(0, 0, "Param1: %p\n", param1);
    
    // 2. Call original
    YourSyscall_t original = (YourSyscall_t)OrigYourSyscall;
    return original(param1, param2, param3);
}
```

---

## Example 1: Get Filename from NtCreateFile

```cpp
NTSTATUS NTAPI HkNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,  // ← Contains filename!
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    // Check if pointer is valid
    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        
        // Get filename as UNICODE_STRING
        PUNICODE_STRING filename = ObjectAttributes->ObjectName;
        
        DbgPrintEx(0, 0, "[FILE] Create: %wZ\n", filename);
        DbgPrintEx(0, 0, "[FILE] Length: %u bytes\n", filename->Length);
        DbgPrintEx(0, 0, "[FILE] Access: 0x%lx\n", DesiredAccess);
        DbgPrintEx(0, 0, "[FILE] Disposition: %lu\n", CreateDisposition);
    }
    
    // Call original
    NtCreateFile_t original = (NtCreateFile_t)OrigNtCreateFile;
    return original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                   AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                   CreateOptions, EaBuffer, EaLength);
}
```

**Output:**
```
[FILE] Create: \??\C:\Users\test\document.txt
[FILE] Length: 62 bytes
[FILE] Access: 0x120116
[FILE] Disposition: 1
```

---

## Example 2: Get Process ID from NtOpenProcess

```cpp
NTSTATUS NTAPI HkNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId  // ← Contains PID!
) {
    if (ClientId && ClientId->UniqueProcess) {
        
        HANDLE targetPid = ClientId->UniqueProcess;
        
        DbgPrintEx(0, 0, "[PROC] OpenProcess PID: %llu\n", (ULONG64)targetPid);
        DbgPrintEx(0, 0, "[PROC] Access requested: 0x%lx\n", DesiredAccess);
        
        // Get process name from PID
        PEPROCESS process = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(targetPid, &process))) {
            PUCHAR processName = (PUCHAR)PsGetProcessImageFileName(process);
            DbgPrintEx(0, 0, "[PROC] Target: %s\n", processName);
            ObDereferenceObject(process);
        }
    }
    
    NtOpenProcess_t original = (NtOpenProcess_t)OrigNtOpenProcess;
    return original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
```

**Output:**
```
[PROC] OpenProcess PID: 1234
[PROC] Access requested: 0x1000
[PROC] Target: notepad.exe
```

---

## Example 3: Get Memory Address from NtReadVirtualMemory

```cpp
NTSTATUS NTAPI HkNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,      // ← Address being read
    PVOID Buffer,           // ← Where data goes
    SIZE_T BufferSize,      // ← How much to read
    PSIZE_T NumberOfBytesRead
) {
    DbgPrintEx(0, 0, "[MEM] ReadVirtualMemory\n");
    DbgPrintEx(0, 0, "[MEM] Address: %p\n", BaseAddress);
    DbgPrintEx(0, 0, "[MEM] Size: %llu bytes\n", (ULONG64)BufferSize);
    
    // Get target process info
    PEPROCESS process = NULL;
    if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
        KernelMode, (PVOID*)&process, NULL))) {
        
        HANDLE pid = PsGetProcessId(process);
        PUCHAR processName = (PUCHAR)PsGetProcessImageFileName(process);
        
        DbgPrintEx(0, 0, "[MEM] Target PID: %llu (%s)\n", 
            (ULONG64)pid, processName);
        
        ObDereferenceObject(process);
    }
    
    // Call original
    NtReadVirtualMemory_t original = (NtReadVirtualMemory_t)OrigNtReadVirtualMemory;
    NTSTATUS status = original(ProcessHandle, BaseAddress, Buffer, 
                               BufferSize, NumberOfBytesRead);
    
    // After call - check how much was actually read
    if (NT_SUCCESS(status) && NumberOfBytesRead) {
        DbgPrintEx(0, 0, "[MEM] Actually read: %llu bytes\n", 
            (ULONG64)*NumberOfBytesRead);
    }
    
    return status;
}
```

**Output:**
```
[MEM] ReadVirtualMemory
[MEM] Address: 0x7FF6A2B10000
[MEM] Size: 4096 bytes
[MEM] Target PID: 5678 (game.exe)
[MEM] Actually read: 4096 bytes
```

---

## Example 4: Inspect Buffer Data from NtWriteVirtualMemory

```cpp
NTSTATUS NTAPI HkNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,           // ← Contains data being written
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
) {
    DbgPrintEx(0, 0, "[MEM] WriteVirtualMemory to %p\n", BaseAddress);
    
    // Read first few bytes of buffer (be careful with size!)
    if (Buffer && BufferSize >= 4) {
        __try {
            ULONG firstDword = *(ULONG*)Buffer;
            DbgPrintEx(0, 0, "[MEM] First 4 bytes: 0x%08lx\n", firstDword);
            
            // Check for suspicious patterns (shellcode, hooks, etc.)
            if (firstDword == 0x90909090) {  // NOP sled
                DbgPrintEx(0, 0, "[MEM] ⚠️ WARNING: NOP sled detected!\n");
            }
            if ((firstDword & 0xFFFF) == 0x25FF) {  // jmp [rip+...]
                DbgPrintEx(0, 0, "[MEM] ⚠️ WARNING: Hook pattern detected!\n");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(0, 0, "[MEM] Failed to read buffer\n");
        }
    }
    
    NtWriteVirtualMemory_t original = (NtWriteVirtualMemory_t)OrigNtWriteVirtualMemory;
    return original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}
```

---

## Example 5: Get Registry Key Path

```cpp
NTSTATUS NTAPI HkNtSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,  // ← Registry value name
    ULONG TitleIndex,
    ULONG Type,                 // ← REG_SZ, REG_DWORD, etc.
    PVOID Data,                 // ← The data being written
    ULONG DataSize
) {
    if (ValueName) {
        DbgPrintEx(0, 0, "[REG] SetValueKey: %wZ\n", ValueName);
        DbgPrintEx(0, 0, "[REG] Type: %lu\n", Type);
        DbgPrintEx(0, 0, "[REG] DataSize: %lu bytes\n", DataSize);
        
        // Get full key path from handle
        POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, 'Reg ');
        
        if (nameInfo) {
            ULONG returnLen = 0;
            if (NT_SUCCESS(ObQueryNameString(KeyHandle, nameInfo, 1024, &returnLen))) {
                DbgPrintEx(0, 0, "[REG] Key path: %wZ\n", &nameInfo->Name);
            }
            ExFreePoolWithTag(nameInfo, 'Reg ');
        }
        
        // Print data based on type
        if (Data && DataSize > 0) {
            if (Type == REG_DWORD && DataSize == 4) {
                ULONG value = *(ULONG*)Data;
                DbgPrintEx(0, 0, "[REG] DWORD value: %lu (0x%lx)\n", value, value);
            }
            else if (Type == REG_SZ && DataSize >= 2) {
                DbgPrintEx(0, 0, "[REG] String value: %S\n", (PWCHAR)Data);
            }
        }
    }
    
    NtSetValueKey_t original = (NtSetValueKey_t)OrigNtSetValueKey;
    return original(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}
```

**Output:**
```
[REG] SetValueKey: TestValue
[REG] Type: 4 (REG_DWORD)
[REG] DataSize: 4 bytes
[REG] Key path: \REGISTRY\MACHINE\SOFTWARE\Test
[REG] DWORD value: 1234 (0x4d2)
```

---

## Example 6: Get Thread Context

```cpp
NTSTATUS NTAPI HkNtCreateThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,     // ← CPU registers!
    PVOID InitialTeb,
    BOOLEAN CreateSuspended
) {
    DbgPrintEx(0, 0, "[THREAD] CreateThread\n");
    
    if (ThreadContext) {
        DbgPrintEx(0, 0, "[THREAD] Start RIP: %p\n", (PVOID)ThreadContext->Rip);
        DbgPrintEx(0, 0, "[THREAD] RCX: %llx\n", ThreadContext->Rcx);
        DbgPrintEx(0, 0, "[THREAD] RDX: %llx\n", ThreadContext->Rdx);
        DbgPrintEx(0, 0, "[THREAD] R8: %llx\n", ThreadContext->R8);
        DbgPrintEx(0, 0, "[THREAD] R9: %llx\n", ThreadContext->R9);
    }
    
    DbgPrintEx(0, 0, "[THREAD] Suspended: %s\n", CreateSuspended ? "Yes" : "No");
    
    NtCreateThread_t original = (NtCreateThread_t)OrigNtCreateThread;
    return original(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                   ClientId, ThreadContext, InitialTeb, CreateSuspended);
}
```

---

## Helper Functions for Data Extraction

Add these to your `Ssdt.cpp`:

```cpp
// Get process name from handle
PUCHAR GetProcessNameFromHandle(HANDLE ProcessHandle) {
    PEPROCESS process = NULL;
    if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
        KernelMode, (PVOID*)&process, NULL))) {
        PUCHAR name = (PUCHAR)PsGetProcessImageFileName(process);
        ObDereferenceObject(process);
        return name;
    }
    return (PUCHAR)"Unknown";
}

// Get PID from handle
HANDLE GetPidFromHandle(HANDLE ProcessHandle) {
    PEPROCESS process = NULL;
    if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
        KernelMode, (PVOID*)&process, NULL))) {
        HANDLE pid = PsGetProcessId(process);
        ObDereferenceObject(process);
        return pid;
    }
    return NULL;
}

// Get filename from file handle
BOOLEAN GetFilenameFromHandle(HANDLE FileHandle, PUNICODE_STRING* OutName) {
    POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, 'File');
    
    if (!nameInfo) return FALSE;
    
    ULONG returnLen = 0;
    NTSTATUS status = ObQueryNameString(FileHandle, nameInfo, 1024, &returnLen);
    
    if (NT_SUCCESS(status)) {
        *OutName = &nameInfo->Name;
        return TRUE;
    }
    
    ExFreePoolWithTag(nameInfo, 'File');
    return FALSE;
}

// Get current process name (who called the syscall)
PUCHAR GetCurrentProcessName() {
    PEPROCESS process = PsGetCurrentProcess();
    return (PUCHAR)PsGetProcessImageFileName(process);
}

// Get current PID
HANDLE GetCurrentPid() {
    return PsGetCurrentProcessId();
}
```

---

## Usage in Hooks

```cpp
NTSTATUS NTAPI HkNtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    // Who is calling?
    PUCHAR callerName = GetCurrentProcessName();
    HANDLE callerPid = GetCurrentPid();
    
    // What file?
    PUNICODE_STRING filename = NULL;
    if (GetFilenameFromHandle(FileHandle, &filename)) {
        DbgPrintEx(0, 0, "[%s:%llu] Reading %lu bytes from %wZ\n",
            callerName, (ULONG64)callerPid, Length, filename);
        // Don't forget to free!
        ExFreePoolWithTag(filename, 'File');
    }
    
    NtReadFile_t original = (NtReadFile_t)OrigNtReadFile;
    return original(FileHandle, Event, ApcRoutine, ApcContext,
                   IoStatusBlock, Buffer, Length, ByteOffset, Key);
}
```

**Output:**
```
[notepad.exe:1234] Reading 4096 bytes from \Device\HarddiskVolume3\Windows\System32\test.txt
```

---

## Advanced: Dump Memory Buffer

```cpp
// Hex dump helper
VOID HexDump(PVOID Buffer, SIZE_T Size, SIZE_T MaxBytes) {
    if (!Buffer || Size == 0) return;
    
    SIZE_T bytesToDump = min(Size, MaxBytes);
    PUCHAR bytes = (PUCHAR)Buffer;
    
    __try {
        for (SIZE_T i = 0; i < bytesToDump; i += 16) {
            DbgPrintEx(0, 0, "[%04llx] ", (ULONG64)i);
            
            // Hex
            for (SIZE_T j = 0; j < 16 && (i + j) < bytesToDump; j++) {
                DbgPrintEx(0, 0, "%02x ", bytes[i + j]);
            }
            
            // ASCII
            DbgPrintEx(0, 0, " | ");
            for (SIZE_T j = 0; j < 16 && (i + j) < bytesToDump; j++) {
                UCHAR c = bytes[i + j];
                DbgPrintEx(0, 0, "%c", (c >= 32 && c <= 126) ? c : '.');
            }
            
            DbgPrintEx(0, 0, "\n");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(0, 0, "[HexDump] Access violation\n");
    }
}

// Usage in hook
NTSTATUS NTAPI HkNtWriteVirtualMemory(...) {
    DbgPrintEx(0, 0, "[MEM] Writing to %p:\n", BaseAddress);
    HexDump(Buffer, BufferSize, 64);  // Dump first 64 bytes
    
    // ... call original ...
}
```

**Output:**
```
[MEM] Writing to 0x7FF6A2B10000:
[0000] 48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 48  | H.\$.H.t$.WH.. H
[0010] 8b f2 48 8b d9 48 85 d2 74 15 48 8b 01 48 85 c0  | ..H..H..t.H..H..
[0020] 74 0c 48 8b 4b 08 48 8b 54 24 30 ff d0 48 8b 5c  | t.H.K.H.T$0..H.\
[0030] 24 30 48 8b 74 24 38 48 83 c4 20 5f c3 cc cc cc  | $0H.t$8H.. _....
```

---

## Saving Data to File (Optional)

```cpp
// Save syscall log to file
VOID LogToFile(PCSTR Format, ...) {
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING filePath;
    
    RtlInitUnicodeString(&filePath, L"\\??\\C:\\syscall_log.txt");
    InitializeObjectAttributes(&objAttr, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                              NULL, NULL);
    
    NTSTATUS status = ZwCreateFile(&fileHandle, FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0,
        FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    
    if (NT_SUCCESS(status)) {
        CHAR buffer[512];
        va_list args;
        va_start(args, Format);
        RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
        va_end(args);
        
        ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus,
                   buffer, (ULONG)strlen(buffer), NULL, NULL);
        ZwClose(fileHandle);
    }
}
```

---

## Summary: Quick Reference

| Syscall | Key Parameters | What to Extract |
|---------|---------------|-----------------|
| **NtCreateFile** | ObjectAttributes | `ObjectAttributes->ObjectName` = filename |
| **NtReadFile** | FileHandle, Length | Handle→filename, bytes to read |
| **NtWriteFile** | FileHandle, Buffer | Handle→filename, data being written |
| **NtOpenProcess** | ClientId | `ClientId->UniqueProcess` = PID |
| **NtTerminateProcess** | ProcessHandle | Handle→PID→process name |
| **NtReadVirtualMemory** | ProcessHandle, BaseAddress, BufferSize | Handle→PID, address, size |
| **NtWriteVirtualMemory** | ProcessHandle, BaseAddress, Buffer | Handle→PID, address, data |
| **NtCreateThread** | ProcessHandle, ThreadContext | Handle→PID, `ThreadContext->Rip` = start address |
| **NtSetValueKey** | KeyHandle, ValueName, Data | Handle→key path, value name, data |

---

## Best Practices

✅ **Always check pointers for NULL**
```cpp
if (ObjectAttributes && ObjectAttributes->ObjectName) {
    // Safe to use
}
```

✅ **Use __try/__except for user-mode pointers**
```cpp
__try {
    ULONG value = *(ULONG*)UserBuffer;
} __except (EXCEPTION_EXECUTE_HANDLER) {
    // Handle error
}
```

✅ **Don't forget to dereference objects**
```cpp
ObReferenceObjectByHandle(..., &process, ...);
// Use process
ObDereferenceObject(process);  // ← Important!
```

✅ **Be careful with IRQL**
```cpp
// At DISPATCH_LEVEL or higher, you can't:
// - Allocate paged pool
// - Access paged memory
// - Wait for events
```

✅ **Don't log too much (performance!)**
```cpp
// Bad: Log EVERY file operation (thousands per second)
// Good: Log specific files or processes
if (strcmp(processName, "target.exe") == 0) {
    // Only log this process
}
```

---

Need specific examples for other syscalls? Just ask!
