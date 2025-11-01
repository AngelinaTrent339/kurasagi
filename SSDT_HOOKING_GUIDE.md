# SSDT Hooking Guide for Kurasagi

## What is SSDT?

SSDT (System Service Descriptor Table) is a kernel table that contains pointers to Windows kernel functions (syscalls). When a user-mode program calls functions like `CreateFile`, `OpenProcess`, etc., they eventually go through SSDT.

## How It Works

### 1. Architecture

```
User Mode Program
    ↓ (syscall instruction)
Kernel Mode (ntoskrnl.exe)
    ↓ (looks up SSDT)
KeServiceDescriptorTable
    ↓ (dispatches to function)
NtCreateFile / NtOpenProcess / etc.
```

### 2. SSDT Structure on x64

On 64-bit Windows, SSDT entries are **NOT direct pointers**. They're encoded as 32-bit offsets:

```cpp
// SSDT entry format (32-bit value):
// Bits 31-4: Offset from ServiceTableBase (divided by 16)
// Bits 3-0:  Parameter count

ActualFunction = ServiceTableBase + ((Entry >> 4) << 4)
```

### 3. Hooking Process

1. **Find KeServiceDescriptorTable** - Pattern scan in ntoskrnl.exe
2. **Calculate function address** - Decode SSDT entry
3. **Create new entry** - Encode your hook address
4. **Write using MDL** - Bypass read-only protection
5. **Hook is active** - Syscalls now go through your function

## Usage Instructions

### Step 1: Find Syscall Number

You need to know the syscall number (index) you want to hook. Common ones:

| Syscall Name | Index (Win 11 24H2) | Description |
|--------------|---------------------|-------------|
| NtCreateFile | 0x55 | File creation/opening |
| NtOpenProcess | 0x26 | Process handle opening |
| NtReadFile | 0x06 | File reading |
| NtWriteFile | 0x08 | File writing |
| NtCreateThread | 0x4E | Thread creation |
| NtTerminateProcess | 0x2C | Process termination |

⚠️ **WARNING**: Syscall numbers change between Windows versions!

**How to find the correct number for your Windows version:**

#### Method 1: Use WinDbg
```
kd> x nt!*NtCreateFile
fffff805`12345678 nt!NtCreateFile

kd> ? nt!KeServiceDescriptorTable
Evaluate expression: 18446735277718233600 = fffff805`12341100

kd> dd fffff805`12341100 L1
fffff805`12341100  aaaabbbb  <- This is ServiceTableBase

kd> dd aaaabbbb L100
[Find your function offset]
```

#### Method 2: Use Online Resources
- https://j00ru.vexillium.org/syscalls/nt/64/
- Check your exact Windows build number

#### Method 3: Use Code (Easier!)
```cpp
// Add this function to Ssdt.cpp:
ULONG FindSyscallNumber(const char* functionName) {
    UNICODE_STRING unicodeName;
    RtlInitUnicodeString(&unicodeName, functionName);
    
    PVOID targetAddress = MmGetSystemRoutineAddress(&unicodeName);
    
    for (ULONG i = 0; i < g_KeServiceDescriptorTable->NumberOfServices; i++) {
        if (GetSsdtFunctionAddress(i) == targetAddress) {
            return i;
        }
    }
    return (ULONG)-1;
}

// Usage:
ULONG ntCreateFileIndex = FindSyscallNumber(L"NtCreateFile");
LogInfo("NtCreateFile index: 0x%x", ntCreateFileIndex);
```

### Step 2: Create Your Hook Function

Your hook function MUST have the **exact same signature** as the original:

```cpp
// Example: Hook NtReadFile
typedef NTSTATUS(NTAPI* NtReadFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

PVOID OrigNtReadFile = NULL;

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
    // Your code here - log, filter, modify parameters, etc.
    LogInfo("NtReadFile: Reading %lu bytes from handle %p", Length, FileHandle);
    
    // IMPORTANT: Always call the original function!
    NtReadFile_t original = (NtReadFile_t)OrigNtReadFile;
    return original(
        FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key
    );
}
```

### Step 3: Install the Hook

```cpp
// In DriverEntry or wherever:
if (wsbp::Ssdt::HookSsdtEntry(0x06, HkNtReadFile, &OrigNtReadFile)) {
    LogInfo("NtReadFile hooked successfully!");
}
```

### Step 4: Unhook When Unloading (Optional)

```cpp
// In driver unload:
if (OrigNtReadFile) {
    wsbp::Ssdt::UnhookSsdtEntry(0x06, OrigNtReadFile);
}
```

## Examples

### Example 1: Block Specific File Access

```cpp
NTSTATUS NTAPI HkNtCreateFile(...) {
    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        UNICODE_STRING blockedFile;
        RtlInitUnicodeString(&blockedFile, L"\\??\\C:\\Windows\\System32\\secret.txt");
        
        if (RtlEqualUnicodeString(ObjectAttributes->ObjectName, &blockedFile, TRUE)) {
            LogInfo("Blocked access to secret.txt!");
            return STATUS_ACCESS_DENIED;
        }
    }
    
    // Allow other files
    NtCreateFile_t original = (NtCreateFile_t)OrigNtCreateFile;
    return original(...);
}
```

### Example 2: Protect Process from Termination

```cpp
NTSTATUS NTAPI HkNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    // Get PID from handle
    PEPROCESS process;
    if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, &process, NULL))) {
        HANDLE protectedPid = PsGetProcessId(process);
        ObDereferenceObject(process);
        
        // Protect PID 1234
        if (protectedPid == (HANDLE)1234) {
            LogInfo("Blocked termination of protected process!");
            return STATUS_ACCESS_DENIED;
        }
    }
    
    // Allow other processes
    NtTerminateProcess_t original = (NtTerminateProcess_t)OrigNtTerminateProcess;
    return original(ProcessHandle, ExitStatus);
}
```

### Example 3: Log All File Operations

```cpp
NTSTATUS NTAPI HkNtReadFile(...) {
    // Get filename from handle
    POBJECT_NAME_INFORMATION nameInfo = ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, 'File');
    if (nameInfo) {
        if (NT_SUCCESS(ObQueryNameString(FileHandle, nameInfo, 1024, NULL))) {
            LogInfo("Reading: %wZ", &nameInfo->Name);
        }
        ExFreePoolWithTag(nameInfo, 'File');
    }
    
    NtReadFile_t original = (NtReadFile_t)OrigNtReadFile;
    return original(...);
}
```

## Testing

### How to Test Your Hooks

1. **Build the driver** (use your existing build method)
2. **Load with kdmapper** (as mentioned in README)
3. **Check DbgView** for log messages
4. **Trigger syscalls**:
   - Open Notepad (triggers NtCreateFile)
   - Open Task Manager (triggers NtOpenProcess)
   - Any file operation will show in logs

### Debugging

If hooks don't work:

1. **Check KeServiceDescriptorTable address**:
   ```
   LogInfo("SSDT Base: %p", g_KeServiceDescriptorTable);
   ```

2. **Verify syscall number**:
   ```cpp
   PVOID addr = GetSsdtFunctionAddress(0x55);
   LogInfo("Index 0x55 points to: %p", addr);
   ```

3. **Check original function is saved**:
   ```cpp
   LogInfo("Original NtCreateFile: %p", OrigNtCreateFile);
   ```

4. **Ensure PatchGuard is bypassed first**!

## Important Notes

⚠️ **Critical Points:**

1. **ALWAYS call the original function** - or system will hang
2. **Check for NULL pointers** - especially in ObjectAttributes
3. **Don't hold locks too long** - you're in critical paths
4. **Be aware of IRQL** - you're often at PASSIVE_LEVEL but not always
5. **Syscall numbers change** - verify for your Windows build
6. **PatchGuard must be bypassed** - do SSDT hooking AFTER bypass

## What You Can Do

✅ **Possible Applications:**

- **File system monitoring** - Track all file operations
- **Process protection** - Prevent termination/access
- **Anti-cheat** - Detect game cheats accessing memory
- **EDR/AV** - Endpoint security monitoring
- **Rootkit detection** - Find hidden processes/files
- **Behavior analysis** - Study malware behavior

❌ **Limitations:**

- Can't hook user-mode functions directly
- Performance impact if hooks are slow
- Syscall numbers are Windows version-specific
- Some syscalls are rarely used (hook popular ones)

## Need Help?

Common syscall indices I can provide:
- ✅ Just ask: "What's the syscall number for NtWriteVirtualMemory?"
- ✅ Or: "How do I hook registry operations?"
- ✅ Or: "Show me how to filter by process name in hooks?"

Let me know what you want to hook and I'll help you write the code!
