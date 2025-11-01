/*
 * @file SsdtReference.hpp
 * @brief Common syscall function signatures for hooking
 * 
 * Use FindSyscallIndex() to get the correct index for your Windows version
 * All functions are NTAPI calling convention
 */

#pragma once
#include "../Include.hpp"

// ============================================================================
// FILE OPERATIONS
// ============================================================================

typedef NTSTATUS(NTAPI* NtCreateFile_t)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
);

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

typedef NTSTATUS(NTAPI* NtWriteFile_t)(
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

typedef NTSTATUS(NTAPI* NtDeleteFile_t)(
	POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS(NTAPI* NtQueryInformationFile_t)(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass
);

// ============================================================================
// PROCESS OPERATIONS
// ============================================================================

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
);

typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(
	HANDLE ProcessHandle,
	NTSTATUS ExitStatus
);

typedef NTSTATUS(NTAPI* NtSuspendProcess_t)(
	HANDLE ProcessHandle
);

typedef NTSTATUS(NTAPI* NtResumeProcess_t)(
	HANDLE ProcessHandle
);

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

// ============================================================================
// THREAD OPERATIONS
// ============================================================================

typedef NTSTATUS(NTAPI* NtCreateThread_t)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PCLIENT_ID ClientId,
	PCONTEXT ThreadContext,
	PVOID InitialTeb,
	BOOLEAN CreateSuspended
);

typedef NTSTATUS(NTAPI* NtOpenThread_t)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
);

typedef NTSTATUS(NTAPI* NtTerminateThread_t)(
	HANDLE ThreadHandle,
	NTSTATUS ExitStatus
);

typedef NTSTATUS(NTAPI* NtSuspendThread_t)(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
);

typedef NTSTATUS(NTAPI* NtResumeThread_t)(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
);

// ============================================================================
// MEMORY OPERATIONS
// ============================================================================

typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG FreeType
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
);

// ============================================================================
// REGISTRY OPERATIONS
// ============================================================================

typedef NTSTATUS(NTAPI* NtCreateKey_t)(
	PHANDLE KeyHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG TitleIndex,
	PUNICODE_STRING Class,
	ULONG CreateOptions,
	PULONG Disposition
);

typedef NTSTATUS(NTAPI* NtOpenKey_t)(
	PHANDLE KeyHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS(NTAPI* NtSetValueKey_t)(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName,
	ULONG TitleIndex,
	ULONG Type,
	PVOID Data,
	ULONG DataSize
);

typedef NTSTATUS(NTAPI* NtQueryValueKey_t)(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID KeyValueInformation,
	ULONG Length,
	PULONG ResultLength
);

typedef NTSTATUS(NTAPI* NtDeleteKey_t)(
	HANDLE KeyHandle
);

typedef NTSTATUS(NTAPI* NtDeleteValueKey_t)(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName
);

// ============================================================================
// COMMON FUNCTION NAMES FOR FindSyscallIndex()
// ============================================================================

/*
Usage example:

ULONG index = wsbp::Ssdt::FindSyscallIndex(L"NtCreateFile");
if (index != (ULONG)-1) {
    wsbp::Ssdt::HookSsdtEntry(index, MyHook, &OriginalFunc);
}

Common function names:
- L"NtCreateFile"
- L"NtReadFile"
- L"NtWriteFile"
- L"NtDeleteFile"
- L"NtOpenProcess"
- L"NtTerminateProcess"
- L"NtSuspendProcess"
- L"NtResumeProcess"
- L"NtCreateThread"
- L"NtOpenThread"
- L"NtTerminateThread"
- L"NtReadVirtualMemory"
- L"NtWriteVirtualMemory"
- L"NtAllocateVirtualMemory"
- L"NtFreeVirtualMemory"
- L"NtProtectVirtualMemory"
- L"NtCreateKey"
- L"NtOpenKey"
- L"NtSetValueKey"
- L"NtQueryValueKey"
- L"NtDeleteKey"
*/
