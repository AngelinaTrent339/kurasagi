/*
 * @file SyscallTracer.cpp
 * @brief Full syscall tracing for AC reversing - ALL the intel you need
 */

#include "SyscallTracer.hpp"
#include "InlineHook.hpp"
#include "../Log.hpp"
#include "../Util/StackWalker.hpp"
#include "../Util/Memory.hpp"

using namespace wsbp;

// Trampolines for all syscalls
static PVOID g_NtReadVirtualMemoryTrampoline = NULL;
static PVOID g_NtQueryVirtualMemoryTrampoline = NULL;
static PVOID g_NtQueryInformationProcessTrampoline = NULL;
static PVOID g_NtOpenProcessTrampoline = NULL;
static PVOID g_NtProtectVirtualMemoryTrampoline = NULL;
static PVOID g_NtQuerySystemInformationTrampoline = NULL;

// Hook structures
static wsbp::InlineHook::Hook g_ReadVMHook = {0};
static wsbp::InlineHook::Hook g_QueryVMHook = {0};
static wsbp::InlineHook::Hook g_QueryProcHook = {0};
static wsbp::InlineHook::Hook g_OpenProcHook = {0};
static wsbp::InlineHook::Hook g_ProtectVMHook = {0};
static wsbp::InlineHook::Hook g_QuerySysHook = {0};

// Helper: Get caller info
static void GetCallerInfo(PEPROCESS Process, PVOID* OutCaller, WCHAR* OutModule, SIZE_T ModuleSize, ULONG_PTR* OutOffset) {
	wsbp::StackWalker::StackFrame frames[16] = {0};
	ULONG count = wsbp::StackWalker::CaptureStack(frames, 16, Process);
	
	for (ULONG i = 0; i < count; i++) {
		if (frames[i].IsUserMode && frames[i].Address) {
			*OutCaller = frames[i].Address;
			if (frames[i].ModuleName[0] != 0) {
				wcsncpy_s(OutModule, ModuleSize / sizeof(WCHAR), frames[i].ModuleName, _TRUNCATE);
				*OutOffset = frames[i].Offset;
			}
			return;
		}
	}
}

// ============================================================================
// NtReadVirtualMemory Hook - AC reading memory for signatures
// ============================================================================
NTSTATUS NTAPI HkNtReadVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead
) {
	PEPROCESS process = PsGetCurrentProcess();
	HANDLE pid = PsGetCurrentProcessId();
	HANDLE tid = PsGetCurrentThreadId();
	
	char procName[16] = {0};
	__try {
		RtlCopyMemory(procName, (char*)((ULONG_PTR)process + 0x338), 15);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		strcpy_s(procName, sizeof(procName), "Unknown");
	}
	
	// Call original
	auto orig = (wsbp::SyscallTracer::NtReadVirtualMemory_t)g_NtReadVirtualMemoryTrampoline;
	NTSTATUS status = orig(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
	
	// Log interesting reads (skip self-reads unless large)
	BOOLEAN isSelfRead = (ProcessHandle == (HANDLE)-1 || ProcessHandle == NtCurrentProcess());
	if (NT_SUCCESS(status) && (!isSelfRead || BufferSize >= 0x1000)) {
		PVOID caller = NULL;
		WCHAR callerMod[64] = {0};
		ULONG_PTR callerOff = 0;
		GetCallerInfo(process, &caller, callerMod, sizeof(callerMod), &callerOff);
		
		const char* comment = "";
		if (BufferSize >= 0x100000) comment = " -> Reading large memory region (signature scan?)";
		else if (BufferSize == 2) comment = " -> Reading MZ header?";
		else if ((ULONG_PTR)BaseAddress >= 0xFFFF800000000000) comment = " -> Reading kernel memory!";
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"\n[%p] Syscall NtReadVirtualMemory | TID: %04X | %s (PID:%04X)\n",
			caller, (ULONG)(ULONG_PTR)tid, procName, (ULONG)(ULONG_PTR)pid);
		
		if (callerMod[0]) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"  Caller: %ws+0x%llX%s\n", callerMod, callerOff, comment);
		}
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"  Args:\n");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    ProcessHandle: %p %s\n", ProcessHandle, isSelfRead ? "(SELF)" : "");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    BaseAddress:   %p\n", BaseAddress);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    Buffer:        %p\n", Buffer);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    BufferSize:    0x%llX (%llu bytes)\n", BufferSize, BufferSize);
		
		SIZE_T bytesRead = 0;
		if (NumberOfBytesRead) {
			__try { bytesRead = *NumberOfBytesRead; } __except(EXCEPTION_EXECUTE_HANDLER) {}
		}
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"  Result: 0x%08X - Read 0x%llX bytes\n", status, bytesRead);
		
		// Dump first 64 bytes if small read
		if (NT_SUCCESS(status) && Buffer && bytesRead > 0 && bytesRead <= 256) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Data: ");
			__try {
				UCHAR* data = (UCHAR*)Buffer;
				for (SIZE_T i = 0; i < min(bytesRead, 64); i++) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%02X ", data[i]);
				}
			} __except(EXCEPTION_EXECUTE_HANDLER) {}
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");
		}
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");
	}
	
	return status;
}

// ============================================================================
// NtQueryVirtualMemory Hook - AC scanning memory regions
// ============================================================================
NTSTATUS NTAPI HkNtQueryVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG MemoryInformationClass,
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
) {
	PEPROCESS process = PsGetCurrentProcess();
	HANDLE pid = PsGetCurrentProcessId();
	HANDLE tid = PsGetCurrentThreadId();
	
	char procName[16] = {0};
	__try {
		RtlCopyMemory(procName, (char*)((ULONG_PTR)process + 0x338), 15);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		strcpy_s(procName, sizeof(procName), "Unknown");
	}
	
	auto orig = (wsbp::SyscallTracer::NtQueryVirtualMemory_t)g_NtQueryVirtualMemoryTrampoline;
	NTSTATUS status = orig(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	
	// Log all queries
	if (NT_SUCCESS(status)) {
		PVOID caller = NULL;
		WCHAR callerMod[64] = {0};
		ULONG_PTR callerOff = 0;
		GetCallerInfo(process, &caller, callerMod, sizeof(callerMod), &callerOff);
		
		const char* infoClass = "Unknown";
		const char* comment = "";
		switch (MemoryInformationClass) {
			case 0: infoClass = "MemoryBasicInformation"; comment = " -> Scanning memory layout"; break;
			case 1: infoClass = "MemoryWorkingSetInformation"; break;
			case 2: infoClass = "MemoryMappedFilenameInformation"; comment = " -> Getting mapped file name"; break;
			case 3: infoClass = "MemoryRegionInformation"; break;
		}
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"\n[%p] Syscall NtQueryVirtualMemory | TID: %04X | %s (PID:%04X)\n",
			caller, (ULONG)(ULONG_PTR)tid, procName, (ULONG)(ULONG_PTR)pid);
		
		if (callerMod[0]) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"  Caller: %ws+0x%llX%s\n", callerMod, callerOff, comment);
		}
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"  Args:\n");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    ProcessHandle: %p\n", ProcessHandle);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    BaseAddress:   %p\n", BaseAddress);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    InfoClass:     0x%X (%s)\n", MemoryInformationClass, infoClass);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"  Result: 0x%08X\n\n", status);
	}
	
	return status;
}

// ============================================================================
// NtQueryInformationProcess Hook - AC getting process info
// ============================================================================
NTSTATUS NTAPI HkNtQueryInformationProcess(
	HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
) {
	PEPROCESS process = PsGetCurrentProcess();
	HANDLE pid = PsGetCurrentProcessId();
	HANDLE tid = PsGetCurrentThreadId();
	
	char procName[16] = {0};
	__try {
		RtlCopyMemory(procName, (char*)((ULONG_PTR)process + 0x338), 15);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		strcpy_s(procName, sizeof(procName), "Unknown");
	}
	
	auto orig = (wsbp::SyscallTracer::NtQueryInformationProcess_t)g_NtQueryInformationProcessTrampoline;
	NTSTATUS status = orig(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	
	if (NT_SUCCESS(status)) {
		PVOID caller = NULL;
		WCHAR callerMod[64] = {0};
		ULONG_PTR callerOff = 0;
		GetCallerInfo(process, &caller, callerMod, sizeof(callerMod), &callerOff);
		
		const char* infoClass = "Unknown";
		const char* comment = "";
		switch (ProcessInformationClass) {
			case 0: infoClass = "ProcessBasicInformation"; break;
			case 7: infoClass = "ProcessDebugPort"; comment = " -> Checking for debugger!"; break;
			case 18: infoClass = "ProcessImageFileName"; break;
			case 22: infoClass = "ProcessBreakOnTermination"; break;
			case 30: infoClass = "ProcessDebugObjectHandle"; comment = " -> Debug detection!"; break;
			case 31: infoClass = "ProcessDebugFlags"; comment = " -> Debug detection!"; break;
		}
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"\n[%p] Syscall NtQueryInformationProcess | TID: %04X | %s (PID:%04X)\n",
			caller, (ULONG)(ULONG_PTR)tid, procName, (ULONG)(ULONG_PTR)pid);
		
		if (callerMod[0]) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"  Caller: %ws+0x%llX%s\n", callerMod, callerOff, comment);
		}
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"  Args:\n");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    ProcessHandle: %p\n", ProcessHandle);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"    InfoClass:     0x%X (%s)\n", ProcessInformationClass, infoClass);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
			"  Result: 0x%08X\n\n", status);
	}
	
	return status;
}

// ============================================================================
// Initialize all hooks
// ============================================================================
BOOLEAN wsbp::SyscallTracer::InitializeTracer() {
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
		"[Kurasagi] Initializing comprehensive syscall tracer...\n");
	
	// Get function addresses
	UNICODE_STRING ntReadVM = RTL_CONSTANT_STRING(L"NtReadVirtualMemory");
	UNICODE_STRING ntQueryVM = RTL_CONSTANT_STRING(L"NtQueryVirtualMemory");
	UNICODE_STRING ntQueryProc = RTL_CONSTANT_STRING(L"NtQueryInformationProcess");
	
	PVOID pNtReadVM = MmGetSystemRoutineAddress(&ntReadVM);
	PVOID pNtQueryVM = MmGetSystemRoutineAddress(&ntQueryVM);
	PVOID pNtQueryProc = MmGetSystemRoutineAddress(&ntQueryProc);
	
	if (!pNtReadVM || !pNtQueryVM || !pNtQueryProc) {
		LogError("Failed to resolve syscall addresses");
		return FALSE;
	}
	
	// Install hooks
	BOOLEAN success = TRUE;
	
	if (!InlineHook::InstallHook(pNtReadVM, (PVOID)HkNtReadVirtualMemory, &g_ReadVMHook)) {
		LogError("Failed to hook NtReadVirtualMemory");
		success = FALSE;
	} else {
		g_NtReadVirtualMemoryTrampoline = ExAllocatePoolWithTag(NonPagedPool, 64, 'tRTN');
		if (g_NtReadVirtualMemoryTrampoline) {
			RtlCopyMemory(g_NtReadVirtualMemoryTrampoline, g_ReadVMHook.OriginalBytes, 14);
			UCHAR* jmp = (UCHAR*)g_NtReadVirtualMemoryTrampoline + 14;
			jmp[0] = 0xFF; jmp[1] = 0x25; *(ULONG*)&jmp[2] = 0;
			*(PVOID*)&jmp[6] = (PVOID)((ULONG_PTR)pNtReadVM + 14);
		}
	}
	
	if (!InlineHook::InstallHook(pNtQueryVM, (PVOID)HkNtQueryVirtualMemory, &g_QueryVMHook)) {
		LogError("Failed to hook NtQueryVirtualMemory");
		success = FALSE;
	} else {
		g_NtQueryVirtualMemoryTrampoline = ExAllocatePoolWithTag(NonPagedPool, 64, 'tQVN');
		if (g_NtQueryVirtualMemoryTrampoline) {
			RtlCopyMemory(g_NtQueryVirtualMemoryTrampoline, g_QueryVMHook.OriginalBytes, 14);
			UCHAR* jmp = (UCHAR*)g_NtQueryVirtualMemoryTrampoline + 14;
			jmp[0] = 0xFF; jmp[1] = 0x25; *(ULONG*)&jmp[2] = 0;
			*(PVOID*)&jmp[6] = (PVOID)((ULONG_PTR)pNtQueryVM + 14);
		}
	}
	
	if (!InlineHook::InstallHook(pNtQueryProc, (PVOID)HkNtQueryInformationProcess, &g_QueryProcHook)) {
		LogError("Failed to hook NtQueryInformationProcess");
		success = FALSE;
	} else {
		g_NtQueryInformationProcessTrampoline = ExAllocatePoolWithTag(NonPagedPool, 64, 'tQPN');
		if (g_NtQueryInformationProcessTrampoline) {
			RtlCopyMemory(g_NtQueryInformationProcessTrampoline, g_QueryProcHook.OriginalBytes, 14);
			UCHAR* jmp = (UCHAR*)g_NtQueryInformationProcessTrampoline + 14;
			jmp[0] = 0xFF; jmp[1] = 0x25; *(ULONG*)&jmp[2] = 0;
			*(PVOID*)&jmp[6] = (PVOID)((ULONG_PTR)pNtQueryProc + 14);
		}
	}
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
		"[Kurasagi] Syscall tracer ready - ALL AC behavior will be logged!\n");
	
	return success;
}

VOID wsbp::SyscallTracer::ShutdownTracer() {
	if (g_NtReadVirtualMemoryTrampoline) ExFreePoolWithTag(g_NtReadVirtualMemoryTrampoline, 'tRTN');
	if (g_NtQueryVirtualMemoryTrampoline) ExFreePoolWithTag(g_NtQueryVirtualMemoryTrampoline, 'tQVN');
	if (g_NtQueryInformationProcessTrampoline) ExFreePoolWithTag(g_NtQueryInformationProcessTrampoline, 'tQPN');
}
