/*
 * @file Ssdt.cpp
 * @brief Implementation of SSDT hooking module
 */

#include "Ssdt.hpp"
#include "../Log.hpp"
#include "../Global.hpp"
#include "../Util/Memory.hpp"

// Global SSDT pointer
static wsbp::Ssdt::PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_KeServiceDescriptorTable = NULL;

// Original function pointers
PVOID wsbp::Ssdt::OrigNtCreateFile = NULL;
PVOID wsbp::Ssdt::OrigNtOpenProcess = NULL;

BOOLEAN wsbp::Ssdt::InitializeSsdt() {

	// Pattern to find KeServiceDescriptorTable in ntoskrnl.exe
	// The pattern searches for: lea r10, KeServiceDescriptorTable
	const UCHAR KeServiceDescriptorTablePattern[] = {
		0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00  // lea r10, [rip+offset]
	};
	const char KeServiceDescriptorTableMask[] = "xxx????";

	uintptr_t patternAddress = 0;
	if (!PatternSearchNtKernelSection(
		DOTTEXT_SECTION,
		KeServiceDescriptorTablePattern,
		KeServiceDescriptorTableMask,
		&patternAddress)) {

		LogError("InitializeSsdt: Could not find KeServiceDescriptorTable pattern");
		return FALSE;
	}

	// Calculate absolute address from RIP-relative offset
	// Pattern: 4C 8D 15 [XX XX XX XX] (lea r10, [rip+offset])
	// Offset is at patternAddress + 3
	LONG relativeOffset = *(LONG*)(patternAddress + 3);
	uintptr_t nextInstruction = patternAddress + 7; // Size of instruction
	g_KeServiceDescriptorTable = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)(nextInstruction + relativeOffset);

	LogInfo("InitializeSsdt: KeServiceDescriptorTable found at: %p", g_KeServiceDescriptorTable);
	LogInfo("InitializeSsdt: ServiceTableBase: %p", g_KeServiceDescriptorTable->ServiceTableBase);
	LogInfo("InitializeSsdt: NumberOfServices: %llu", g_KeServiceDescriptorTable->NumberOfServices);

	return TRUE;
}

PVOID wsbp::Ssdt::GetSsdtFunctionAddress(ULONG ServiceIndex) {

	if (!g_KeServiceDescriptorTable) {
		LogError("GetSsdtFunctionAddress: SSDT not initialized");
		return NULL;
	}

	if (ServiceIndex >= g_KeServiceDescriptorTable->NumberOfServices) {
		LogError("GetSsdtFunctionAddress: Invalid service index %lu", ServiceIndex);
		return NULL;
	}

	// On x64, SSDT entries are encoded as offsets from ServiceTableBase
	// Entry format: (ServiceTableBase[index] >> 4) + ServiceTableBase
	LONG offset = g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex] >> 4;
	PVOID functionAddress = (PVOID)((ULONG_PTR)g_KeServiceDescriptorTable->ServiceTableBase + offset);

	return functionAddress;
}

BOOLEAN wsbp::Ssdt::HookSsdtEntry(ULONG ServiceIndex, PVOID HookFunction, PVOID* OutOriginalFunction) {

	if (!g_KeServiceDescriptorTable) {
		LogError("HookSsdtEntry: SSDT not initialized");
		return FALSE;
	}

	if (ServiceIndex >= g_KeServiceDescriptorTable->NumberOfServices) {
		LogError("HookSsdtEntry: Invalid service index %lu", ServiceIndex);
		return FALSE;
	}

	// Get current function address
	PVOID originalFunction = GetSsdtFunctionAddress(ServiceIndex);
	if (!originalFunction) {
		LogError("HookSsdtEntry: Could not get original function for index %lu", ServiceIndex);
		return FALSE;
	}

	LogInfo("HookSsdtEntry: Original function at index %lu: %p", ServiceIndex, originalFunction);
	LogInfo("HookSsdtEntry: Hook function: %p", HookFunction);

	// Calculate new offset for hook function
	// New offset = (HookFunction - ServiceTableBase) << 4
	LONG_PTR hookOffset = (LONG_PTR)HookFunction - (LONG_PTR)g_KeServiceDescriptorTable->ServiceTableBase;
	ULONG newEntry = (ULONG)(hookOffset << 4);

	// Preserve the lower 4 bits (parameter count) from original entry
	ULONG originalEntry = g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex];
	ULONG parameterCount = originalEntry & 0xF;
	newEntry |= parameterCount;

	// Write the new entry using MDL method
	PVOID entryAddress = &g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex];
	if (!WriteOnReadOnlyMemory(&newEntry, entryAddress, sizeof(ULONG))) {
		LogError("HookSsdtEntry: Failed to write hook entry");
		return FALSE;
	}

	LogInfo("HookSsdtEntry: Successfully hooked index %lu", ServiceIndex);

	// Return original function if requested
	if (OutOriginalFunction) {
		*OutOriginalFunction = originalFunction;
	}

	return TRUE;
}

BOOLEAN wsbp::Ssdt::UnhookSsdtEntry(ULONG ServiceIndex, PVOID OriginalFunction) {

	if (!g_KeServiceDescriptorTable) {
		LogError("UnhookSsdtEntry: SSDT not initialized");
		return FALSE;
	}

	if (ServiceIndex >= g_KeServiceDescriptorTable->NumberOfServices) {
		LogError("UnhookSsdtEntry: Invalid service index %lu", ServiceIndex);
		return FALSE;
	}

	// Calculate original offset
	LONG_PTR originalOffset = (LONG_PTR)OriginalFunction - (LONG_PTR)g_KeServiceDescriptorTable->ServiceTableBase;
	ULONG originalEntry = (ULONG)(originalOffset << 4);

	// Get current entry to preserve parameter count
	ULONG currentEntry = g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex];
	ULONG parameterCount = currentEntry & 0xF;
	originalEntry |= parameterCount;

	// Restore original entry
	PVOID entryAddress = &g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex];
	if (!WriteOnReadOnlyMemory(&originalEntry, entryAddress, sizeof(ULONG))) {
		LogError("UnhookSsdtEntry: Failed to restore original entry");
		return FALSE;
	}

	LogInfo("UnhookSsdtEntry: Successfully unhooked index %lu", ServiceIndex);
	return TRUE;
}

VOID wsbp::Ssdt::PrintSsdtInfo() {

	if (!g_KeServiceDescriptorTable) {
		LogError("PrintSsdtInfo: SSDT not initialized");
		return;
	}

	LogInfo("=== SSDT Information ===");
	LogInfo("KeServiceDescriptorTable: %p", g_KeServiceDescriptorTable);
	LogInfo("ServiceTableBase: %p", g_KeServiceDescriptorTable->ServiceTableBase);
	LogInfo("NumberOfServices: %llu", g_KeServiceDescriptorTable->NumberOfServices);
	LogInfo("ParamTableBase: %p", g_KeServiceDescriptorTable->ParamTableBase);

	// Print first 10 entries as examples
	LogInfo("=== First 10 SSDT Entries ===");
	for (ULONG i = 0; i < 10 && i < g_KeServiceDescriptorTable->NumberOfServices; i++) {
		PVOID funcAddr = GetSsdtFunctionAddress(i);
		LogInfo("Index %lu: %p", i, funcAddr);
	}
}

ULONG wsbp::Ssdt::FindSyscallIndex(PCWSTR FunctionName) {

	if (!g_KeServiceDescriptorTable) {
		LogError("FindSyscallIndex: SSDT not initialized");
		return (ULONG)-1;
	}

	// Get the function address by name
	UNICODE_STRING unicodeName;
	RtlInitUnicodeString(&unicodeName, FunctionName);
	
	PVOID targetAddress = MmGetSystemRoutineAddress(&unicodeName);
	if (!targetAddress) {
		LogError("FindSyscallIndex: Could not find function %wZ", &unicodeName);
		return (ULONG)-1;
	}

	LogVerbose("FindSyscallIndex: %wZ is at address %p", &unicodeName, targetAddress);

	// Search through SSDT to find matching address
	for (ULONG i = 0; i < g_KeServiceDescriptorTable->NumberOfServices; i++) {
		PVOID ssdtAddress = GetSsdtFunctionAddress(i);
		if (ssdtAddress == targetAddress) {
			LogInfo("FindSyscallIndex: Found %wZ at index 0x%lx", &unicodeName, i);
			return i;
		}
	}

	LogError("FindSyscallIndex: Could not find %wZ in SSDT", &unicodeName);
	return (ULONG)-1;
}

// ============================================================================
// Example Hook Functions
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

NTSTATUS NTAPI wsbp::Ssdt::HkNtCreateFile(
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
) {

	// Log file creation attempts
	if (ObjectAttributes && ObjectAttributes->ObjectName) {
		LogInfo("NtCreateFile called: %wZ", ObjectAttributes->ObjectName);
	}

	// Call original function
	NtCreateFile_t original = (NtCreateFile_t)OrigNtCreateFile;
	return original(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
	);
}

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
);

NTSTATUS NTAPI wsbp::Ssdt::HkNtOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
) {

	// Log process access attempts
	if (ClientId && ClientId->UniqueProcess) {
		LogInfo("NtOpenProcess called: PID=%llu, Access=0x%lx", 
			(ULONG_PTR)ClientId->UniqueProcess, DesiredAccess);
	}

	// Call original function
	NtOpenProcess_t original = (NtOpenProcess_t)OrigNtOpenProcess;
	return original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
