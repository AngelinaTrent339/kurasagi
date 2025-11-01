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

	// WARNING: This returns the CURRENT entry, which may be hooked!
	// On x64, SSDT entries are encoded as offsets from ServiceTableBase
	// Entry format: (ServiceTableBase[index] >> 4) + ServiceTableBase
	LONG offset = (LONG)(g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex] >> 4);
	PVOID functionAddress = (PVOID)((LONG_PTR)g_KeServiceDescriptorTable->ServiceTableBase + offset);

	return functionAddress;
}

BOOLEAN wsbp::Ssdt::GetSsdtEntry(ULONG ServiceIndex, PULONG OutEntry) {

	if (!g_KeServiceDescriptorTable) {
		LogError("GetSsdtEntry: SSDT not initialized");
		return FALSE;
	}

	if (ServiceIndex >= g_KeServiceDescriptorTable->NumberOfServices) {
		LogError("GetSsdtEntry: Invalid service index %lu", ServiceIndex);
		return FALSE;
	}

	if (!OutEntry) {
		LogError("GetSsdtEntry: OutEntry is NULL");
		return FALSE;
	}

	*OutEntry = g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex];
	return TRUE;
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

	// Get ORIGINAL entry BEFORE any modification
	ULONG originalEntry = g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex];
	
	// Decode original function address from entry
	LONG offset = (LONG)(originalEntry >> 4);
	PVOID originalFunction = (PVOID)((LONG_PTR)g_KeServiceDescriptorTable->ServiceTableBase + offset);
	
	if (!originalFunction) {
		LogError("HookSsdtEntry: Could not get original function for index %lu", ServiceIndex);
		return FALSE;
	}

	LogInfo("HookSsdtEntry: Original function at index %lu: %p", ServiceIndex, originalFunction);
	LogInfo("HookSsdtEntry: Hook function: %p", HookFunction);

	// Calculate new offset for hook function
	// New offset = (HookFunction - ServiceTableBase) >> 4 (then << 4 for storage)
	LONG_PTR hookOffset = (LONG_PTR)HookFunction - (LONG_PTR)g_KeServiceDescriptorTable->ServiceTableBase;
	
	// Check for 32-bit offset overflow (very rare but possible)
	// Maximum positive offset: 0x7FFFFFF0 (2GB range)
	// Maximum negative offset: 0x80000000 (-2GB range)
	if (hookOffset > 0x7FFFFFF0LL || hookOffset < -0x80000000LL) {
		LogError("HookSsdtEntry: Hook function too far from SSDT base (offset: 0x%llx)", hookOffset);
		LogError("HookSsdtEntry: SSDT base: %p, Hook: %p", 
			g_KeServiceDescriptorTable->ServiceTableBase, HookFunction);
		return FALSE;
	}
	
	ULONG newEntry = (ULONG)(hookOffset << 4);

	// Preserve the lower 4 bits (parameter count) from original entry
	ULONG parameterCount = originalEntry & 0xF;
	newEntry |= parameterCount;

	// Write the new entry using MDL method
	PVOID entryAddress = &g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex];
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] 📝 Writing hook to SSDT[%lu]:\n", ServiceIndex);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   Entry address: %p\n", entryAddress);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   Original entry: 0x%08X\n", originalEntry);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   New entry: 0x%08X\n", newEntry);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   Original func: %p\n", originalFunction);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   Hook func: %p\n", HookFunction);
	
	if (!WriteOnReadOnlyMemory(&newEntry, entryAddress, sizeof(ULONG))) {
		LogError("HookSsdtEntry: Failed to write hook entry");
		return FALSE;
	}
	
	// Verify the write actually worked
	ULONG verifyEntry = g_KeServiceDescriptorTable->ServiceTableBase[ServiceIndex];
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   ✅ Entry after write: 0x%08X\n", verifyEntry);
	
	if (verifyEntry != newEntry) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   ⚠️ WARNING: Entry mismatch! Expected 0x%08X, got 0x%08X\n", newEntry, verifyEntry);
	}

	LogInfo("HookSsdtEntry: Successfully hooked index %lu", ServiceIndex);

	// Return original function if requested (save BEFORE hooking)
	if (OutOriginalFunction) {
		*OutOriginalFunction = originalFunction;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   Saved original function to %p -> %p\n", OutOriginalFunction, originalFunction);
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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] 🔥 HkNtCreateFile CALLED!\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   ObjectAttributes=%p\n", ObjectAttributes);
	
	if (ObjectAttributes) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   ObjectAttributes->ObjectName=%p\n", ObjectAttributes->ObjectName);
		if (ObjectAttributes->ObjectName) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   File: %wZ\n", ObjectAttributes->ObjectName);
		}
	}
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   OrigNtCreateFile=%p\n", OrigNtCreateFile);

	// Check if original function is valid
	if (!OrigNtCreateFile) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] ❌ ERROR: OrigNtCreateFile is NULL!\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Call original function
	NtCreateFile_t original = (NtCreateFile_t)OrigNtCreateFile;
	NTSTATUS status = original(
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
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   Status=0x%08X\n", status);
	return status;
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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] 🔥 HkNtOpenProcess CALLED!\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   ClientId=%p\n", ClientId);
	
	if (ClientId) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   PID=%llu, Access=0x%lx\n", 
			(ULONG_PTR)ClientId->UniqueProcess, DesiredAccess);
	}
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   OrigNtOpenProcess=%p\n", OrigNtOpenProcess);

	// Check if original function is valid
	if (!OrigNtOpenProcess) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] ❌ ERROR: OrigNtOpenProcess is NULL!\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Call original function
	NtOpenProcess_t original = (NtOpenProcess_t)OrigNtOpenProcess;
	NTSTATUS status = original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi]   Status=0x%08X\n", status);
	return status;
}
