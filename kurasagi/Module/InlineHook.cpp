/*
 * @file InlineHook.cpp
 * @brief Inline hooking implementation
 */

#include "InlineHook.hpp"
#include "../Log.hpp"
#include "../Util/Memory.hpp"

wsbp::InlineHook::Hook wsbp::InlineHook::NtCreateFileHook = { 0 };
wsbp::InlineHook::NtCreateFile_t wsbp::InlineHook::OrigNtCreateFile = NULL;

// Trampoline buffer
static PVOID g_TrampolineBuffer = NULL;

BOOLEAN wsbp::InlineHook::InstallHook(PVOID TargetFunction, PVOID HookFunction, Hook* OutHook) {
	
	if (!TargetFunction || !HookFunction || !OutHook) {
		LogError("InstallHook: Invalid parameters");
		return FALSE;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi] 🪝 Installing inline hook:\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi]   Target: %p\n", TargetFunction);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi]   Hook: %p\n", HookFunction);

	// Save original bytes
	RtlCopyMemory(OutHook->OriginalBytes, TargetFunction, 14);
	
	// Allocate trampoline (executable memory)
	g_TrampolineBuffer = ExAllocatePoolWithTag(NonPagedPool, 64, 'pmrT');
	if (!g_TrampolineBuffer) {
		LogError("InstallHook: Failed to allocate trampoline");
		return FALSE;
	}
	
	// Build trampoline: original 14 bytes + JMP back to Target+14
	RtlCopyMemory(g_TrampolineBuffer, OutHook->OriginalBytes, 14);
	
	UCHAR* trampJmp = (UCHAR*)g_TrampolineBuffer + 14;
	PVOID returnAddr = (PVOID)((ULONG_PTR)TargetFunction + 14);
	
	// JMP [RIP+0]; dq returnAddr
	trampJmp[0] = 0xFF;
	trampJmp[1] = 0x25;
	trampJmp[2] = 0x00;
	trampJmp[3] = 0x00;
	trampJmp[4] = 0x00;
	trampJmp[5] = 0x00;
	*(PVOID*)&trampJmp[6] = returnAddr;
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi]   Trampoline: %p -> %p\n", g_TrampolineBuffer, returnAddr);
	
	// Build JMP instruction: JMP [RIP+0]; dq HookFunction
	UCHAR jmpBytes[14] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // JMP [RIP+0]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Address
	};
	
	*(PVOID*)&jmpBytes[6] = HookFunction;
	
	// Write the hook
	if (!WriteOnReadOnlyMemory(jmpBytes, TargetFunction, 14)) {
		LogError("InstallHook: Failed to write hook bytes");
		ExFreePoolWithTag(g_TrampolineBuffer, 'pmrT');
		g_TrampolineBuffer = NULL;
		return FALSE;
	}
	
	OutHook->TargetFunction = TargetFunction;
	OutHook->HookFunction = HookFunction;
	OutHook->IsHooked = TRUE;
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi] ✅ Hook installed successfully!\n");
	
	return TRUE;
}

BOOLEAN wsbp::InlineHook::RemoveHook(Hook* HookInfo) {
	
	if (!HookInfo || !HookInfo->IsHooked) {
		return FALSE;
	}
	
	// Restore original bytes
	if (!WriteOnReadOnlyMemory(HookInfo->OriginalBytes, HookInfo->TargetFunction, 14)) {
		LogError("RemoveHook: Failed to restore original bytes");
		return FALSE;
	}
	
	HookInfo->IsHooked = FALSE;
	return TRUE;
}

NTSTATUS NTAPI wsbp::InlineHook::HkNtCreateFile(
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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi] 🔥 NtCreateFile called!\n");
	
	if (ObjectAttributes && ObjectAttributes->ObjectName) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi]   File: %wZ\n", ObjectAttributes->ObjectName);
	}
	
	// Call original via trampoline (original bytes + jmp back)
	if (!g_TrampolineBuffer) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] ERROR: Trampoline not initialized!\n");
		return STATUS_UNSUCCESSFUL;
	}
	
	NtCreateFile_t trampolineFunc = (NtCreateFile_t)g_TrampolineBuffer;
	
	NTSTATUS status = trampolineFunc(
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
	
	return status;
}
