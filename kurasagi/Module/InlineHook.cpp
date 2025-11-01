/*
 * @file InlineHook.cpp
 * @brief Inline hooking implementation
 */

#include "InlineHook.hpp"
#include "../Log.hpp"
#include "../Util/Memory.hpp"

wsbp::InlineHook::Hook wsbp::InlineHook::NtCreateFileHook = { 0 };
wsbp::InlineHook::NtCreateFile_t wsbp::InlineHook::OrigNtCreateFile = NULL;

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
	
	// Build JMP instruction: JMP [RIP+0]; dq HookFunction
	// FF 25 00 00 00 00 = JMP [RIP+0]
	// Followed by 8-byte absolute address
	UCHAR jmpBytes[14] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // JMP [RIP+0]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Address
	};
	
	*(PVOID*)&jmpBytes[6] = HookFunction;
	
	// Write the hook
	if (!WriteOnReadOnlyMemory(jmpBytes, TargetFunction, 14)) {
		LogError("InstallHook: Failed to write hook bytes");
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
		"[Kurasagi] 🔥 INLINE HOOK TRIGGERED! NtCreateFile called!\n");
	
	if (ObjectAttributes && ObjectAttributes->ObjectName) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi]   File: %wZ\n", ObjectAttributes->ObjectName);
	}
	
	// Temporarily unhook to call original
	RemoveHook(&NtCreateFileHook);
	
	NTSTATUS status = OrigNtCreateFile(
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
	
	// Re-hook
	InstallHook(NtCreateFileHook.TargetFunction, HkNtCreateFile, &NtCreateFileHook);
	
	return status;
}
