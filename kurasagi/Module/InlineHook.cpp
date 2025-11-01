/*
 * @file InlineHook.cpp
 * @brief Inline hooking implementation
 */

#include "InlineHook.hpp"
#include "../Log.hpp"
#include "../Util/Memory.hpp"
#include "../Util/LDE64.hpp"

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

	// Use LDE to find safe hook length (need >= 14 bytes for JMP [RIP+0])
	SIZE_T safeLength = LDE64::GetSafeHookLength(TargetFunction, 14);
	if (safeLength == 0 || safeLength > 64) {
		LogError("InstallHook: Cannot safely hook (LDE failed)");
		return FALSE;
	}
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi]   Safe hook length: %llu bytes (complete instructions)\n", safeLength);

	// Save original bytes (use calculated safe length)
	RtlCopyMemory(OutHook->OriginalBytes, TargetFunction, min(safeLength, 14));
	
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

// Helper to decode access mask
static const char* DecodeAccessMask(ACCESS_MASK access) {
	static char buffer[256];
	buffer[0] = 0;
	if (access & GENERIC_READ) strcat_s(buffer, sizeof(buffer), "READ|");
	if (access & GENERIC_WRITE) strcat_s(buffer, sizeof(buffer), "WRITE|");
	if (access & GENERIC_EXECUTE) strcat_s(buffer, sizeof(buffer), "EXEC|");
	if (access & DELETE) strcat_s(buffer, sizeof(buffer), "DEL|");
	if (buffer[0]) buffer[strlen(buffer)-1] = 0;
	return buffer[0] ? buffer : "NONE";
}

static const char* DecodeDisposition(ULONG disp) {
	switch(disp) {
		case FILE_SUPERSEDE: return "SUPERSEDE";
		case FILE_OPEN: return "OPEN";
		case FILE_CREATE: return "CREATE";
		case FILE_OPEN_IF: return "OPEN_IF";
		case FILE_OVERWRITE: return "OVERWRITE";
		case FILE_OVERWRITE_IF: return "OVERWRITE_IF";
		default: return "UNKNOWN";
	}
}

static void DecodeCreateOptions(ULONG options, char* buffer, SIZE_T bufSize) {
	buffer[0] = 0;
	if (options & FILE_DIRECTORY_FILE) strcat_s(buffer, bufSize, "DIR|");
	if (options & FILE_NON_DIRECTORY_FILE) strcat_s(buffer, bufSize, "FILE|");
	if (options & FILE_DELETE_ON_CLOSE) strcat_s(buffer, bufSize, "DEL_ON_CLOSE|");
	if (options & FILE_SYNCHRONOUS_IO_NONALERT) strcat_s(buffer, bufSize, "SYNC_IO|");
	if (options & FILE_RANDOM_ACCESS) strcat_s(buffer, bufSize, "RANDOM|");
	if (options & FILE_SEQUENTIAL_ONLY) strcat_s(buffer, bufSize, "SEQUENTIAL|");
	if (buffer[0]) buffer[strlen(buffer)-1] = 0;
	if (buffer[0] == 0) strcpy_s(buffer, bufSize, "NONE");
}

static void DecodeShareAccess(ULONG share, char* buffer, SIZE_T bufSize) {
	buffer[0] = 0;
	if (share & FILE_SHARE_READ) strcat_s(buffer, bufSize, "READ|");
	if (share & FILE_SHARE_WRITE) strcat_s(buffer, bufSize, "WRITE|");
	if (share & FILE_SHARE_DELETE) strcat_s(buffer, bufSize, "DELETE|");
	if (buffer[0]) buffer[strlen(buffer)-1] = 0;
	if (buffer[0] == 0) strcpy_s(buffer, bufSize, "EXCLUSIVE");
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

	// ========== CAPTURE CONTEXT BEFORE CALL ==========
	LARGE_INTEGER timestamp;
	KeQuerySystemTime(&timestamp);
	PVOID returnAddress = _ReturnAddress();
	PEPROCESS process = PsGetCurrentProcess();
	HANDLE pid = PsGetCurrentProcessId();
	HANDLE tid = PsGetCurrentThreadId();
	
	// Get process name - EPROCESS.ImageFileName offset is 0x338 for Windows 26100.6584
	char processNameBuf[16] = {0};
	__try {
		const char* namePtr = (const char*)((ULONG_PTR)process + 0x338);
		RtlCopyMemory(processNameBuf, namePtr, 15);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		strcpy_s(processNameBuf, sizeof(processNameBuf), "Unknown");
	}
	const char* processName = processNameBuf;
	
	// Capture call stack - use RtlCaptureStackBackTrace instead (more reliable)
	PVOID callStack[16] = {0};
	ULONG framesCapture = RtlCaptureStackBackTrace(0, 16, callStack, NULL);
	
	// ========== CALL ORIGINAL ==========
	if (!g_TrampolineBuffer) {
		return STATUS_UNSUCCESSFUL;
	}
	
	NtCreateFile_t trampolineFunc = (NtCreateFile_t)g_TrampolineBuffer;
	NTSTATUS status = trampolineFunc(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	
	// ========== FILTER & LOG ==========
	BOOLEAN shouldLog = FALSE;
	if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
		WCHAR* buf = ObjectAttributes->ObjectName->Buffer;
		// Skip boring system stuff
		if (wcsstr(buf, L"\\Device\\") == NULL && wcsstr(buf, L"MountPointManager") == NULL &&
		    wcsstr(buf, L"STORAGE#") == NULL && wcsstr(buf, L"ConDrv") == NULL) {
			// Log interesting extensions
			if (wcsstr(buf, L".txt") || wcsstr(buf, L".doc") || wcsstr(buf, L".exe") ||
			    wcsstr(buf, L".dll") || wcsstr(buf, L".log") || wcsstr(buf, L".ini") ||
			    wcsstr(buf, L".cfg") || wcsstr(buf, L".bat") || wcsstr(buf, L".ps1") ||
			    wcsstr(buf, L".json") || wcsstr(buf, L".xml") || wcsstr(buf, L".db")) {
				shouldLog = TRUE;
			}
		}
	}
	
	if (shouldLog) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"\n[Kurasagi] ═══════════════════════════════════════════════════\n");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 🔥 NtCreateFile - FULL INTEL\n");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] ═══════════════════════════════════════════════════\n");
		
		// Timestamp
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] ⏱️  Time: %lld (100ns units since 1601)\n", timestamp.QuadPart);
		
		// Process Context
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 📦 Process: %s | PID: %llu | TID: %llu\n", processName, (ULONG_PTR)pid, (ULONG_PTR)tid);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 📍 EPROCESS: %p\n", process);
		
		// Caller Info
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] � Return Address: %p (caller instruction)\n", returnAddress);
		
		// File Path
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 📄 File: %wZ\n", ObjectAttributes->ObjectName);
		
		// All Arguments Decoded
		char optionsBuf[256];
		char shareBuf[128];
		DecodeCreateOptions(CreateOptions, optionsBuf, sizeof(optionsBuf));
		DecodeShareAccess(ShareAccess, shareBuf, sizeof(shareBuf));
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 🔐 DesiredAccess: 0x%08X (%s)\n", DesiredAccess, DecodeAccessMask(DesiredAccess));
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 🗂️  Disposition: %s (0x%X)\n", DecodeDisposition(CreateDisposition), CreateDisposition);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 🔧 CreateOptions: 0x%08X (%s)\n", CreateOptions, optionsBuf);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 🤝 ShareAccess: 0x%X (%s)\n", ShareAccess, shareBuf);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 📋 FileAttributes: 0x%X\n", FileAttributes);
		
		// Return Status
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] ↩️  NTSTATUS: 0x%08X (%s)\n", status, NT_SUCCESS(status) ? "✅ SUCCESS" : "❌ FAILED");
		
		// Handle if successful
		if (NT_SUCCESS(status) && FileHandle) {
			__try {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
					"[Kurasagi] 🎯 FileHandle: 0x%p\n", *FileHandle);
			} __except(EXCEPTION_EXECUTE_HANDLER) {}
		}
		
		// Call Stack (shows execution path)
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] 📚 Call Stack (%lu frames):\n", framesCapture);
		for (ULONG i = 0; i < framesCapture; i++) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
				"[Kurasagi]   [%lu] %p\n", i, callStack[i]);
		}
		
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
			"[Kurasagi] ═══════════════════════════════════════════════════\n\n");
	}
	
	return status;
}
