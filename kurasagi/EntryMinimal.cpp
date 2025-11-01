/*
 * @file EntryMinimal.cpp  
 * @brief Minimal entry point for testing SSDT hooks WITHOUT full PatchGuard bypass
 * 
 * WARNING: This will likely trigger PatchGuard eventually!
 * Only use for SHORT testing sessions (< 5 minutes)
 */

#include "Include.hpp"
#include "Module.hpp"
#include "Global.hpp"
#include "Log.hpp"
#include "Util/Memory.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	LogInfo("========== MINIMAL SSDT TEST (NO PATCHGUARD BYPASS) ==========");
	LogInfo("WARNING: This may BSOD after a few minutes due to PatchGuard!");
	LogInfo("Use ONLY for quick testing!");
	
	// Initialize only what SSDT needs
	UNICODE_STRING zwQueryString = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	gl::RtVar::ZwQuerySystemInformationPtr = (NTSTATUS(*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))
		MmGetSystemRoutineAddress(&zwQueryString);

	if (!GetKernelBaseNSize(&gl::RtVar::KernelBase, &gl::RtVar::KernelSize)) {
		LogError("Failed to get kernel base");
		return STATUS_UNSUCCESSFUL;
	}

	LogInfo("Kernel Base: %p, Size: %llx", (PVOID)gl::RtVar::KernelBase, gl::RtVar::KernelSize);

	// Try SSDT hooking WITHOUT PatchGuard bypass
	if (!wsbp::Ssdt::InitializeSsdt()) {
		LogError("Failed to initialize SSDT module");
		return STATUS_UNSUCCESSFUL;
	}

	wsbp::Ssdt::PrintSsdtInfo();

	// Hook some syscalls for demonstration
	// Use hardcoded syscall indexes (Windows 11 24H2 x64)
	// NtCreateFile = 0x55, NtOpenProcess = 0x26

	// Hook NtCreateFile (syscall index 0x55)
	if (wsbp::Ssdt::HookSsdtEntry(0x55, (PVOID)wsbp::Ssdt::HkNtCreateFile, &wsbp::Ssdt::OrigNtCreateFile)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] ✅ Successfully hooked NtCreateFile at index 0x55!\n");
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] ❌ Failed to hook NtCreateFile\n");
	}

	// Hook NtOpenProcess (syscall index 0x26)
	if (wsbp::Ssdt::HookSsdtEntry(0x26, (PVOID)wsbp::Ssdt::HkNtOpenProcess, &wsbp::Ssdt::OrigNtOpenProcess)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] ✅ Successfully hooked NtOpenProcess at index 0x26!\n");
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] ❌ Failed to hook NtOpenProcess\n");
	}

	// Test the hook by calling NtCreateFile from kernel mode
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] 🧪 Testing hook by calling from kernel mode...\n");
	
	UNICODE_STRING testPath;
	RtlInitUnicodeString(&testPath, L"\\??\\C:\\test_kurasagi_hook.txt");
	
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &testPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	HANDLE testHandle;
	IO_STATUS_BLOCK ioStatus;
	
	NTSTATUS testStatus = ZwCreateFile(
		&testHandle,
		GENERIC_WRITE,
		&objAttr,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Kurasagi] 🧪 Test call returned: 0x%08X\n", testStatus);
	
	if (NT_SUCCESS(testStatus)) {
		ZwClose(testHandle);
	}	LogInfo("========== SSDT Hooks Active - Test QUICKLY! ==========");
	LogInfo("Open Notepad and save a file to test NtCreateFile");
	LogInfo("Open Task Manager to test NtOpenProcess");

	return STATUS_SUCCESS;
}
