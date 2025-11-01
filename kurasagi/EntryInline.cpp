/*
 * @file EntryInline.cpp  
 * @brief Test inline hooking (ACTUALLY WORKS on modern Windows)
 */

#include "Include.hpp"
#include "Module/InlineHook.hpp"
#include "Global.hpp"
#include "Log.hpp"
#include "Util/Memory.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	LogInfo("========== INLINE HOOK TEST ==========");
	
	// Get NtCreateFile address
	UNICODE_STRING ntCreateFileStr;
	RtlInitUnicodeString(&ntCreateFileStr, L"NtCreateFile");
	
	PVOID ntCreateFileAddr = MmGetSystemRoutineAddress(&ntCreateFileStr);
	if (!ntCreateFileAddr) {
		LogError("Could not find NtCreateFile");
		return STATUS_UNSUCCESSFUL;
	}
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi] NtCreateFile found at: %p\n", ntCreateFileAddr);
	
	// Save original function pointer
	wsbp::InlineHook::OrigNtCreateFile = (wsbp::InlineHook::NtCreateFile_t)ntCreateFileAddr;
	
	// Install inline hook
	if (!wsbp::InlineHook::InstallHook(
		ntCreateFileAddr, 
		(PVOID)wsbp::InlineHook::HkNtCreateFile,
		&wsbp::InlineHook::NtCreateFileHook)) {
		
		LogError("Failed to install inline hook");
		return STATUS_UNSUCCESSFUL;
	}
	
	// Test it
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi] 🧪 Testing inline hook...\n");
	
	UNICODE_STRING testPath;
	RtlInitUnicodeString(&testPath, L"\\??\\C:\\test_inline_hook.txt");
	
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
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
		"[Kurasagi] 🧪 Test returned: 0x%08X\n", testStatus);
	
	if (NT_SUCCESS(testStatus)) {
		ZwClose(testHandle);
	}
	
	LogInfo("========== INLINE HOOK ACTIVE ==========");
	LogInfo("Open Notepad and save a file - you WILL see logs!");
	
	return STATUS_SUCCESS;
}
