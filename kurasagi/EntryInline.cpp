/*
 * @file EntryInline.cpp  
 * @brief FULL SYSCALL TRACER - Everything anticheats do will be logged
 */

#include "Include.hpp"
#include "Module/InlineHook.hpp"
#include "Module/SyscallTracer.hpp"
#include "Global.hpp"
#include "Log.hpp"
#include "Util/Memory.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
		"\n"
		"========================================================\n"
		"  KURASAGI - ANTICHEAT SYSCALL TRACER\n"
		"  Full Intel: Memory reads, queries, file access, etc.\n"
		"========================================================\n\n");
	
	// Install NtCreateFile hook
	UNICODE_STRING ntCreateFileStr;
	RtlInitUnicodeString(&ntCreateFileStr, L"NtCreateFile");
	PVOID ntCreateFileAddr = MmGetSystemRoutineAddress(&ntCreateFileStr);
	
	if (ntCreateFileAddr) {
		wsbp::InlineHook::OrigNtCreateFile = (wsbp::InlineHook::NtCreateFile_t)ntCreateFileAddr;
		if (wsbp::InlineHook::InstallHook(ntCreateFileAddr, (PVOID)wsbp::InlineHook::HkNtCreateFile, &wsbp::InlineHook::NtCreateFileHook)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] NtCreateFile hooked\n");
		}
	}
	
	// Install comprehensive syscall tracer
	if (wsbp::SyscallTracer::InitializeTracer()) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Comprehensive syscall tracer active\n");
	}
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
		"\n"
		"========================================================\n"
		"  TRACER READY - Run your anticheat now!\n"
		"  All syscalls will be logged with full context\n"
		"========================================================\n\n");
	
	return STATUS_SUCCESS;
}
