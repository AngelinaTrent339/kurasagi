/*
 * @file Entry.cpp
 * @brief Entry Point.
 */

#include "Include.hpp"
#include "Module.hpp"
#include "Global.hpp"
#include "Log.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	
	if (!gl::RtVar::InitializeRuntimeVariables()) {
		LogError("DriverEntry: Failed to initialize runtime variables.");
		return STATUS_UNSUCCESSFUL;
	}

	LogVerbose("DriverEntry: Driver Image Base: %llX", gl::RtVar::Self::SelfBase);
	LogVerbose("DriverEntry: Driver Image Size: %llx", gl::RtVar::Self::SelfSize);

	if (!wsbp::BypassPatchGuard()) {
		LogError("DriverEntry: Failed to bypass PatchGuard");
		return STATUS_UNSUCCESSFUL;
	}

	LogVerbose("Test #1: %p", KeDelayExecutionThread); // Yeah it is fine

	// ========== SSDT HOOKING DEMO ==========
	
	LogInfo("========== Starting SSDT Hooking Demo ==========");

	// Step 1: Initialize SSDT module
	if (!wsbp::Ssdt::InitializeSsdt()) {
		LogError("DriverEntry: Failed to initialize SSDT module");
		return STATUS_UNSUCCESSFUL;
	}

	// Step 2: Print SSDT information
	wsbp::Ssdt::PrintSsdtInfo();

	// Step 3: Automatically find and hook NtCreateFile
	ULONG ntCreateFileIndex = wsbp::Ssdt::FindSyscallIndex(L"NtCreateFile");
	if (ntCreateFileIndex != (ULONG)-1) {
		if (wsbp::Ssdt::HookSsdtEntry(ntCreateFileIndex, wsbp::Ssdt::HkNtCreateFile, &wsbp::Ssdt::OrigNtCreateFile)) {
			LogInfo("DriverEntry: Successfully hooked NtCreateFile at index 0x%lx!", ntCreateFileIndex);
		}
	}

	// Step 4: Automatically find and hook NtOpenProcess
	ULONG ntOpenProcessIndex = wsbp::Ssdt::FindSyscallIndex(L"NtOpenProcess");
	if (ntOpenProcessIndex != (ULONG)-1) {
		if (wsbp::Ssdt::HookSsdtEntry(ntOpenProcessIndex, wsbp::Ssdt::HkNtOpenProcess, &wsbp::Ssdt::OrigNtOpenProcess)) {
			LogInfo("DriverEntry: Successfully hooked NtOpenProcess at index 0x%lx!", ntOpenProcessIndex);
		}
	}

	LogInfo("========== SSDT Hooks Installed - Syscalls will be traced ==========");

	return STATUS_SUCCESS;
}