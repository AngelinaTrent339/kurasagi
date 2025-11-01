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

	// Hook NtCreateFile
	ULONG ntCreateFileIndex = wsbp::Ssdt::FindSyscallIndex(L"NtCreateFile");
	if (ntCreateFileIndex != (ULONG)-1) {
		if (wsbp::Ssdt::HookSsdtEntry(ntCreateFileIndex, wsbp::Ssdt::HkNtCreateFile, &wsbp::Ssdt::OrigNtCreateFile)) {
			LogInfo("✅ Successfully hooked NtCreateFile at index 0x%lx!", ntCreateFileIndex);
		}
	}

	// Hook NtOpenProcess
	ULONG ntOpenProcessIndex = wsbp::Ssdt::FindSyscallIndex(L"NtOpenProcess");
	if (ntOpenProcessIndex != (ULONG)-1) {
		if (wsbp::Ssdt::HookSsdtEntry(ntOpenProcessIndex, wsbp::Ssdt::HkNtOpenProcess, &wsbp::Ssdt::OrigNtOpenProcess)) {
			LogInfo("✅ Successfully hooked NtOpenProcess at index 0x%lx!", ntOpenProcessIndex);
		}
	}

	LogInfo("========== SSDT Hooks Active - Test QUICKLY! ==========");
	LogInfo("Open Notepad and save a file to test NtCreateFile");
	LogInfo("Open Task Manager to test NtOpenProcess");

	return STATUS_SUCCESS;
}
