/*
 * @file SsdtExamples.hpp
 * @brief Practical SSDT hook examples - Copy/paste ready!
 */

#pragma once

#include "../Include.hpp"
#include "Ssdt.hpp"
#include "SsdtReference.hpp"
#include "SsdtHelpers.hpp"

namespace Examples {

	// ========================================================================
	// Example 1: File Monitor - Log all file operations
	// ========================================================================

	PVOID OrigNtCreateFileEx1 = NULL;
	PVOID OrigNtReadFileEx1 = NULL;
	PVOID OrigNtWriteFileEx1 = NULL;

	NTSTATUS NTAPI HkNtCreateFileEx1(
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
		if (ObjectAttributes && ObjectAttributes->ObjectName) {
			// Use helper for enhanced logging
			SsdtHelpers::LogSyscall("NtCreateFile",
				"File: %wZ | Access: %s | Disposition: %s",
				ObjectAttributes->ObjectName,
				SsdtHelpers::AccessMaskToString(DesiredAccess),
				SsdtHelpers::DispositionToString(CreateDisposition));
		}

		NtCreateFile_t original = (NtCreateFile_t)OrigNtCreateFileEx1;
		return original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
			AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
			CreateOptions, EaBuffer, EaLength);
	}

	VOID InstallFileMonitor() {
		ULONG index = wsbp::Ssdt::FindSyscallIndex(L"NtCreateFile");
		if (index != (ULONG)-1) {
			wsbp::Ssdt::HookSsdtEntry(index, HkNtCreateFileEx1, &OrigNtCreateFileEx1);
			DbgPrintEx(0, 0, "[FileMonitor] Installed!\n");
		}
	}

	// ========================================================================
	// Example 2: Process Protector - Protect specific PID
	// ========================================================================

	PVOID OrigNtTerminateProcessEx2 = NULL;
	HANDLE g_ProtectedPid = (HANDLE)1234; // Change this to PID you want to protect

	NTSTATUS NTAPI HkNtTerminateProcessEx2(HANDLE ProcessHandle, NTSTATUS ExitStatus) {

		if (ProcessHandle) {
			PEPROCESS process = NULL;
			if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, 
				KernelMode, (PVOID*)&process, NULL))) {

				HANDLE pid = PsGetProcessId(process);
				ObDereferenceObject(process);

				if (pid == g_ProtectedPid) {
					DbgPrintEx(0, 0, "[ProcessProtector] BLOCKED termination of PID %llu\n", 
						(ULONG_PTR)pid);
					return STATUS_ACCESS_DENIED;
				}
			}
		}

		NtTerminateProcess_t original = (NtTerminateProcess_t)OrigNtTerminateProcessEx2;
		return original(ProcessHandle, ExitStatus);
	}

	VOID InstallProcessProtector(HANDLE PidToProtect) {
		g_ProtectedPid = PidToProtect;
		ULONG index = wsbp::Ssdt::FindSyscallIndex(L"NtTerminateProcess");
		if (index != (ULONG)-1) {
			wsbp::Ssdt::HookSsdtEntry(index, HkNtTerminateProcessEx2, &OrigNtTerminateProcessEx2);
			DbgPrintEx(0, 0, "[ProcessProtector] Protecting PID %llu\n", (ULONG_PTR)PidToProtect);
		}
	}

	// ========================================================================
	// Example 3: Memory Access Monitor - Detect RPM/WPM on specific process
	// ========================================================================

	PVOID OrigNtReadVirtualMemoryEx3 = NULL;
	PVOID OrigNtWriteVirtualMemoryEx3 = NULL;
	HANDLE g_MonitoredPid = (HANDLE)5678; // Change this

	NTSTATUS NTAPI HkNtReadVirtualMemoryEx3(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesRead
	) {
		PEPROCESS process = NULL;
		if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
			KernelMode, (PVOID*)&process, NULL))) {

			HANDLE pid = PsGetProcessId(process);
			ObDereferenceObject(process);

			if (pid == g_MonitoredPid) {
				DbgPrintEx(0, 0, "[MemMonitor] RPM on PID %llu: Address=%p Size=%llu\n",
					(ULONG_PTR)pid, BaseAddress, (ULONG64)BufferSize);
			}
		}

		NtReadVirtualMemory_t original = (NtReadVirtualMemory_t)OrigNtReadVirtualMemoryEx3;
		return original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
	}

	NTSTATUS NTAPI HkNtWriteVirtualMemoryEx3(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesWritten
	) {
		PEPROCESS process = NULL;
		if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
			KernelMode, (PVOID*)&process, NULL))) {

			HANDLE pid = PsGetProcessId(process);
			ObDereferenceObject(process);

			if (pid == g_MonitoredPid) {
				DbgPrintEx(0, 0, "[MemMonitor] WPM on PID %llu: Address=%p Size=%llu\n",
					(ULONG_PTR)pid, BaseAddress, (ULONG64)BufferSize);
			}
		}

		NtWriteVirtualMemory_t original = (NtWriteVirtualMemory_t)OrigNtWriteVirtualMemoryEx3;
		return original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
	}

	VOID InstallMemoryMonitor(HANDLE PidToMonitor) {
		g_MonitoredPid = PidToMonitor;

		ULONG readIndex = wsbp::Ssdt::FindSyscallIndex(L"NtReadVirtualMemory");
		if (readIndex != (ULONG)-1) {
			wsbp::Ssdt::HookSsdtEntry(readIndex, HkNtReadVirtualMemoryEx3, &OrigNtReadVirtualMemoryEx3);
		}

		ULONG writeIndex = wsbp::Ssdt::FindSyscallIndex(L"NtWriteVirtualMemory");
		if (writeIndex != (ULONG)-1) {
			wsbp::Ssdt::HookSsdtEntry(writeIndex, HkNtWriteVirtualMemoryEx3, &OrigNtWriteVirtualMemoryEx3);
		}

		DbgPrintEx(0, 0, "[MemMonitor] Monitoring PID %llu\n", (ULONG_PTR)PidToMonitor);
	}

	// ========================================================================
	// Example 4: Registry Protector - Block registry modifications
	// ========================================================================

	PVOID OrigNtSetValueKeyEx4 = NULL;
	PVOID OrigNtDeleteKeyEx4 = NULL;

	NTSTATUS NTAPI HkNtSetValueKeyEx4(
		HANDLE KeyHandle,
		PUNICODE_STRING ValueName,
		ULONG TitleIndex,
		ULONG Type,
		PVOID Data,
		ULONG DataSize
	) {
		// Block all registry writes (you can filter specific keys)
		if (ValueName) {
			DbgPrintEx(0, 0, "[RegProtector] BLOCKED write to: %wZ\n", ValueName);
			return STATUS_ACCESS_DENIED;
		}

		NtSetValueKey_t original = (NtSetValueKey_t)OrigNtSetValueKeyEx4;
		return original(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
	}

	NTSTATUS NTAPI HkNtDeleteKeyEx4(HANDLE KeyHandle) {
		DbgPrintEx(0, 0, "[RegProtector] BLOCKED key deletion\n");
		return STATUS_ACCESS_DENIED;
	}

	VOID InstallRegistryProtector() {
		ULONG setIndex = wsbp::Ssdt::FindSyscallIndex(L"NtSetValueKey");
		if (setIndex != (ULONG)-1) {
			wsbp::Ssdt::HookSsdtEntry(setIndex, HkNtSetValueKeyEx4, &OrigNtSetValueKeyEx4);
		}

		ULONG delIndex = wsbp::Ssdt::FindSyscallIndex(L"NtDeleteKey");
		if (delIndex != (ULONG)-1) {
			wsbp::Ssdt::HookSsdtEntry(delIndex, HkNtDeleteKeyEx4, &OrigNtDeleteKeyEx4);
		}

		DbgPrintEx(0, 0, "[RegProtector] Installed!\n");
	}

	// ========================================================================
	// Example 5: Thread Monitor - Detect thread creation
	// ========================================================================

	PVOID OrigNtCreateThreadEx5 = NULL;

	NTSTATUS NTAPI HkNtCreateThreadEx5(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		HANDLE ProcessHandle,
		PCLIENT_ID ClientId,
		PCONTEXT ThreadContext,
		PVOID InitialTeb,
		BOOLEAN CreateSuspended
	) {
		PEPROCESS process = NULL;
		if (ProcessHandle && NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
			KernelMode, (PVOID*)&process, NULL))) {

			HANDLE pid = PsGetProcessId(process);
			ObDereferenceObject(process);

			DbgPrintEx(0, 0, "[ThreadMonitor] New thread in PID %llu, StartAddr=%p\n",
				(ULONG_PTR)pid, ThreadContext ? (PVOID)ThreadContext->Rip : NULL);
		}

		NtCreateThread_t original = (NtCreateThread_t)OrigNtCreateThreadEx5;
		return original(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
			ClientId, ThreadContext, InitialTeb, CreateSuspended);
	}

	VOID InstallThreadMonitor() {
		ULONG index = wsbp::Ssdt::FindSyscallIndex(L"NtCreateThread");
		if (index != (ULONG)-1) {
			wsbp::Ssdt::HookSsdtEntry(index, HkNtCreateThreadEx5, &OrigNtCreateThreadEx5);
			DbgPrintEx(0, 0, "[ThreadMonitor] Installed!\n");
		}
	}

	// ========================================================================
	// Example 6: Anti-Cheat - Detect game memory tampering
	// ========================================================================

	PVOID OrigNtProtectVirtualMemoryEx6 = NULL;
	HANDLE g_GamePid = (HANDLE)9999; // Set to your game's PID

	NTSTATUS NTAPI HkNtProtectVirtualMemoryEx6(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG NewProtect,
		PULONG OldProtect
	) {
		PEPROCESS process = NULL;
		if (ProcessHandle && NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
			KernelMode, (PVOID*)&process, NULL))) {

			HANDLE pid = PsGetProcessId(process);
			ObDereferenceObject(process);

			if (pid == g_GamePid) {
				// Detect suspicious protection changes (e.g., making code writable)
				if ((NewProtect & PAGE_EXECUTE_READWRITE) || (NewProtect & PAGE_EXECUTE_WRITECOPY)) {
					DbgPrintEx(0, 0, "[AntiCheat] SUSPICIOUS: Process %llu trying to make code writable!\n",
						(ULONG_PTR)pid);
					// Optionally block it
					// return STATUS_ACCESS_DENIED;
				}
			}
		}

		NtProtectVirtualMemory_t original = (NtProtectVirtualMemory_t)OrigNtProtectVirtualMemoryEx6;
		return original(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
	}

	VOID InstallAntiCheat(HANDLE GamePid) {
		g_GamePid = GamePid;
		ULONG index = wsbp::Ssdt::FindSyscallIndex(L"NtProtectVirtualMemory");
		if (index != (ULONG)-1) {
			wsbp::Ssdt::HookSsdtEntry(index, HkNtProtectVirtualMemoryEx6, &OrigNtProtectVirtualMemoryEx6);
			DbgPrintEx(0, 0, "[AntiCheat] Monitoring game PID %llu\n", (ULONG_PTR)GamePid);
		}
	}

}

/*
 * HOW TO USE IN DriverEntry:
 * 
 * // After bypassing PatchGuard and initializing SSDT:
 * 
 * // Install file monitor
 * Examples::InstallFileMonitor();
 * 
 * // Protect a process from termination
 * Examples::InstallProcessProtector((HANDLE)1234);
 * 
 * // Monitor memory access to a process
 * Examples::InstallMemoryMonitor((HANDLE)5678);
 * 
 * // Block registry modifications
 * Examples::InstallRegistryProtector();
 * 
 * // Monitor thread creation
 * Examples::InstallThreadMonitor();
 * 
 * // Anti-cheat for a game
 * Examples::InstallAntiCheat((HANDLE)9999);
 */
