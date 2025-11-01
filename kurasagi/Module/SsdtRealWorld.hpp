/*
 * @file SsdtRealWorld.hpp
 * @brief Real-world syscall tracing examples with full data extraction
 */

#pragma once

#include "../Include.hpp"
#include "Ssdt.hpp"
#include "SsdtReference.hpp"
#include "SsdtHelpers.hpp"

namespace RealWorld {

	// ========================================================================
	// Example 1: Complete File Activity Logger
	// ========================================================================

	PVOID OrigNtCreateFileRW = NULL;
	PVOID OrigNtReadFileRW = NULL;
	PVOID OrigNtWriteFileRW = NULL;

	NTSTATUS NTAPI HkNtCreateFileRW(
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
			SsdtHelpers::LogSyscall("NtCreateFile",
				"📁 %wZ | Access: 0x%lx | Disp: %s",
				ObjectAttributes->ObjectName,
				DesiredAccess,
				SsdtHelpers::DispositionToString(CreateDisposition));
		}

		NtCreateFile_t original = (NtCreateFile_t)OrigNtCreateFileRW;
		return original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
			AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
			CreateOptions, EaBuffer, EaLength);
	}

	NTSTATUS NTAPI HkNtReadFileRW(
		HANDLE FileHandle,
		HANDLE Event,
		PIO_APC_ROUTINE ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key
	) {
		POBJECT_NAME_INFORMATION nameInfo = NULL;
		if (SsdtHelpers::GetFilenameFromHandle(FileHandle, &nameInfo)) {
			SsdtHelpers::LogSyscall("NtReadFile",
				"📖 %wZ | Size: %lu bytes | Offset: %lld",
				&nameInfo->Name,
				Length,
				ByteOffset ? ByteOffset->QuadPart : 0LL);
			ExFreePoolWithTag(nameInfo, 'File');
		}

		NtReadFile_t original = (NtReadFile_t)OrigNtReadFileRW;
		NTSTATUS status = original(FileHandle, Event, ApcRoutine, ApcContext,
			IoStatusBlock, Buffer, Length, ByteOffset, Key);

		// Log actual bytes read
		if (NT_SUCCESS(status) && IoStatusBlock) {
			DbgPrintEx(0, 0, "    └─ Actually read: %lu bytes\n",
				IoStatusBlock->Information);
		}

		return status;
	}

	NTSTATUS NTAPI HkNtWriteFileRW(
		HANDLE FileHandle,
		HANDLE Event,
		PIO_APC_ROUTINE ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key
	) {
		POBJECT_NAME_INFORMATION nameInfo = NULL;
		if (SsdtHelpers::GetFilenameFromHandle(FileHandle, &nameInfo)) {
			SsdtHelpers::LogSyscall("NtWriteFile",
				"✍️ %wZ | Size: %lu bytes",
				&nameInfo->Name,
				Length);

			// Show first 64 bytes being written
			if (Buffer && Length > 0) {
				DbgPrintEx(0, 0, "    Data preview:\n");
				SsdtHelpers::HexDump(Buffer, Length, 64);
			}

			ExFreePoolWithTag(nameInfo, 'File');
		}

		NtWriteFile_t original = (NtWriteFile_t)OrigNtWriteFileRW;
		return original(FileHandle, Event, ApcRoutine, ApcContext,
			IoStatusBlock, Buffer, Length, ByteOffset, Key);
	}

	VOID InstallFileActivityLogger() {
		ULONG createIndex = wsbp::Ssdt::FindSyscallIndex(L"NtCreateFile");
		ULONG readIndex = wsbp::Ssdt::FindSyscallIndex(L"NtReadFile");
		ULONG writeIndex = wsbp::Ssdt::FindSyscallIndex(L"NtWriteFile");

		if (createIndex != (ULONG)-1)
			wsbp::Ssdt::HookSsdtEntry(createIndex, HkNtCreateFileRW, &OrigNtCreateFileRW);
		if (readIndex != (ULONG)-1)
			wsbp::Ssdt::HookSsdtEntry(readIndex, HkNtReadFileRW, &OrigNtReadFileRW);
		if (writeIndex != (ULONG)-1)
			wsbp::Ssdt::HookSsdtEntry(writeIndex, HkNtWriteFileRW, &OrigNtWriteFileRW);

		DbgPrintEx(0, 0, "✅ File Activity Logger installed\n");
	}

	// ========================================================================
	// Example 2: Process Memory Spy (RPM/WPM Monitor)
	// ========================================================================

	PVOID OrigNtReadVirtualMemoryRW = NULL;
	PVOID OrigNtWriteVirtualMemoryRW = NULL;
	HANDLE g_SpyTargetPid = NULL;  // Set this to PID you want to monitor

	NTSTATUS NTAPI HkNtReadVirtualMemoryRW(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesRead
	) {
		HANDLE targetPid = SsdtHelpers::GetPidFromHandle(ProcessHandle);

		if (targetPid == g_SpyTargetPid || g_SpyTargetPid == NULL) {
			PUCHAR targetName = SsdtHelpers::GetProcessNameFromHandle(ProcessHandle);
			SsdtHelpers::LogSyscall("NtReadVirtualMemory",
				"🔍 Target: %s (PID %llu) | Addr: %p | Size: %llu bytes",
				targetName,
				(ULONG64)targetPid,
				BaseAddress,
				(ULONG64)BufferSize);
		}

		NtReadVirtualMemory_t original = (NtReadVirtualMemory_t)OrigNtReadVirtualMemoryRW;
		NTSTATUS status = original(ProcessHandle, BaseAddress, Buffer,
			BufferSize, NumberOfBytesRead);

		// Show what was read (if successful)
		if (NT_SUCCESS(status) && NumberOfBytesRead && *NumberOfBytesRead > 0) {
			if (targetPid == g_SpyTargetPid || g_SpyTargetPid == NULL) {
				DbgPrintEx(0, 0, "    └─ Read %llu bytes:\n", (ULONG64)*NumberOfBytesRead);
				SsdtHelpers::HexDump(Buffer, *NumberOfBytesRead, 32);
			}
		}

		return status;
	}

	NTSTATUS NTAPI HkNtWriteVirtualMemoryRW(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesWritten
	) {
		HANDLE targetPid = SsdtHelpers::GetPidFromHandle(ProcessHandle);

		if (targetPid == g_SpyTargetPid || g_SpyTargetPid == NULL) {
			PUCHAR targetName = SsdtHelpers::GetProcessNameFromHandle(ProcessHandle);
			SsdtHelpers::LogSyscall("NtWriteVirtualMemory",
				"✏️ Target: %s (PID %llu) | Addr: %p | Size: %llu bytes",
				targetName,
				(ULONG64)targetPid,
				BaseAddress,
				(ULONG64)BufferSize);

			// Show what's being written
			if (Buffer && BufferSize > 0) {
				DbgPrintEx(0, 0, "    Data being written:\n");
				SsdtHelpers::HexDump(Buffer, BufferSize, 32);

				// Detect suspicious patterns
				if (BufferSize >= 4) {
					ULONG* dwords = (ULONG*)Buffer;
					if (dwords[0] == 0x90909090) {
						DbgPrintEx(0, 0, "    ⚠️ NOP SLED DETECTED!\n");
					}
					if ((dwords[0] & 0xFFFF) == 0x25FF) {
						DbgPrintEx(0, 0, "    ⚠️ HOOK PATTERN DETECTED!\n");
					}
				}
			}
		}

		NtWriteVirtualMemory_t original = (NtWriteVirtualMemory_t)OrigNtWriteVirtualMemoryRW;
		return original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
	}

	VOID InstallMemorySpy(HANDLE TargetPid) {
		g_SpyTargetPid = TargetPid;

		ULONG readIndex = wsbp::Ssdt::FindSyscallIndex(L"NtReadVirtualMemory");
		ULONG writeIndex = wsbp::Ssdt::FindSyscallIndex(L"NtWriteVirtualMemory");

		if (readIndex != (ULONG)-1)
			wsbp::Ssdt::HookSsdtEntry(readIndex, HkNtReadVirtualMemoryRW, &OrigNtReadVirtualMemoryRW);
		if (writeIndex != (ULONG)-1)
			wsbp::Ssdt::HookSsdtEntry(writeIndex, HkNtWriteVirtualMemoryRW, &OrigNtWriteVirtualMemoryRW);

		if (TargetPid) {
			DbgPrintEx(0, 0, "✅ Memory Spy installed for PID %llu (%s)\n",
				(ULONG64)TargetPid,
				SsdtHelpers::GetProcessNameFromPid(TargetPid));
		}
		else {
			DbgPrintEx(0, 0, "✅ Memory Spy installed (monitoring ALL processes)\n");
		}
	}

	// ========================================================================
	// Example 3: Complete Process Activity Monitor
	// ========================================================================

	PVOID OrigNtOpenProcessRW = NULL;
	PVOID OrigNtTerminateProcessRW = NULL;
	PVOID OrigNtCreateThreadExRW = NULL;

	NTSTATUS NTAPI HkNtOpenProcessRW(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID ClientId
	) {
		if (ClientId && ClientId->UniqueProcess) {
			HANDLE targetPid = ClientId->UniqueProcess;
			PUCHAR targetName = SsdtHelpers::GetProcessNameFromPid(targetPid);

			SsdtHelpers::LogSyscall("NtOpenProcess",
				"🔓 Opening: %s (PID %llu) | Access: 0x%lx (%s)",
				targetName,
				(ULONG64)targetPid,
				DesiredAccess,
				SsdtHelpers::AccessMaskToString(DesiredAccess));
		}

		NtOpenProcess_t original = (NtOpenProcess_t)OrigNtOpenProcessRW;
		return original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}

	NTSTATUS NTAPI HkNtTerminateProcessRW(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
		if (ProcessHandle) {
			HANDLE targetPid = SsdtHelpers::GetPidFromHandle(ProcessHandle);
			PUCHAR targetName = SsdtHelpers::GetProcessNameFromHandle(ProcessHandle);

			SsdtHelpers::LogSyscall("NtTerminateProcess",
				"💀 Terminating: %s (PID %llu) | ExitCode: 0x%lx",
				targetName,
				(ULONG64)targetPid,
				ExitStatus);
		}

		NtTerminateProcess_t original = (NtTerminateProcess_t)OrigNtTerminateProcessRW;
		return original(ProcessHandle, ExitStatus);
	}

	NTSTATUS NTAPI HkNtCreateThreadExRW(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		HANDLE ProcessHandle,
		PVOID StartRoutine,
		PVOID Argument,
		ULONG CreateFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		PVOID AttributeList
	) {
		HANDLE targetPid = SsdtHelpers::GetPidFromHandle(ProcessHandle);
		PUCHAR targetName = SsdtHelpers::GetProcessNameFromHandle(ProcessHandle);

		SsdtHelpers::LogSyscall("NtCreateThreadEx",
			"🧵 Thread in: %s (PID %llu) | StartAddr: %p | Suspended: %s",
			targetName,
			(ULONG64)targetPid,
			StartRoutine,
			(CreateFlags & 0x1) ? "Yes" : "No");

		// Call original (note: NtCreateThreadEx signature varies by Windows version)
		typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
			HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
		NtCreateThreadEx_t original = (NtCreateThreadEx_t)OrigNtCreateThreadExRW;
		return original(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
			StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
			MaximumStackSize, AttributeList);
	}

	VOID InstallProcessMonitor() {
		ULONG openIndex = wsbp::Ssdt::FindSyscallIndex(L"NtOpenProcess");
		ULONG termIndex = wsbp::Ssdt::FindSyscallIndex(L"NtTerminateProcess");
		ULONG threadIndex = wsbp::Ssdt::FindSyscallIndex(L"NtCreateThreadEx");

		if (openIndex != (ULONG)-1)
			wsbp::Ssdt::HookSsdtEntry(openIndex, HkNtOpenProcessRW, &OrigNtOpenProcessRW);
		if (termIndex != (ULONG)-1)
			wsbp::Ssdt::HookSsdtEntry(termIndex, HkNtTerminateProcessRW, &OrigNtTerminateProcessRW);
		if (threadIndex != (ULONG)-1)
			wsbp::Ssdt::HookSsdtEntry(threadIndex, HkNtCreateThreadExRW, &OrigNtCreateThreadExRW);

		DbgPrintEx(0, 0, "✅ Process Monitor installed\n");
	}

}

/*
 * HOW TO USE IN DriverEntry:
 *
 * // After PatchGuard bypass and SSDT initialization:
 *
 * // Monitor ALL file operations
 * RealWorld::InstallFileActivityLogger();
 *
 * // Monitor memory operations on specific PID (or NULL for all)
 * RealWorld::InstallMemorySpy((HANDLE)1234);  // Specific PID
 * RealWorld::InstallMemorySpy(NULL);          // All processes
 *
 * // Monitor all process operations
 * RealWorld::InstallProcessMonitor();
 *
 * // Output will look like:
 * // [2025-11-01 12:34:56] [notepad.exe:1234] NtCreateFile: 📁 \??\C:\test.txt | Access: 0x120116 | Disp: FILE_OPEN_IF
 * // [2025-11-01 12:34:57] [explorer.exe:5678] NtReadVirtualMemory: 🔍 Target: chrome.exe (PID 9999) | Addr: 0x7FF6A2B10000 | Size: 4096 bytes
 * //     └─ Read 4096 bytes:
 * //     [0000] 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  | MZ..............
 */
