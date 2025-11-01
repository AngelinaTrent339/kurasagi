/*
 * @file InlineHook.hpp
 * @brief Inline hooking for kernel functions (works on modern Windows)
 */

#pragma once
#include "../Include.hpp"

namespace wsbp {
	namespace InlineHook {

		// Simple inline hook structure
		struct Hook {
			PVOID TargetFunction;
			PVOID HookFunction;
			BYTE OriginalBytes[14];  // Store original bytes
			BOOLEAN IsHooked;
		};

		// Hook a kernel function by writing a JMP
		BOOLEAN InstallHook(PVOID TargetFunction, PVOID HookFunction, Hook* OutHook);

		// Restore original bytes
		BOOLEAN RemoveHook(Hook* HookInfo);

		// Example hook functions
		typedef NTSTATUS(NTAPI* NtCreateFile_t)(
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
		);

		extern Hook NtCreateFileHook;
		extern NtCreateFile_t OrigNtCreateFile;

		NTSTATUS NTAPI HkNtCreateFile(
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
		);

	}
}
