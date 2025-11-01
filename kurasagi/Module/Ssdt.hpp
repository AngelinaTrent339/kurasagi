/*
 * @file Ssdt.hpp
 * @brief SSDT (System Service Descriptor Table) hooking module
 */

#pragma once

#include "../Include.hpp"

namespace wsbp {
	namespace Ssdt {

		// SSDT structure (undocumented)
		typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE {
			PULONG_PTR ServiceTableBase;      // Array of function pointers
			PULONG ServiceCounterTableBase;   // Not used on x64
			ULONG_PTR NumberOfServices;       // Number of services
			PUCHAR ParamTableBase;            // Array of parameter counts
		} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

		// Hook information structure
		typedef struct _SSDT_HOOK_INFO {
			ULONG ServiceIndex;               // Syscall number (e.g., 0x55 for NtCreateFile)
			PVOID OriginalFunction;           // Original function pointer
			PVOID HookFunction;               // Your hook function
			BOOLEAN IsHooked;                 // Hook status
		} SSDT_HOOK_INFO, *PSSDT_HOOK_INFO;

		/*
		 * @brief Initialize SSDT module - finds KeServiceDescriptorTable
		 * @returns TRUE if successful, FALSE otherwise
		 */
		BOOLEAN InitializeSsdt();

		/*
		 * @brief Hook a single SSDT entry
		 * @param ServiceIndex: The syscall number to hook (e.g., 0x55 for NtCreateFile)
		 * @param HookFunction: Your hook function pointer
		 * @param OutOriginalFunction: Pointer to store the original function address
		 * @returns TRUE if successful, FALSE otherwise
		 */
		BOOLEAN HookSsdtEntry(ULONG ServiceIndex, PVOID HookFunction, PVOID* OutOriginalFunction);

		/*
		 * @brief Unhook a single SSDT entry
		 * @param ServiceIndex: The syscall number to unhook
		 * @param OriginalFunction: The original function pointer to restore
		 * @returns TRUE if successful, FALSE otherwise
		 */
		BOOLEAN UnhookSsdtEntry(ULONG ServiceIndex, PVOID OriginalFunction);

		/*
		 * @brief Get SSDT function address by index
		 * @param ServiceIndex: The syscall number
		 * @returns Function pointer or NULL if not found
		 * @warning Returns CURRENT entry (may be hooked). Use GetOriginalSsdtEntry for original.
		 */
		PVOID GetSsdtFunctionAddress(ULONG ServiceIndex);

		/*
		 * @brief Get original SSDT entry value (before any hooks)
		 * @param ServiceIndex: The syscall number
		 * @param OutEntry: Pointer to store the raw SSDT entry value
		 * @returns TRUE if successful, FALSE otherwise
		 */
		BOOLEAN GetSsdtEntry(ULONG ServiceIndex, PULONG OutEntry);

		/*
		 * @brief Print SSDT information for debugging
		 */
		VOID PrintSsdtInfo();

		/*
		 * @brief Find syscall index by function name
		 * @param FunctionName: Name of the function (e.g., L"NtCreateFile")
		 * @returns Syscall index or (ULONG)-1 if not found
		 */
		ULONG FindSyscallIndex(PCWSTR FunctionName);

		// Example hook functions - you can use these as templates

		/*
		 * @brief Example: Hook NtCreateFile to trace file creation
		 */
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

		/*
		 * @brief Example: Hook NtOpenProcess to trace process access
		 */
		NTSTATUS NTAPI HkNtOpenProcess(
			PHANDLE ProcessHandle,
			ACCESS_MASK DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes,
			PCLIENT_ID ClientId
		);

		// Original function pointers (will be filled after hooking)
		extern PVOID OrigNtCreateFile;
		extern PVOID OrigNtOpenProcess;
	}
}
