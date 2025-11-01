/*
 * @file SyscallTracer.hpp
 * @brief Comprehensive syscall tracing for anticheat reversing
 */

#pragma once
#include "../Include.hpp"

namespace wsbp {
	namespace SyscallTracer {

		// Initialize all syscall hooks
		BOOLEAN InitializeTracer();
		
		// Cleanup
		VOID ShutdownTracer();

		// NtReadVirtualMemory - AC reads memory for signatures
		typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
			HANDLE ProcessHandle,
			PVOID BaseAddress,
			PVOID Buffer,
			SIZE_T BufferSize,
			PSIZE_T NumberOfBytesRead
		);

		// NtQueryVirtualMemory - AC scans memory regions
		typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_t)(
			HANDLE ProcessHandle,
			PVOID BaseAddress,
			ULONG MemoryInformationClass,
			PVOID MemoryInformation,
			SIZE_T MemoryInformationLength,
			PSIZE_T ReturnLength
		);

		// NtQueryInformationProcess - AC gets process info
		typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
			HANDLE ProcessHandle,
			ULONG ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength,
			PULONG ReturnLength
		);

		// NtOpenProcess - AC opens other processes
		typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
			PHANDLE ProcessHandle,
			ACCESS_MASK DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes,
			PCLIENT_ID ClientId
		);

		// NtProtectVirtualMemory - AC changes memory protections
		typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
			HANDLE ProcessHandle,
			PVOID* BaseAddress,
			PSIZE_T RegionSize,
			ULONG NewProtect,
			PULONG OldProtect
		);

		// NtQuerySystemInformation - AC queries system state
		typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
			ULONG SystemInformationClass,
			PVOID SystemInformation,
			ULONG SystemInformationLength,
			PULONG ReturnLength
		);

	}
}
