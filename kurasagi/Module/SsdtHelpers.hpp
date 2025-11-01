/*
 * @file SsdtHelpers.hpp
 * @brief Helper functions for extracting data from syscall hooks
 */

#pragma once

#include "../Include.hpp"

namespace SsdtHelpers {

	// ========================================================================
	// PROCESS HELPERS
	// ========================================================================

	/*
	 * @brief Get process name from process handle
	 * @returns Process name (e.g., "notepad.exe") or "Unknown"
	 */
	inline PUCHAR GetProcessNameFromHandle(HANDLE ProcessHandle) {
		PEPROCESS process = NULL;
		if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
			KernelMode, (PVOID*)&process, NULL))) {
			PUCHAR name = (PUCHAR)PsGetProcessImageFileName(process);
			ObDereferenceObject(process);
			return name;
		}
		return (PUCHAR)"Unknown";
	}

	/*
	 * @brief Get PID from process handle
	 * @returns PID or NULL if failed
	 */
	inline HANDLE GetPidFromHandle(HANDLE ProcessHandle) {
		PEPROCESS process = NULL;
		if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
			KernelMode, (PVOID*)&process, NULL))) {
			HANDLE pid = PsGetProcessId(process);
			ObDereferenceObject(process);
			return pid;
		}
		return NULL;
	}

	/*
	 * @brief Get current process name (caller of syscall)
	 * @returns Process name
	 */
	inline PUCHAR GetCurrentProcessName() {
		PEPROCESS process = PsGetCurrentProcess();
		return (PUCHAR)PsGetProcessImageFileName(process);
	}

	/*
	 * @brief Get current PID (caller of syscall)
	 * @returns PID
	 */
	inline HANDLE GetCurrentPid() {
		return PsGetCurrentProcessId();
	}

	/*
	 * @brief Get process name from PID
	 * @returns Process name or "Unknown"
	 */
	inline PUCHAR GetProcessNameFromPid(HANDLE Pid) {
		PEPROCESS process = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &process))) {
			PUCHAR name = (PUCHAR)PsGetProcessImageFileName(process);
			ObDereferenceObject(process);
			return name;
		}
		return (PUCHAR)"Unknown";
	}

	// ========================================================================
	// FILE HELPERS
	// ========================================================================

	/*
	 * @brief Get filename from file handle
	 * @param FileHandle: File handle
	 * @param OutName: Allocated UNICODE_STRING* (caller must free with ExFreePoolWithTag)
	 * @returns TRUE if successful
	 * @note Remember to free: ExFreePoolWithTag(OutName, 'File');
	 */
	inline BOOLEAN GetFilenameFromHandle(HANDLE FileHandle, POBJECT_NAME_INFORMATION* OutName) {
		POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)
			ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, 'File');

		if (!nameInfo) return FALSE;

		ULONG returnLen = 0;
		NTSTATUS status = ObQueryNameString(FileHandle, nameInfo, 1024, &returnLen);

		if (NT_SUCCESS(status)) {
			*OutName = nameInfo;
			return TRUE;
		}

		ExFreePoolWithTag(nameInfo, 'File');
		return FALSE;
	}

	// ========================================================================
	// REGISTRY HELPERS
	// ========================================================================

	/*
	 * @brief Get registry key path from handle
	 * @param KeyHandle: Registry key handle
	 * @param OutName: Allocated OBJECT_NAME_INFORMATION* (caller must free)
	 * @returns TRUE if successful
	 * @note Remember to free: ExFreePoolWithTag(OutName, 'Reg ');
	 */
	inline BOOLEAN GetRegistryPathFromHandle(HANDLE KeyHandle, POBJECT_NAME_INFORMATION* OutName) {
		POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)
			ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, 'Reg ');

		if (!nameInfo) return FALSE;

		ULONG returnLen = 0;
		NTSTATUS status = ObQueryNameString(KeyHandle, nameInfo, 1024, &returnLen);

		if (NT_SUCCESS(status)) {
			*OutName = nameInfo;
			return TRUE;
		}

		ExFreePoolWithTag(nameInfo, 'Reg ');
		return FALSE;
	}

	// ========================================================================
	// DATA FORMATTING HELPERS
	// ========================================================================

	/*
	 * @brief Print hex dump of memory buffer
	 * @param Buffer: Buffer to dump
	 * @param Size: Total size of buffer
	 * @param MaxBytes: Maximum bytes to dump (for limiting output)
	 */
	inline VOID HexDump(PVOID Buffer, SIZE_T Size, SIZE_T MaxBytes) {
		if (!Buffer || Size == 0) return;

		SIZE_T bytesToDump = min(Size, MaxBytes);
		PUCHAR bytes = (PUCHAR)Buffer;

		__try {
			for (SIZE_T i = 0; i < bytesToDump; i += 16) {
				DbgPrintEx(0, 0, "[%04llx] ", (ULONG64)i);

				// Hex bytes
				for (SIZE_T j = 0; j < 16; j++) {
					if ((i + j) < bytesToDump) {
						DbgPrintEx(0, 0, "%02x ", bytes[i + j]);
					}
					else {
						DbgPrintEx(0, 0, "   ");
					}
				}

				// ASCII representation
				DbgPrintEx(0, 0, " | ");
				for (SIZE_T j = 0; j < 16 && (i + j) < bytesToDump; j++) {
					UCHAR c = bytes[i + j];
					DbgPrintEx(0, 0, "%c", (c >= 32 && c <= 126) ? c : '.');
				}

				DbgPrintEx(0, 0, "\n");
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrintEx(0, 0, "[HexDump] Access violation at offset %llu\n", (ULONG64)0);
		}
	}

	/*
	 * @brief Get access mask as human-readable string
	 */
	inline PCSTR AccessMaskToString(ACCESS_MASK Access) {
		// Common process access rights
		if (Access & PROCESS_ALL_ACCESS) return "PROCESS_ALL_ACCESS";
		if (Access & PROCESS_TERMINATE) return "PROCESS_TERMINATE";
		if (Access & PROCESS_VM_WRITE) return "PROCESS_VM_WRITE";
		if (Access & PROCESS_VM_READ) return "PROCESS_VM_READ";
		if (Access & PROCESS_VM_OPERATION) return "PROCESS_VM_OPERATION";
		if (Access & PROCESS_QUERY_INFORMATION) return "PROCESS_QUERY_INFORMATION";

		// Common file access rights
		if (Access & FILE_READ_DATA) return "FILE_READ_DATA";
		if (Access & FILE_WRITE_DATA) return "FILE_WRITE_DATA";
		if (Access & FILE_EXECUTE) return "FILE_EXECUTE";

		return "UNKNOWN";
	}

	/*
	 * @brief Get file disposition as string
	 */
	inline PCSTR DispositionToString(ULONG Disposition) {
		switch (Disposition) {
		case FILE_SUPERSEDE: return "FILE_SUPERSEDE";
		case FILE_OPEN: return "FILE_OPEN";
		case FILE_CREATE: return "FILE_CREATE";
		case FILE_OPEN_IF: return "FILE_OPEN_IF";
		case FILE_OVERWRITE: return "FILE_OVERWRITE";
		case FILE_OVERWRITE_IF: return "FILE_OVERWRITE_IF";
		default: return "UNKNOWN";
		}
	}

	// ========================================================================
	// FILTERING HELPERS
	// ========================================================================

	/*
	 * @brief Check if current process matches name
	 * @param ProcessName: Process name to match (e.g., "notepad.exe")
	 * @returns TRUE if matches
	 */
	inline BOOLEAN IsCurrentProcess(PCSTR ProcessName) {
		PUCHAR currentName = GetCurrentProcessName();
		return (_stricmp((const char*)currentName, ProcessName) == 0);
	}

	/*
	 * @brief Check if process handle matches name
	 * @param ProcessHandle: Process handle
	 * @param ProcessName: Process name to match
	 * @returns TRUE if matches
	 */
	inline BOOLEAN IsProcessName(HANDLE ProcessHandle, PCSTR ProcessName) {
		PUCHAR targetName = GetProcessNameFromHandle(ProcessHandle);
		return (_stricmp((const char*)targetName, ProcessName) == 0);
	}

	/*
	 * @brief Check if filename contains substring
	 * @param Filename: UNICODE_STRING filename
	 * @param Substring: ASCII substring to search for
	 * @returns TRUE if found
	 */
	inline BOOLEAN FilenameContains(PUNICODE_STRING Filename, PCSTR Substring) {
		if (!Filename || !Filename->Buffer) return FALSE;

		// Convert to uppercase for case-insensitive search
		UNICODE_STRING searchStr;
		WCHAR wideSubstring[256];
		size_t convertedChars = 0;
		mbstowcs_s(&convertedChars, wideSubstring, 256, Substring, strlen(Substring));

		RtlInitUnicodeString(&searchStr, wideSubstring);

		// Simple substring search
		for (USHORT i = 0; i <= Filename->Length / sizeof(WCHAR) - searchStr.Length / sizeof(WCHAR); i++) {
			BOOLEAN match = TRUE;
			for (USHORT j = 0; j < searchStr.Length / sizeof(WCHAR); j++) {
				WCHAR c1 = Filename->Buffer[i + j];
				WCHAR c2 = searchStr.Buffer[j];
				// Case insensitive compare
				if (towupper(c1) != towupper(c2)) {
					match = FALSE;
					break;
				}
			}
			if (match) return TRUE;
		}

		return FALSE;
	}

	// ========================================================================
	// LOGGING HELPERS
	// ========================================================================

	/*
	 * @brief Format timestamp
	 */
	inline VOID GetTimestamp(PCHAR Buffer, SIZE_T BufferSize) {
		LARGE_INTEGER systemTime, localTime;
		TIME_FIELDS timeFields;

		KeQuerySystemTime(&systemTime);
		ExSystemTimeToLocalTime(&systemTime, &localTime);
		RtlTimeToTimeFields(&localTime, &timeFields);

		RtlStringCbPrintfA(Buffer, BufferSize, "[%04d-%02d-%02d %02d:%02d:%02d]",
			timeFields.Year, timeFields.Month, timeFields.Day,
			timeFields.Hour, timeFields.Minute, timeFields.Second);
	}

	/*
	 * @brief Enhanced logging with timestamp and caller info
	 */
	inline VOID LogSyscall(PCSTR SyscallName, PCSTR Format, ...) {
		CHAR timestamp[32];
		GetTimestamp(timestamp, sizeof(timestamp));

		PUCHAR processName = GetCurrentProcessName();
		HANDLE pid = GetCurrentPid();

		DbgPrintEx(0, 0, "%s [%s:%llu] %s: ",
			timestamp, processName, (ULONG64)pid, SyscallName);

		va_list args;
		va_start(args, Format);

		CHAR buffer[512];
		RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
		DbgPrintEx(0, 0, "%s\n", buffer);

		va_end(args);
	}

}
