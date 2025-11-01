/*
 * @file StackWalker.cpp
 * @brief Proper stack walking implementation with PEB parsing
 */

#include "StackWalker.hpp"
#include "../Log.hpp"

// Custom KTRAP_FRAME structure (0x190 bytes) - renamed to avoid conflicts
typedef struct _KURASAGI_TRAP_FRAME {
	ULONGLONG P1Home;                    // 0x0
	ULONGLONG P2Home;                    // 0x8
	ULONGLONG P3Home;                    // 0x10
	ULONGLONG P4Home;                    // 0x18
	ULONGLONG P5;                        // 0x20
	UCHAR PreviousMode;                  // 0x28
	UCHAR PreviousIrql;                  // 0x29
	UCHAR FaultIndicator;                // 0x2a
	UCHAR ExceptionActive;               // 0x2b
	ULONG MxCsr;                         // 0x2c
	ULONGLONG Rax;                       // 0x30
	ULONGLONG Rcx;                       // 0x38
	ULONGLONG Rdx;                       // 0x40
	ULONGLONG R8;                        // 0x48
	ULONGLONG R9;                        // 0x50
	ULONGLONG R10;                       // 0x58
	ULONGLONG R11;                       // 0x60
	ULONGLONG GsBase;                    // 0x68
	UCHAR Padding1[0x68];                // 0x70-0xd7 (XMM registers, etc)
	ULONGLONG FaultAddress;              // 0xd8
	UCHAR Padding2[0x88];                // 0xe0-0x167
	ULONGLONG Rip;                       // 0x168
	USHORT SegCs;                        // 0x170
	UCHAR Fill0;                         // 0x172
	UCHAR Logging;                       // 0x173
	USHORT Fill1[2];                     // 0x174
	ULONG EFlags;                        // 0x178
	ULONG Fill2;                         // 0x17c
	ULONGLONG Rsp;                       // 0x180
	USHORT SegSs;                        // 0x188
	USHORT Fill3;                        // 0x18a
	ULONG Fill4;                         // 0x18c
} KURASAGI_TRAP_FRAME, *PKURASAGI_TRAP_FRAME;

// KAPC_STATE structure - renamed to avoid conflicts
typedef struct _KURASAGI_KAPC_STATE {
	LIST_ENTRY ApcListHead[2];
	PKPROCESS Process;
	BOOLEAN KernelApcInProgress;
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KURASAGI_KAPC_STATE, *PKURASAGI_KAPC_STATE;

// Forward declarations for undocumented APIs
extern "C" {
	NTKERNELAPI VOID KeStackAttachProcess(PKPROCESS Process, PKURASAGI_KAPC_STATE ApcState);
	NTKERNELAPI VOID KeUnstackDetachProcess(PKURASAGI_KAPC_STATE ApcState);
}

// TEB/PEB definitions - renamed to avoid conflicts
typedef struct _KURASAGI_NT_TIB {
	PVOID ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
	PVOID FiberData;
	PVOID ArbitraryUserPointer;
	struct _KURASAGI_NT_TIB* Self;
} KURASAGI_NT_TIB, *PKURASAGI_NT_TIB;

typedef struct _KURASAGI_TEB {
	KURASAGI_NT_TIB NtTib;
	// ... rest omitted
} KURASAGI_TEB, *PKURASAGI_TEB;

typedef struct _KURASAGI_PEB {
	UCHAR Reserved1[2];
	UCHAR BeingDebugged;
	UCHAR Reserved2[1];
	PVOID Reserved3[2];
	PVOID Ldr;
	PVOID ProcessParameters;
} KURASAGI_PEB, *PKURASAGI_PEB;

// Undocumented function to get TEB
extern "C" {
	NTKERNELAPI PKURASAGI_TEB PsGetThreadTeb(PETHREAD Thread);
}

// PEB structures for module enumeration
typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

BOOLEAN wsbp::StackWalker::GetModuleForAddress(PEPROCESS Process, PVOID Address, WCHAR* ModuleName, SIZE_T NameSize, PVOID* ModuleBase) {
	
	if (!Process || !Address || !ModuleName) return FALSE;
	
	ModuleName[0] = 0;
	if (ModuleBase) *ModuleBase = NULL;
	
	// Check if kernel address
	if ((ULONG_PTR)Address >= 0xFFFF800000000000) {
		wcsncpy_s(ModuleName, NameSize / sizeof(WCHAR), L"ntoskrnl.exe", _TRUNCATE);
		return TRUE;
	}
	
	// Attach to target process only if we're not already in it
	BOOLEAN needDetach = FALSE;
	KURASAGI_KAPC_STATE apcState;
	RtlZeroMemory(&apcState, sizeof(apcState));
	if (PsGetCurrentProcess() != Process) {
		KeStackAttachProcess((PKPROCESS)Process, &apcState);
		needDetach = TRUE;
	}
	
	__try {
		// Get PEB - offset 0x2e0 in EPROCESS (from your structure dump)
		PKURASAGI_PEB peb = *(PKURASAGI_PEB*)((ULONG_PTR)Process + 0x2e0);
		if (!peb || !MmIsAddressValid(peb)) {
			if (needDetach) KeUnstackDetachProcess(&apcState);
			return FALSE;
		}
		
		// Get loader data
		PPEB_LDR_DATA64 ldr = (PPEB_LDR_DATA64)peb->Ldr;
		if (!ldr) {
			if (needDetach) KeUnstackDetachProcess(&apcState);
			return FALSE;
		}
		
		// Walk module list
		PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
		PLIST_ENTRY current = head->Flink;
		
		while (current != head && current != NULL) {
			PLDR_DATA_TABLE_ENTRY64 entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
			
			PVOID base = entry->DllBase;
			ULONG size = entry->SizeOfImage;
			
			// Check if address is in this module
			if ((ULONG_PTR)Address >= (ULONG_PTR)base && 
			    (ULONG_PTR)Address < ((ULONG_PTR)base + size)) {
				
				// Copy module name (prefer base name, fallback to full path)
				if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
					SIZE_T copyLen = min(entry->BaseDllName.Length / sizeof(WCHAR), (NameSize / sizeof(WCHAR)) - 1);
					wcsncpy_s(ModuleName, NameSize / sizeof(WCHAR), entry->BaseDllName.Buffer, copyLen);
				} else if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
					SIZE_T copyLen = min(entry->FullDllName.Length / sizeof(WCHAR), (NameSize / sizeof(WCHAR)) - 1);
					wcsncpy_s(ModuleName, NameSize / sizeof(WCHAR), entry->FullDllName.Buffer, copyLen);
				}
				
				if (ModuleBase) *ModuleBase = base;
				
				if (needDetach) KeUnstackDetachProcess(&apcState);
				return TRUE;
			}
			
			current = current->Flink;
			
			// Safety check
			if (current == NULL || !MmIsAddressValid(current)) break;
		}
		
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		if (needDetach) KeUnstackDetachProcess(&apcState);
		return FALSE;
	}
	
	if (needDetach) KeUnstackDetachProcess(&apcState);
	return FALSE;
}

ULONG wsbp::StackWalker::CaptureStack(StackFrame* Frames, ULONG MaxFrames, PEPROCESS Process) {
	if (!Frames || MaxFrames == 0) return 0;

	RtlZeroMemory(Frames, sizeof(StackFrame) * MaxFrames);

	ULONG captured = 0;
	const ULONG maxUserFrames = 64;
	PVOID userStack[maxUserFrames] = {0};
	ULONG userFrames = 0;

	PKTHREAD currentThread = KeGetCurrentThread();
	if (!currentThread) return 0;

	ULONGLONG userRsp = 0;
	ULONGLONG userRip = 0;

	__try {
		PKURASAGI_TRAP_FRAME trapFrame = *(PKURASAGI_TRAP_FRAME*)((ULONG_PTR)currentThread + 0x90);
		if (trapFrame && MmIsAddressValid(trapFrame)) {
			userRsp = trapFrame->Rsp;
			userRip = trapFrame->Rip;
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		userRsp = 0;
		userRip = 0;
	}

	// Attach to process if necessary before walking user stack
	KURASAGI_KAPC_STATE apcState;
	RtlZeroMemory(&apcState, sizeof(apcState));
	BOOLEAN attached = FALSE;
	if (Process && PsGetCurrentProcess() != Process) {
		KeStackAttachProcess((PKPROCESS)Process, &apcState);
		attached = TRUE;
	}

	__try {
		userFrames = RtlWalkFrameChain(userStack, maxUserFrames, 1);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		userFrames = 0;
	}

	if (userFrames == 0) {
		// Fallback: manual walk using TEB stack boundaries
		// KTHREAD.Teb is at offset 0xF0
		PKURASAGI_TEB teb = NULL;
		__try {
			teb = *(PKURASAGI_TEB*)((ULONG_PTR)currentThread + 0xF0);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			teb = NULL;
		}

		PVOID stackBase = NULL;
		PVOID stackLimit = NULL;
		if (teb) {
			__try {
				stackBase = teb->NtTib.StackBase;
				stackLimit = teb->NtTib.StackLimit;
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				stackBase = stackLimit = NULL;
			}
		}

		if (userRip > 0x10000 && userRip < 0x00007FFFFFFFFFFF && userFrames < maxUserFrames) {
			userStack[userFrames++] = (PVOID)userRip;
		}

		if (userRsp && stackBase && stackLimit &&
			userRsp >= (ULONGLONG)stackLimit && userRsp < (ULONGLONG)stackBase) {
			ULONGLONG* framePtr = (ULONGLONG*)userRsp;
			ULONGLONG* frameEnd = (ULONGLONG*)stackBase;
			
			while (framePtr < frameEnd && userFrames < maxUserFrames) {
				ULONGLONG potential = 0;
				__try {
					potential = *framePtr;
				} __except(EXCEPTION_EXECUTE_HANDLER) {
					break;
				}
				framePtr++;

				if (potential <= 0x10000 || potential >= 0x00007FFFFFFFFFFF) continue;

				BOOLEAN duplicate = FALSE;
				for (ULONG j = 0; j < userFrames; j++) {
					if (userStack[j] == (PVOID)potential) {
						duplicate = TRUE;
						break;
					}
				}
				if (duplicate) continue;

				WCHAR modCheck[64] = {0};
				if (GetModuleForAddress(Process, (PVOID)potential, modCheck, sizeof(modCheck), NULL)) {
					if (modCheck[0] != 0) {
						userStack[userFrames++] = (PVOID)potential;
					}
				}
			}
		}
	}

	if (attached) {
		KeUnstackDetachProcess(&apcState);
	}

	if (userFrames == 0 && userRip > 0x10000 && userRip < 0x00007FFFFFFFFFFF) {
		userStack[userFrames++] = (PVOID)userRip;
	}

	for (ULONG i = 0; i < userFrames && captured < MaxFrames; i++) {
		PVOID addr = userStack[i];
		if (!addr) continue;
		if ((ULONG_PTR)addr >= 0xFFFF800000000000) continue;

		Frames[captured].Address = addr;
		Frames[captured].IsKernelMode = FALSE;
		Frames[captured].IsUserMode = TRUE;
		Frames[captured].Offset = 0;
		Frames[captured].ModuleBase = NULL;
		Frames[captured].ModuleName[0] = 0;

		GetModuleForAddress(Process, addr, Frames[captured].ModuleName,
			sizeof(Frames[captured].ModuleName), &Frames[captured].ModuleBase);

		if (Frames[captured].ModuleBase) {
			Frames[captured].Offset = (ULONG_PTR)addr - (ULONG_PTR)Frames[captured].ModuleBase;
		}

		captured++;
	}

	return captured;
}
