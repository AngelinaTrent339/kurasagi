/*
 * @file StackWalker.cpp
 * @brief Proper stack walking implementation with PEB parsing
 */

#include "StackWalker.hpp"
#include "../Log.hpp"

// PEB definition
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PVOID Ldr;
	PVOID ProcessParameters;
	// ... rest omitted
} PEB, *PPEB;

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
	
	// Attach to target process
	KAPC_STATE apcState = {0};
	KeStackAttachProcess((PKPROCESS)Process, &apcState);
	
	__try {
		// Get PEB - offset 0x2e0 in EPROCESS (from your structure dump)
		PPEB peb = *(PPEB*)((ULONG_PTR)Process + 0x2e0);
		if (!peb || !MmIsAddressValid(peb)) {
			KeUnstackDetachProcess(&apcState);
			return FALSE;
		}
		
		// Get loader data
		PPEB_LDR_DATA64 ldr = (PPEB_LDR_DATA64)peb->Ldr;
		if (!ldr) {
			KeUnstackDetachProcess(&apcState);
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
				
				// Copy module name
				if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
					SIZE_T copyLen = min(entry->BaseDllName.Length / sizeof(WCHAR), (NameSize / sizeof(WCHAR)) - 1);
					wcsncpy_s(ModuleName, NameSize / sizeof(WCHAR), entry->BaseDllName.Buffer, copyLen);
				}
				
				if (ModuleBase) *ModuleBase = base;
				
				KeUnstackDetachProcess(&apcState);
				return TRUE;
			}
			
			current = current->Flink;
			
			// Safety check
			if (current == NULL || !MmIsAddressValid(current)) break;
		}
		
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&apcState);
		return FALSE;
	}
	
	KeUnstackDetachProcess(&apcState);
	return FALSE;
}

ULONG wsbp::StackWalker::CaptureStack(StackFrame* Frames, ULONG MaxFrames, PEPROCESS Process) {
	
	if (!Frames || MaxFrames == 0) return 0;
	
	RtlZeroMemory(Frames, sizeof(StackFrame) * MaxFrames);
	
	PVOID rawStack[32] = {0};
	ULONG captured = 0;
	
	// Try user-mode stack first
	__try {
		captured = RtlWalkFrameChain(rawStack, min(MaxFrames, 32), 1);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		captured = 0;
	}
	
	// If no user frames, try kernel
	if (captured == 0) {
		__try {
			captured = RtlWalkFrameChain(rawStack, min(MaxFrames, 32), 0);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			return 0;
		}
	}
	
	// Fill in frame details
	for (ULONG i = 0; i < captured && i < MaxFrames; i++) {
		if (rawStack[i] == NULL) break;
		
		Frames[i].Address = rawStack[i];
		Frames[i].IsKernelMode = ((ULONG_PTR)rawStack[i] >= 0xFFFF800000000000);
		Frames[i].IsUserMode = !Frames[i].IsKernelMode;
		
		// Resolve module
		GetModuleForAddress(Process, rawStack[i], Frames[i].ModuleName, sizeof(Frames[i].ModuleName), &Frames[i].ModuleBase);
		
		if (Frames[i].ModuleBase) {
			Frames[i].Offset = (ULONG_PTR)rawStack[i] - (ULONG_PTR)Frames[i].ModuleBase;
		}
	}
	
	return captured;
}
