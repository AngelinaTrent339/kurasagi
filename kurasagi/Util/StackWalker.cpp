/*
 * @file StackWalker.cpp
 * @brief Proper stack walking implementation with PEB parsing
 */

#include "StackWalker.hpp"
#include "../Log.hpp"

// KAPC_STATE structure
typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[2];
	PKPROCESS Process;
	BOOLEAN KernelApcInProgress;
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

// Forward declarations for undocumented APIs
extern "C" {
	NTKERNELAPI VOID KeStackAttachProcess(PKPROCESS Process, PKAPC_STATE ApcState);
	NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);
}

// TEB/PEB definitions
typedef struct _NT_TIB {
	PVOID ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
	PVOID FiberData;
	PVOID ArbitraryUserPointer;
	struct _NT_TIB* Self;
} NT_TIB, *PNT_TIB;

typedef struct _TEB {
	NT_TIB NtTib;
	// ... rest omitted
} TEB, *PTEB;

typedef struct _PEB {
	UCHAR Reserved1[2];
	UCHAR BeingDebugged;
	UCHAR Reserved2[1];
	PVOID Reserved3[2];
	PVOID Ldr;
	PVOID ProcessParameters;
} PEB, *PPEB;

// Undocumented function to get TEB
extern "C" {
	NTKERNELAPI PTEB PsGetThreadTeb(PETHREAD Thread);
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
	
	// Attach to target process
	KAPC_STATE apcState;
	RtlZeroMemory(&apcState, sizeof(apcState));
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
	
	ULONG captured = 0;
	
	// Get current thread's trap frame to access user-mode context
	PKTHREAD currentThread = KeGetCurrentThread();
	if (!currentThread) return 0;
	
	// Attach to process to read user-mode memory
	KAPC_STATE apcState;
	RtlZeroMemory(&apcState, sizeof(apcState));
	KeStackAttachProcess((PKPROCESS)Process, &apcState);
	
	__try {
		// Get user-mode RSP and RBP from thread context
		// TrapFrame offset varies, try to get from KTHREAD + 0x90 (common offset)
		PVOID* trapFrame = (PVOID*)((ULONG_PTR)currentThread + 0x90);
		
		// Manual stack walk - read return addresses from user stack
		// This is simplified but works for most cases
		
		// Try to read user-mode stack frames manually
		// Get context from current syscall transition
		CONTEXT ctx = {0};
		ctx.ContextFlags = CONTEXT_CONTROL;
		
		// For now, capture what we can from kernel side
		// and add first user-mode return address from _ReturnAddress()
		
		// First frame: the syscall caller (user-mode)
		PVOID userRetAddr = _ReturnAddress();
		
		// Walk backwards from kernel to find user transition
		PVOID kernelStack[16] = {0};
		ULONG kernelFrames = RtlWalkFrameChain(kernelStack, 16, 0);
		
		// Add kernel frames
		for (ULONG i = 0; i < kernelFrames && captured < MaxFrames; i++) {
			if (kernelStack[i] == NULL) break;
			
			Frames[captured].Address = kernelStack[i];
			Frames[captured].IsKernelMode = TRUE;
			Frames[captured].IsUserMode = FALSE;
			
			// Resolve kernel module
			GetModuleForAddress(Process, kernelStack[i], Frames[captured].ModuleName, 
				sizeof(Frames[captured].ModuleName), &Frames[captured].ModuleBase);
			
			if (Frames[captured].ModuleBase) {
				Frames[captured].Offset = (ULONG_PTR)kernelStack[i] - (ULONG_PTR)Frames[captured].ModuleBase;
			}
			
			captured++;
		}
		
		// Try to capture user-mode frames by walking user stack
		// Get TEB and stack bounds
		PTEB teb = (PTEB)PsGetThreadTeb(currentThread);
		if (teb && MmIsAddressValid(teb)) {
			// Get stack base and limit from TEB
			PVOID stackBase = (PVOID)teb->NtTib.StackBase;
			PVOID stackLimit = (PVOID)teb->NtTib.StackLimit;
			
			if (stackBase && stackLimit && MmIsAddressValid(stackBase)) {
				// Walk user stack looking for valid code pointers
				PVOID* stackPtr = (PVOID*)stackBase;
				
				for (int i = 0; i < 256 && captured < MaxFrames; i++) {
					PVOID addr = stackPtr[-i];
					
					// Check if this looks like a user-mode code address
					if ((ULONG_PTR)addr < 0x00007FFFFFFFFFFF && (ULONG_PTR)addr > 0x10000) {
						// Validate it's in a module
						WCHAR modName[64] = {0};
						PVOID modBase = NULL;
						
						if (GetModuleForAddress(Process, addr, modName, sizeof(modName), &modBase)) {
							if (modName[0] != 0) {
								Frames[captured].Address = addr;
								Frames[captured].IsKernelMode = FALSE;
								Frames[captured].IsUserMode = TRUE;
								wcsncpy_s(Frames[captured].ModuleName, 64, modName, _TRUNCATE);
								Frames[captured].ModuleBase = modBase;
								Frames[captured].Offset = (ULONG_PTR)addr - (ULONG_PTR)modBase;
								captured++;
							}
						}
					}
				}
			}
		}
		
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		// Continue with what we have
	}
	
	KeUnstackDetachProcess(&apcState);
	
	return captured;
}
