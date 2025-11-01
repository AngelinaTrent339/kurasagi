/*
 * @file StackWalker.hpp
 * @brief Proper user-mode and kernel-mode stack walking with module resolution
 */

#pragma once
#include "../Include.hpp"

namespace wsbp {
	namespace StackWalker {

		// Stack frame with full context
		struct StackFrame {
			PVOID Address;
			BOOLEAN IsKernelMode;
			BOOLEAN IsUserMode;
			WCHAR ModuleName[64];
			PVOID ModuleBase;
			ULONG_PTR Offset;
		};

		// Capture full stack with module resolution
		ULONG CaptureStack(StackFrame* Frames, ULONG MaxFrames, PEPROCESS Process);

		// Get module name for an address in a process
		BOOLEAN GetModuleForAddress(PEPROCESS Process, PVOID Address, WCHAR* ModuleName, SIZE_T NameSize, PVOID* ModuleBase);

	}
}
