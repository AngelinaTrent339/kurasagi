/*
 * @file LDE64.hpp
 * @brief Minimal x64 Length Disassembler Engine for inline hooking
 * 
 * Returns the length of x64 instructions to safely hook without breaking code
 */

#pragma once
#include "../Include.hpp"

namespace wsbp {
	namespace LDE64 {

		// Get the length of a single x64 instruction
		SIZE_T GetInstructionLength(PVOID Address);

		// Calculate how many bytes we need to safely overwrite for inline hook
		// Returns total bytes that contain only complete instructions >= MinBytes
		SIZE_T GetSafeHookLength(PVOID Address, SIZE_T MinBytes);

	}
}
