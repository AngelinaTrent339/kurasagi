/*
 * @file Module.hpp
 * @brief Modules
 */

#pragma once

#include "Module/Timer.hpp"
#include "Module/Barricade.hpp"
#include "Module/Context7.hpp"
#include "Module/Misc.hpp"
#include "Module/Ssdt.hpp"

namespace wsbp {

	/*
	 * @brief Bypasses PatchGuard.
	 * @returns `TRUE` if successfully bypassed, `FALSE` you failed and you should miserably wait for BSOD :(
	 */
	BOOLEAN BypassPatchGuard();
}