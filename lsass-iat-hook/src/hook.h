#pragma once
#include <string_view>
#include <unordered_map>

namespace hook {
	inline uintptr_t g_universal_buffer;
	inline std::unordered_map< uint32_t, std::string_view > g_names;

	bool hook_iat( std::string_view process_name, std::string_view module_name );
}
