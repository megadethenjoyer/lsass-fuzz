#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>

namespace finder {
	struct mod {
		uintptr_t base;
		size_t size;

		inline bool invalid( ) { return base == 0 || size == 0; }
		static mod empty( ) { return mod{ }; }
	};

	uint64_t find_pid( std::string_view target_name );
	mod find_module( uint64_t pid, std::string_view target_name );
}
