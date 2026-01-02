#pragma once
#include <string_view>
#include <cstdint>

// https://gist.github.com/hwei/1950649d523afd03285c

namespace fnv {
	constexpr uint32_t PRIME = 16777619u;
	constexpr uint32_t BASIS = 2166136261u;

	uint32_t hash( std::string_view str );
}
