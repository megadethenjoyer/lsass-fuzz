#pragma once
#include <cstddef>

struct sample_harness {
	static constexpr size_t buf_size = 4;
	static bool execute( char *buffer );
};
