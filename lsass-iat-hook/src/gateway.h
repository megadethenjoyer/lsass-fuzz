#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mutex>

namespace gateway {
	inline HANDLE pipe;
	inline std::mutex pipe_mutex;

	void init( );
}
